<?php

declare(strict_types=1);

namespace ZanShield\Sdk;

use Closure;
use DateTime;
use DateTimeImmutable;
use DateTimeZone;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\RSA;
use Random\RandomException;
use Throwable;

/**
 * Builds and opens ZanShield tickets: signs and encrypts outbound tickets addressed to
 * ZanShield's engine, and decrypts + verifies the signed acknowledgement tickets it sends
 * back. Uses phpseclib3 rather than PHP's native openssl_* functions because
 * openssl_public_encrypt()'s OAEP padding is hardcoded to SHA-1 with no way to request
 * SHA-256 — phpseclib3 supports RSA-OAEP with a configurable hash correctly.
 *
 * Wire format (all base64url, no padding, of the concatenation): a 4-byte big-endian length
 * of the RSA-wrapped AES key, the wrapped AES key itself, a 12-byte GCM IV, then the AES-GCM
 * ciphertext with its 16-byte tag appended. See DOCS/03-Integration-Guide.html §3.2.
 *
 * The ticket only says who the user is. ZanShield decides everything else: whether they set up
 * a first method or verify an existing one, which methods their system allows, and lets them add
 * another method after verifying.
 */
final class ZanShieldClient
{
    private const GCM_IV_BYTES = 12;
    private const GCM_TAG_BYTES = 16;

    private string $systemCode;
    private string $institutionCode;
    private PrivateKey $myPrivateKey;
    private PublicKey $enginePublicKey;
    private TxnIdStore $txnIdStore;
    private int $maxAcknowledgementAgeSeconds;
    /** @var Closure(): int */
    private Closure $now;

    /**
     * @param TxnIdStore|null $txnIdStore where acceptAcknowledgement() remembers used txnIDs —
     *     use one backed by shared storage in production (see TxnIdStore)
     * @param int $maxAcknowledgementAgeSeconds how old an acknowledgement may be (default 3 minutes)
     * @param Closure|null $now returns the current unix time; for tests
     */
    public function __construct(
        string $systemCode,
        string $institutionCode,
        PrivateKey $myPrivateKey,
        PublicKey $enginePublicKey,
        ?TxnIdStore $txnIdStore = null,
        int $maxAcknowledgementAgeSeconds = 180,
        ?Closure $now = null
    ) {
        $this->systemCode = $systemCode;
        $this->institutionCode = $institutionCode;
        $this->myPrivateKey = $myPrivateKey;
        $this->enginePublicKey = $enginePublicKey;
        $this->txnIdStore = $txnIdStore ?? new InMemoryTxnIdStore();
        $this->maxAcknowledgementAgeSeconds = $maxAcknowledgementAgeSeconds;
        $this->now = $now ?? static fn (): int => time();
    }

    /** Parses a PKCS#8 PEM-encoded RSA private key. */
    public static function loadPrivateKey(string $pem): PrivateKey
    {
        return PublicKeyLoader::loadPrivateKey($pem);
    }

    /** Parses an X.509 PEM-encoded RSA public key. */
    public static function loadPublicKey(string $pem): PublicKey
    {
        return PublicKeyLoader::loadPublicKey($pem);
    }

    /**
     * Builds a signed, sealed ticket asking ZanShield to verify $userId/$email. Authenticate the
     * user with your own credential first — ZanShield only ever handles the second factor.
     * $fullName lets the portal greet the user by name; $mobile (any common format, e.g.
     * "0772 123 456") is needed for the user to choose SMS codes. Pass null to omit either.
     */
    public function createTicket(string $userId, string $email, ?string $fullName = null, ?string $mobile = null): string
    {
        $payload = new TicketPayload();
        $payload->systemCode = $this->systemCode;
        $payload->institutionCode = $this->institutionCode;
        $payload->userId = $userId;
        $payload->email = $email;
        $payload->fullName = $fullName;
        $payload->mobile = $mobile;
        $payload->dateTime = (new DateTime('@' . ($this->now)()))
            ->setTimezone(new DateTimeZone('UTC'))
            ->format('Y-m-d\TH:i:s\Z');

        return $this->createTicketFromPayload($payload);
    }

    /**
     * The portal address to redirect the browser to. With $addMethod (e.g. from an "Add an MFA
     * method" button in your app), the user goes straight to adding a method after verifying.
     */
    public static function portalUrl(string $portalBaseUrl, string $ticket, bool $addMethod = false): string
    {
        $url = rtrim($portalBaseUrl, '/') . '/ticket?ticket=' . rawurlencode($ticket);
        return $addMethod ? $url . '&add=1' : $url;
    }

    /**
     * Everything your redirectUri must check before starting a session, in one call: decrypts and
     * verifies the acknowledgement (openAcknowledgement()), then requires a successful
     * verification, a fresh dateTime, and a txnID never accepted before.
     *
     * @throws AcknowledgementRejectedException if it's genuine but must not sign the user in
     * @throws ZanShieldException if it isn't a valid ZanShield acknowledgement at all
     */
    public function acceptAcknowledgement(string $ticket): TicketPayload
    {
        $ack = $this->openAcknowledgement($ticket);
        if ($ack->responseCode !== ResponseCodes::SUCCESS || $ack->isAuthenticated !== true) {
            throw new AcknowledgementRejectedException(
                AcknowledgementRejectedException::REASON_NOT_AUTHENTICATED,
                $ack->message ?? 'ZanShield verification was not completed',
                $ack,
            );
        }

        $issuedAt = self::parseIsoDateTime($ack->dateTime);
        if ($issuedAt === null) {
            throw new AcknowledgementRejectedException(
                AcknowledgementRejectedException::REASON_EXPIRED, 'Acknowledgement has no valid dateTime', $ack);
        }
        if ($issuedAt < ($this->now)() - $this->maxAcknowledgementAgeSeconds) {
            throw new AcknowledgementRejectedException(
                AcknowledgementRejectedException::REASON_EXPIRED, 'Acknowledgement has expired', $ack);
        }

        if (!$ack->txnID || !$this->txnIdStore->markUsed($ack->txnID, $issuedAt + $this->maxAcknowledgementAgeSeconds)) {
            throw new AcknowledgementRejectedException(
                AcknowledgementRejectedException::REASON_REPLAYED, 'Acknowledgement was already used', $ack);
        }
        return $ack;
    }

    /** Unix seconds from ZanShield's ISO-8601 dateTime (Java writes up to 9 fractional digits). */
    private static function parseIsoDateTime(?string $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }
        $trimmed = preg_replace('/(\.\d{6})\d+/', '$1', $value);
        try {
            return (new DateTimeImmutable($trimmed))->getTimestamp();
        } catch (Throwable) {
            return null;
        }
    }

    /** Lower-level form for when you need fields {@see createTicket()} doesn't expose. */
    public function createTicketFromPayload(TicketPayload $payload): string
    {
        try {
            $payloadBytes = $payload->toWireJson();

            $signingKey = $this->myPrivateKey->withPadding(RSA::SIGNATURE_PKCS1)->withHash('sha256');
            $signature = $signingKey->sign($payloadBytes);

            $envelope = json_encode([
                'payload' => base64_encode($payloadBytes),
                'signature' => base64_encode($signature),
            ], JSON_UNESCAPED_SLASHES);

            $sealed = $this->seal($envelope, $this->enginePublicKey);
            return self::base64UrlEncode($sealed);
        } catch (ZanShieldException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new ZanShieldException('Failed to build ZanShield ticket', $e);
        }
    }

    /**
     * Decrypts $ticket with your key, then verifies it was signed by ZanShield's engine key.
     * Never trust a ticket that throws here, regardless of what its payload claims. This only
     * proves the ticket is genuine — prefer acceptAcknowledgement(), which also checks it's a
     * fresh, successful, first-time-used verification.
     */
    public function openAcknowledgement(string $ticket): TicketPayload
    {
        try {
            $sealed = self::base64UrlDecode($ticket);
            $envelopeJson = $this->unseal($sealed, $this->myPrivateKey);
            $envelope = json_decode($envelopeJson, true);
            if (!is_array($envelope) || !isset($envelope['payload'], $envelope['signature'])) {
                throw new ZanShieldException('Malformed envelope');
            }

            $payloadBytes = base64_decode($envelope['payload'], true);
            $signature = base64_decode($envelope['signature'], true);
            if ($payloadBytes === false || $signature === false) {
                throw new ZanShieldException('Malformed envelope encoding');
            }

            $verifyKey = $this->enginePublicKey->withPadding(RSA::SIGNATURE_PKCS1)->withHash('sha256');
            if (!$verifyKey->verify($payloadBytes, $signature)) {
                throw new ZanShieldException('Ticket signature verification failed');
            }

            return TicketPayload::fromWireJson($payloadBytes);
        } catch (ZanShieldException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new ZanShieldException('Failed to open acknowledgement ticket', $e);
        }
    }

    private function seal(string $plaintext, PublicKey $recipientPublicKey): string
    {
        try {
            $aesKey = random_bytes(32); // AES-256
            $iv = random_bytes(self::GCM_IV_BYTES);
        } catch (RandomException $e) {
            throw new ZanShieldException('Failed to generate random bytes', $e);
        }

        $cipher = new AES('gcm');
        $cipher->setKey($aesKey);
        $cipher->setNonce($iv);
        $ciphertext = $cipher->encrypt($plaintext);
        $tag = $cipher->getTag();
        // Append the tag to the ciphertext to match the wire format used by the other SDKs.
        $ciphertextWithTag = $ciphertext . $tag;

        $wrapKey = $recipientPublicKey->withPadding(RSA::ENCRYPTION_OAEP)->withHash('sha256')->withMGFHash('sha256');
        $wrappedKey = $wrapKey->encrypt($aesKey);

        $lengthPrefix = pack('N', strlen($wrappedKey)); // 4-byte big-endian
        return $lengthPrefix . $wrappedKey . $iv . $ciphertextWithTag;
    }

    private function unseal(string $sealed, PrivateKey $myPrivateKey): string
    {
        $wrappedKeyLength = unpack('N', substr($sealed, 0, 4))[1];
        $offset = 4;

        $wrappedKey = substr($sealed, $offset, $wrappedKeyLength);
        $offset += $wrappedKeyLength;

        $iv = substr($sealed, $offset, self::GCM_IV_BYTES);
        $offset += self::GCM_IV_BYTES;

        $ciphertextWithTag = substr($sealed, $offset);
        $tag = substr($ciphertextWithTag, -self::GCM_TAG_BYTES);
        $ciphertext = substr($ciphertextWithTag, 0, -self::GCM_TAG_BYTES);

        $unwrapKey = $myPrivateKey->withPadding(RSA::ENCRYPTION_OAEP)->withHash('sha256')->withMGFHash('sha256');
        $aesKey = $unwrapKey->decrypt($wrappedKey);

        $cipher = new AES('gcm');
        $cipher->setKey($aesKey);
        $cipher->setNonce($iv);
        $cipher->setTag($tag);
        $plaintext = $cipher->decrypt($ciphertext);
        if ($plaintext === false) {
            throw new ZanShieldException('AES-GCM authentication failed');
        }
        return $plaintext;
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        $padded = str_pad(strtr($data, '-_', '+/'), strlen($data) % 4 === 0 ? strlen($data) : strlen($data) + (4 - strlen($data) % 4), '=');
        $decoded = base64_decode($padded, true);
        if ($decoded === false) {
            throw new ZanShieldException('Invalid ticket encoding');
        }
        return $decoded;
    }
}
