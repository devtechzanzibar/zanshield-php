<?php

declare(strict_types=1);

namespace ZanShield\Sdk\Tests;

use PHPUnit\Framework\TestCase;
use phpseclib3\Crypt\RSA;
use ZanShield\Sdk\AcknowledgementRejectedException;
use ZanShield\Sdk\TicketPayload;
use ZanShield\Sdk\TxnIdStore;
use ZanShield\Sdk\ZanShieldClient;
use ZanShield\Sdk\ZanShieldException;

/**
 * Simulates both sides of the protocol with throwaway key pairs — a "client" (this SDK) and
 * a stand-in "engine" — to prove the wire format round-trips correctly without needing real
 * ZanShield keys.
 */
final class ZanShieldClientTest extends TestCase
{
    private static $clientPrivate;
    private static $enginePrivate;

    public static function setUpBeforeClass(): void
    {
        self::$clientPrivate = RSA::createKey(2048);
        self::$enginePrivate = RSA::createKey(2048);
    }

    private static function client(?TxnIdStore $store = null, int $maxAge = 180, ?\Closure $now = null): ZanShieldClient
    {
        return new ZanShieldClient(
            'TESTSYS', 'TESTINST', self::$clientPrivate, self::$enginePrivate->getPublicKey(), $store, $maxAge, $now);
    }

    /** The engine's side: decrypts with its key, trusts the client's public key — and signs acks. */
    private static function engineView(): ZanShieldClient
    {
        return new ZanShieldClient('TESTSYS', 'TESTINST', self::$enginePrivate, self::$clientPrivate->getPublicKey());
    }

    private static function engineAck(int $code = 9000, bool $authenticated = true, string $txnId = 'txn-1', ?string $dateTime = null): string
    {
        $ack = new TicketPayload();
        $ack->systemCode = 'TESTSYS';
        $ack->institutionCode = 'TESTINST';
        $ack->userId = 'user-123';
        $ack->email = 'user@example.com';
        $ack->dateTime = $dateTime ?? gmdate('Y-m-d\TH:i:s\Z');
        $ack->responseCode = $code;
        $ack->isAuthenticated = $authenticated;
        $ack->authenticationMethod = 'TOTP';
        $ack->txnID = $txnId;
        $ack->message = $code === 9000 ? 'Success' : 'Maximum attempt reached';
        return self::engineView()->createTicketFromPayload($ack);
    }

    public function testTicketCarriesWhoTheUserIsAndNoRequestType(): void
    {
        $ticket = self::client()->createTicket('user-123', 'user@example.com', 'Amina Juma', '0772 108 420');
        $opened = self::engineView()->openAcknowledgement($ticket);

        $this->assertSame('TESTSYS', $opened->systemCode);
        $this->assertSame('TESTINST', $opened->institutionCode);
        $this->assertSame('user-123', $opened->userId);
        $this->assertSame('user@example.com', $opened->email);
        $this->assertSame('Amina Juma', $opened->fullName);
        $this->assertSame('0772 108 420', $opened->mobile);
        $this->assertStringEndsWith('Z', $opened->dateTime);
    }

    public function testOptionalFieldsAreLeftOut(): void
    {
        $opened = self::engineView()->openAcknowledgement(self::client()->createTicket('user-123', 'user@example.com'));
        $this->assertNull($opened->fullName);
        $this->assertNull($opened->mobile);
    }

    public function testBuildsThePortalUrl(): void
    {
        $this->assertSame('https://portal.example/ticket?ticket=a%2Bb', ZanShieldClient::portalUrl('https://portal.example/', 'a+b'));
        $this->assertSame('https://portal.example/ticket?ticket=abc&add=1', ZanShieldClient::portalUrl('https://portal.example', 'abc', true));
    }

    public function testAcceptsAFreshSuccessfulAcknowledgementOnce(): void
    {
        $client = self::client();
        $ack = self::engineAck(txnId: 'txn-1');

        $accepted = $client->acceptAcknowledgement($ack);
        $this->assertSame('user-123', $accepted->userId);
        $this->assertSame('TOTP', $accepted->authenticationMethod);

        try {
            $client->acceptAcknowledgement($ack);
            $this->fail('expected a replay to be rejected');
        } catch (AcknowledgementRejectedException $e) {
            $this->assertSame(AcknowledgementRejectedException::REASON_REPLAYED, $e->reason);
        }
    }

    public function testRejectsAnUnsuccessfulAcknowledgement(): void
    {
        try {
            self::client()->acceptAcknowledgement(self::engineAck(9032, false, 'txn-2'));
            $this->fail('expected rejection');
        } catch (AcknowledgementRejectedException $e) {
            $this->assertSame(AcknowledgementRejectedException::REASON_NOT_AUTHENTICATED, $e->reason);
            $this->assertSame(9032, $e->acknowledgement->responseCode);
        }
    }

    public function testRejectsAnOldAcknowledgementUnlessTheWindowIsLonger(): void
    {
        $now = static fn (): int => strtotime('2026-10-08T12:00:00Z');
        // Java-style timestamp: nanosecond precision.
        $ack = self::engineAck(txnId: 'txn-3', dateTime: '2026-10-08T11:56:00.123456789Z');

        try {
            self::client(now: $now)->acceptAcknowledgement($ack);
            $this->fail('expected expiry');
        } catch (AcknowledgementRejectedException $e) {
            $this->assertSame(AcknowledgementRejectedException::REASON_EXPIRED, $e->reason);
        }

        $this->assertSame('txn-3', self::client(maxAge: 300, now: $now)->acceptAcknowledgement($ack)->txnID);
    }

    public function testUsesTheConfiguredTxnIdStore(): void
    {
        $alwaysUsed = new class implements TxnIdStore {
            public function markUsed(string $txnId, int $keepUntil): bool
            {
                return false;
            }
        };

        $this->expectException(AcknowledgementRejectedException::class);
        self::client($alwaysUsed)->acceptAcknowledgement(self::engineAck(txnId: 'txn-4'));
    }

    public function testRejectsATicketSignedByTheWrongKey(): void
    {
        $impostor = new ZanShieldClient('TESTSYS', 'TESTINST', RSA::createKey(2048), self::$enginePrivate->getPublicKey());
        $forged = $impostor->createTicket('user-123', 'user@example.com');

        $this->expectException(ZanShieldException::class);
        self::engineView()->openAcknowledgement($forged);
    }

    public function testRejectsATamperedTicket(): void
    {
        $ticket = self::client()->createTicket('user-123', 'user@example.com');
        $middle = intdiv(strlen($ticket), 2);
        $ticket[$middle] = $ticket[$middle] === 'A' ? 'B' : 'A';

        $this->expectException(ZanShieldException::class);
        self::engineView()->openAcknowledgement($ticket);
    }
}
