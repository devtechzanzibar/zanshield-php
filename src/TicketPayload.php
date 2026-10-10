<?php

declare(strict_types=1);

namespace ZanShield\Sdk;

/**
 * The JSON payload carried inside a ticket. The same shape is used for both your outbound
 * ticket and ZanShield's signed acknowledgement — fields that don't apply to a given
 * direction are simply null and omitted from the wire JSON. See Integration Guide §3.1.
 */
final class TicketPayload
{
    public ?string $systemCode = null;
    public ?string $institutionCode = null;
    public ?string $userId = null;
    public ?string $email = null;
    /** Optional — lets the portal greet the user by name. */
    public ?string $fullName = null;
    /** Optional — needed for the user to choose SMS codes; also shown to your institution admin. */
    public ?string $mobile = null;
    public ?string $authenticationMethod = null;
    public ?string $dateTime = null;
    public ?bool $isAuthenticated = null;
    public ?string $authenticationMethods = null;
    public ?string $txnID = null;
    public ?int $responseCode = null;
    public ?string $message = null;

    private const WIRE_FIELDS = [
        'systemCode', 'institutionCode', 'userId', 'email', 'fullName', 'mobile',
        'authenticationMethod', 'dateTime', 'isAuthenticated', 'authenticationMethods',
        'txnID', 'responseCode', 'message',
    ];

    public function toWireJson(): string
    {
        $obj = [];
        foreach (self::WIRE_FIELDS as $field) {
            if ($this->$field !== null) {
                $obj[$field] = $this->$field;
            }
        }
        return json_encode($obj, JSON_UNESCAPED_SLASHES);
    }

    public static function fromWireJson(string $json): self
    {
        $obj = json_decode($json, true);
        $payload = new self();
        foreach (self::WIRE_FIELDS as $field) {
            if (array_key_exists($field, $obj)) {
                $payload->$field = $obj[$field];
            }
        }
        return $payload;
    }
}
