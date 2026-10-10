<?php

declare(strict_types=1);

namespace ZanShield\Sdk;

/** The responseCode values ZanShield puts on acknowledgements — Integration Guide §7. */
final class ResponseCodes
{
    /** The only code that means the user verified successfully. */
    public const SUCCESS = 9000;
    public const INVALID_TICKET = 9031;
    public const MAX_ATTEMPTS_REACHED = 9032;
    public const TICKET_EXPIRED = 9038;
    public const UNKNOWN_CLIENT_SYSTEM = 9040;
    public const METHOD_ALREADY_REGISTERED = 9041;
    public const METHOD_NOT_REGISTERED = 9042;
    public const INVALID_CODE = 9043;
    public const WEBAUTHN_ERROR = 9044;
    public const METHOD_NOT_ALLOWED = 9045;
    public const MOBILE_NOT_AVAILABLE = 9046;
    public const SMS_DELIVERY_FAILED = 9047;
}
