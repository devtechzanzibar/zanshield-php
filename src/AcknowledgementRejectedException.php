<?php

declare(strict_types=1);

namespace ZanShield\Sdk;

/**
 * Thrown by ZanShieldClient::acceptAcknowledgement() when a genuine acknowledgement must still not
 * start a session. $reason is one of the REASON_* constants; $acknowledgement has its contents.
 */
final class AcknowledgementRejectedException extends ZanShieldException
{
    public const REASON_NOT_AUTHENTICATED = 'NOT_AUTHENTICATED';
    public const REASON_EXPIRED = 'EXPIRED';
    public const REASON_REPLAYED = 'REPLAYED';

    public function __construct(
        public readonly string $reason,
        string $message,
        public readonly TicketPayload $acknowledgement
    ) {
        parent::__construct($message);
    }
}
