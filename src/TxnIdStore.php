<?php

declare(strict_types=1);

namespace ZanShield\Sdk;

/**
 * Remembers which acknowledgement txnIDs were already accepted, so a leaked callback URL can't be
 * replayed into a second session. PHP usually runs one process per request, so the in-memory
 * default only protects a single long-running process — in production implement this over shared
 * storage (a database unique key, Redis SET NX, APCu, ...).
 */
interface TxnIdStore
{
    /** Records $txnId until $keepUntil (unix seconds); true the first time it's seen, false if already used. */
    public function markUsed(string $txnId, int $keepUntil): bool;
}
