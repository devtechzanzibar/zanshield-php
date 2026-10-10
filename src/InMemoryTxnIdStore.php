<?php

declare(strict_types=1);

namespace ZanShield\Sdk;

/** A TxnIdStore held in this PHP process only — see TxnIdStore for why that's rarely enough. */
final class InMemoryTxnIdStore implements TxnIdStore
{
    /** @var array<string, int> */
    private array $used = [];

    public function markUsed(string $txnId, int $keepUntil): bool
    {
        $now = time();
        $this->used = array_filter($this->used, static fn (int $expiry) => $expiry >= $now);
        if (isset($this->used[$txnId])) {
            return false;
        }
        $this->used[$txnId] = $keepUntil;
        return true;
    }
}
