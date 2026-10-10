<?php

declare(strict_types=1);

namespace ZanShield\Sdk;

use Exception;
use Throwable;

/** Thrown for any failure while building or opening a ZanShield ticket. */
class ZanShieldException extends Exception
{
    public function __construct(string $message, ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
