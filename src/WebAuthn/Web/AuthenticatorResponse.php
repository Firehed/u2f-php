<?php

declare(strict_types=1);

namespace Firehed\U2F\WebAuthn\Web;

use function array_map;
use function implode;

abstract class AuthenticatorResponse
{
    public string $clientDataJSON;

    /**
     * @param int[] $bytes
     */
    protected static function byteArrayToBinaryString(array $bytes): string
    {
        return implode('', array_map('chr', $bytes));
    }
}
