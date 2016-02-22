<?php
declare(strict_types=1);

namespace Firehed\U2F;
use Exception;

class InvalidDataException extends Exception
{
    const MISSING_KEY = 1;
    const MALFORMED_DATA = 2;
    const PUBLIC_KEY_LENGTH = 3;

    const MESSAGES = [
        self::MISSING_KEY => 'Missing key %s',
        self::MALFORMED_DATA => 'Invalid data found in %s',
        self::PUBLIC_KEY_LENGTH => 'Public key length invalid, must be %s bytes',
    ];

    public function __construct(int $code, string ...$args) {
        $format = self::MESSAGES[$code] ?? 'Default message';

        $message = sprintf($format, ...$args);
        parent::__construct($message, $code);
    }

}
