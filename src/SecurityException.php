<?php
declare(strict_types=1);

namespace Firehed\U2F;
use Exception;

class SecurityException extends Exception
{
    const SIGNATURE_INVALID = 1;
    const COUNTER_USED = 2;
    const CHALLENGE_MISMATCH = 3;
    const KEY_HANDLE_UNRECOGNIZED = 4;
    const NO_TRUSTED_CA = 5;

    const MESSAGES = [
        self::SIGNATURE_INVALID => 'Signature verification failed',
        self::COUNTER_USED => 'Response counter value is too low, indicating a possible replay attack or cloned token. It is also possible but unlikely that the token\'s internal counter wrapped around. This token should be invalidated or flagged for review.',
        self::CHALLENGE_MISMATCH => 'Response challenge does not match request',
        self::KEY_HANDLE_UNRECOGNIZED => 'Key handle has not been registered',
        self::NO_TRUSTED_CA => 'The attestation certificate was not signed by any trusted Certificate Authority',
    ];

    public function __construct(int $code) {
        parent::__construct(self::MESSAGES[$code] ?? '', $code);
    }

}
