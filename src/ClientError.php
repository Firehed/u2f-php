<?php

namespace Firehed\U2F;

interface ClientError
{
    const OK = 0;
    const OTHER_ERROR = 1;
    const BAD_REQUEST = 2;
    const CONFIGURATION_UNSUPPORTED = 3;
    const DEVICE_INELIGIBLE = 4;
    const TIMEOUT = 5;

    const MESSAGES = [
        self::OK => 'Success. Not used in errors but reserved',
        self::OTHER_ERROR => 'An error otherwise not enumerated here',
        self::BAD_REQUEST => 'The request cannot be processed',
        self::CONFIGURATION_UNSUPPORTED => 'Client configuration is not supported',
        self::DEVICE_INELIGIBLE => 'The presented device is not eligible for this request',
        self::TIMEOUT => 'Timeout reached before request could be satisfied',
    ];
}
