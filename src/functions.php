<?php

namespace Firehed\U2F;

/**
 * Takes a web-safe base64 encoded string and returns the decoded version
 * @param the encoded string
 * @return the raw binary string
 */
function fromBase64Web(string $base64): string {
    return base64_decode(strtr($base64, '-_', '+/'));
}

/**
 * Encodes any string to web-safe base64
 * @param the raw binary string
 * @return the encoded string
 */
function toBase64Web(string $binary): string {
    return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
}

// Multibyte string wrappers: hijack calls to `strlen` and `substr` to force
// 8-bit encoding in the event that `mbstring.func_overload` parameter is
// non-zero and the mbstring default charset is not 8bit.

/**
 * Identical to `\strlen` except when `mbstring.func_overload` is enabled and
 * set to a multi-byte character set, in which case it retains the
 * non-overloaded behavior.
 *
 * @param string The string being measured
 * @return int The length of the string, in bytes
 */
function strlen(string $string): int {
    if (function_exists('mb_strlen')) {
        return \mb_strlen($string, '8bit');
    }
    return \strlen($string);
}

/**
 * Identical to `\substr` except when `mbstring.func_overload` is enabled and
 * set to a multi-byte character set, in which case it retains the
 * non-overloaded behavior.
 *
 * @param string The input string
 * @param int The starting point, in bytes
 * @param int The length, in bytes
 * @return string The extracted part of the string
 */
function substr(string $string, int $start, int $length = null): string {
    if (function_exists('mb_substr')) {
        return \mb_substr($string, $start, $length, '8bit');
    }
    return \substr($string, $start, $length);
}
