<?php

namespace Firehed\U2F;

/**
 * Takes a web-safe base64 encoded string and returns the decoded version
 * @param string $base64 the encoded string
 * @return string the raw binary string
 */
function fromBase64Web(string $base64): string
{
    $decoded = base64_decode(strtr($base64, '-_', '+/'));
    assert($decoded !== false);
    return $decoded;
}

/**
 * Encodes any string to web-safe base64
 * @param string $binary the raw binary string
 * @return string the encoded string
 */
function toBase64Web(string $binary): string
{
    return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
}
