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
