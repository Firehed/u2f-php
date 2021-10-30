<?php

declare(strict_types=1);

namespace Firehed\U2F\WebAuthn\Web;

final class AuthenticatorAssertionResponse extends AuthenticatorResponse
{
    public string $authenticatorData;

    public string $rawId;

    public string $signature;

    public ?string $userHandle = null;

    /**
     * This expects JSON encoding the following format:
     * {
     *   rawId: uint8[],
     *   type: 'public-key',
     *   response: {
     *     authenticatorData: uint8[],
     *     clientDataJSON: uint8[],
     *     signature: uint8[],
     *   }
     * }
     *
     * This is, in effect, a serialized form of `PublicKeyCredential` (modulo
     * the `id` field); the ArrayBuffer objects contained within are to be
     * converted to `UInt8Array` objects or render in JSON as same: a list of
     * uint8 numbers.
     *
     * It is not necessary to use this parser, but the examples provided will
     * do so expecting the same format. You may manually construct this object
     * and fill in the values in any way you choose.
     */
    public static function parseJson(string $json): AuthenticatorAssertionResponse
    {
        $data = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        $response = $data['response'];

        $aar = new AuthenticatorAssertionResponse();
        $aar->rawId = self::byteArrayToBinaryString($data['rawId']);
        $aar->authenticatorData = self::byteArrayToBinaryString($response['authenticatorData']);
        $aar->clientDataJSON = self::byteArrayToBinaryString($response['clientDataJSON']);
        $aar->signature = self::byteArrayToBinaryString($response['signature']);
        // TODO: userHandle
        return $aar;
    }
}
