<?php

declare(strict_types=1);

namespace Firehed\U2F\WebAuthn\Web;

final class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
    public string $attestationObject;

    // sequence<DOMString>                              getTransports();
    // ArrayBuffer                                      getAuthenticatorData();
    // ArrayBuffer?                                     getPublicKey();
    // COSEAlgorithmIdentifier                          getPublicKeyAlgorithm();

    /**
     * This expects JSON encoding the following format:
     * {
     *   rawId: uint8[],
     *   type: 'public-key',
     *   response: {
     *     attestestationObject: uint8[],
     *     clientDataJSON: uint8[],
     *   }
     * }
     */
    public static function parseJson(string $json): AuthenticatorAttestationResponse
    {
        $data = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        $response = $data['response'];

        $aar = new AuthenticatorAttestationResponse();
        // $aar->rawId = self::byteArrayToBinaryString($data['rawId']);
        $aar->attestationObject = self::byteArrayToBinaryString($response['attestationObject']);
        $aar->clientDataJSON = self::byteArrayToBinaryString($response['clientDataJSON']);
        // TODO: userHandle
        // print_r($aar);
        return $aar;
    }
}
