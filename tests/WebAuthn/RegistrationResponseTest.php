<?php
declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

/**
 * @coversDefaultClass Firehed\U2F\WebAuthn\RegistrationResponse
 * @covers ::<protected>
 * @covers ::<private>
 */
class RegistrationResponseTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @covers ::fromDecodedJson
     * @covers ::getKeyHandleBinary
     * @covers ::getPublicKeyBinary
     * @covers ::getSignedData
     */
    public function testFromDecodedJson()
    {
        $json = file_get_contents(__DIR__ . '/registrationresponse.json');
        assert($json !== false);
        $data = json_decode($json, true);

        $response = RegistrationResponse::fromDecodedJson($data);

        $this->assertSame(hex2bin(
            '89d8daecf079d5e11e4d3f27f8d6636d'.
            'f14f048d21ce2893623a7c4d3cec8624'.
            '40332960e33055f7c01242de0a5717b0'.
            '81b2ba0af4a0293b21753f0dd97f11f4'
        ), $response->getKeyHandleBinary(), 'Key handle ' . bin2hex($response->getKeyHandleBinary()));

        $this->assertSame(hex2bin(
            '04' . // fixed
            'acb4d70da1504f2376361e0fb331ad41793e9698fa046945f51352820e7c2b78' . // x
            '35c628978409d8c97ef0bb464a5989a0274b24d91bf48901de8dd0450e265680' // y
        ), $response->getPublicKeyBinary(), 'Public key');

        $this->assertSame(hex2bin(
            // \x00
            '00' .
            // rpIdHash
            '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763' .
            // clientDataHash (sha256 of clientDataJson)
            'cc9628728d679df85e14320c7f5be8a7ccfb2f3a91152e2a2b96110430d150bc' .
            // credentialId
            '89d8daecf079d5e11e4d3f27f8d6636df14f048d21ce2893623a7c4d3cec8624' .
            '40332960e33055f7c01242de0a5717b081b2ba0af4a0293b21753f0dd97f11f4' .
            // public key
            '04' . // publicKeyU2F
              'acb4d70da1504f2376361e0fb331ad41793e9698fa046945f51352820e7c2b78' .
              '35c628978409d8c97ef0bb464a5989a0274b24d91bf48901de8dd0450e265680'
        ), $response->getSignedData(), 'Signed data');
    }
}
