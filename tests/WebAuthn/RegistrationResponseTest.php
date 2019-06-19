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
     * @covers ::getAttestationCertificate
     * @covers ::getChallenge
     * @covers ::getKeyHandleBinary
     * @covers ::getPublicKey
     * @covers ::getRpIdHash
     * @covers ::getSignature
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

        $this->assertSame(
            'byUSpVKzETlJjwxjW8RpYQ',
            $response->getChallenge(),
            'Challenge'
        );

        $this->assertSame(hex2bin(
            '04' . // fixed
            'acb4d70da1504f2376361e0fb331ad41793e9698fa046945f51352820e7c2b78' . // x
            '35c628978409d8c97ef0bb464a5989a0274b24d91bf48901de8dd0450e265680' // y
        ), $response->getPublicKey()->getBinary(), 'Public key');

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

        $this->assertSame(hex2bin(
            '3046022100cd65252185e1f46b3566918c5129fa5ef2093f1c9672f58ac1b244a'.
            '28d5069f00221009a56c4465a0d2907dacdfcd8472954dad6f65fca52a159eeac'.
            '5c4fed9bdbfd9d'
        ), $response->getSignature(), 'Signature');

        $this->assertSame(hex2bin(
            '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763'
        ), $response->getRpIdHash(), 'Relying Party ID hash');

        $this->assertSame(hex2bin(
            '3082022d30820117a003020102020405b60579300b06092a864886f70d01010b3'.
            '02e312c302a0603550403132359756269636f2055324620526f6f742043412053'.
            '657269616c203435373230303633313020170d3134303830313030303030305a1'.
            '80f32303530303930343030303030305a30283126302406035504030c1d597562'.
            '69636f205532462045452053657269616c2039353831353033333059301306072'.
            'a8648ce3d020106082a8648ce3d03010703420004fdb8deb3a1ed70eb636c066e'.
            'b6006996a5f970fcb5db88fc3b305d41e5966f0c1b54b852fef0a0907ed17f3bf'.
            'fc29d4d321b9cf8a84a2ceaa038cabd35d598dea3263024302206092b06010401'.
            '82c40a020415312e332e362e312e342e312e34313438322e312e31300b06092a8'.
            '64886f70d01010b03820101007ed3fb6ccc252013f82f218c2a37da6031d20e7f'.
            '3081dafcaeb128fc7f9b233914bfb64d6135f17ce221fa764f453ef1273a8ce96'.
            '5956442bb2f1e47483f737dcbc98b585377fef50b270e0289f88436f1adcf49b2'.
            '621ee5e302df555b9ab74272e069f918149b3dec4f12228b10c0f88de36af58a7'.
            '4bb442b85ae005364bda6702058fc1f2d879b530111ea60e86c63f17fa5944cc8'.
            '3f0aa269848b3ee388a6c09e6b05953fcbb8f47e83a27e0072a63c32ad64864e9'.
            '26d7112fa1997f7839656fbb32be8f7889d0f0145519a27afdd8e46b04ca4290d'.
            '8540b634b886161e7588c86299dcdd6435d1678a3a6f0a74829c4dd3f70c3524d'.
            '1ddf16d78add21b64'
        ), $response->getAttestationCertificate()->getBinary(), 'Attestation cert');
    }

    /**
     * @covers ::__debugInfo
     */
    public function testDebugInfoDoesntPrintBinary()
    {
        $json = file_get_contents(__DIR__ . '/registrationresponse.json');
        assert($json !== false);
        $data = json_decode($json, true);

        $response = RegistrationResponse::fromDecodedJson($data);
        $debug = print_r($response, true);
        $this->assertRegExp(
            '/[^\x20-\x7f]/',
            $debug,
            'Debug output contained non-ascii'
        );
    }
}
