<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\RegisterResponse
 * @covers ::<protected>
 * @covers ::<private>
 */
class RegisterResponseTest extends \PHPUnit_Framework_TestCase
{

    private $validClientData = 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IkJyQWN4dGIxOWFYNTRoN0Y2T0NKWVptQ3prZHlHV0Nib3NEcHpNMUh2MkUiLCJvcmlnaW4iOiJodHRwczovL3UyZi5lcmljc3Rlcm4uY29tIiwiY2lkX3B1YmtleSI6IiJ9';
    private $validRegistrationData = "BQS55FfGvxbgmcNO1cpNhdr4r-CMSbMtuhiMMJbXqd_3FD8Aah2X_n4ZiyBlgBqbbe4RdyksR7ZXoqPYT47-tmeWQJhf7xs1T8ObBRpkFi_VWG5oFJe499mQYxcj9BR0G8B5fjkYbUuPCwNRiscOP8P18ep6V1OOulT3tq6kBC-94xQwggItMIIBF6ADAgECAgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXbiPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsDggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9VW5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHqYOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZl_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6bwp0gpxN0_cMNSTR3fFteK3SG2QwRAIgFTLJPY9_a0ZPujRfLufS-9ANCWemIWPHqs3icavMJIgCIFH5MSGDFkuY_NWhKa4mbLdbP6r7wMwspwHPG5_Xf48V";

    /**
     * @covers ::fromJson
     */
    public function testFromJson() {
        $json = sprintf('{"registrationData":"%s","version":"U2F_V2","challenge":"BrAcxtb19aX54h7F6OCJYZmCzkdyGWCbosDpzM1Hv2E","appId":"https://u2f.ericstern.com","clientData":"%s"}', $this->validRegistrationData, $this->validClientData);;
        $response = RegisterResponse::fromJson($json);
        $this->assertInstanceOf(RegisterResponse::class, $response);
    }

    /**
     * @dataProvider clientErrors
     */
    public function testErrorResponse(int $code) {
        $json = sprintf('{"errorCode":%d}', $code);
        $this->expectException(ClientErrorException::class);
        $this->expectExceptionCode($code);
        RegisterResponse::fromJson($json);
    }

    public function testFromJsonBadJson() {
        $json = 'this is not json';
        $this->expectException(InvalidDataException::class);
        // FIXME: code
        RegisterResponse::fromJson($json);
    }

    public function testFromJsonMissingClientData() {
        $json = sprintf('{"registrationData":"%s"}', $this->validRegistrationData);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        $this->expectExceptionMessageRegExp('/clientData/');
        RegisterResponse::fromJson($json);
    }

    public function testFromJsonMissingRegistrationData() {
        $json = sprintf('{"clientData":"%s"}', $this->validClientData);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        $this->expectExceptionMessageRegExp('/registrationData/');
        RegisterResponse::fromJson($json);
    }

    /**
     * @dataProvider invalidRegistrationData
     */
    public function testBadRegistrationData(string $registrationData) {
        $json = $this->buildJson($this->validClientData, $registrationData);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MALFORMED_DATA);
        RegisterResponse::fromJson($json);
    }

    /**
     * @covers ::getAttestationCertificateBinary
     * @covers ::getKeyHandleBinary
     * @covers ::getPublicKey
     * @covers ::getSignature
     */
    public function testDataAccuracyAfterSuccessfulParsing() {
        $pubkey = "\x04".random_bytes(64);
        $handle = random_bytes(32);
        $st = "\x05".$pubkey."\x20".$handle;
        $body = random_bytes(256);
        $sig = random_bytes(4);
        $cert = "\x30\x82".pack('n', strlen($body)).$body;
        $reg = toBase64Web($st.$cert.$sig);
        $json = $this->buildJson($this->validClientData, $reg);
        $response = RegisterResponse::fromJson($json);

        $this->assertSame($pubkey, $response->getPublicKey(),
            'Public key was not parsed correctly');
        $this->assertSame($handle, $response->getKeyHandleBinary(),
            'Key Handle was not parsed correctly');
        $this->assertSame($cert, $response->getAttestationCertificateBinary(),
            'Cert was not parsed correctly');
        $this->assertSame($sig, $response->getSignature(),
            'Signature was not parsed correctly');
    }

    // -( DataProviders )------------------------------------------------------

    public function clientErrors() {
        return [
            [ClientError::OTHER_ERROR],
            [ClientError::BAD_REQUEST],
            [ClientError::CONFIGURATION_UNSUPPORTED],
            [ClientError::DEVICE_INELIGIBLE],
            [ClientError::TIMEOUT],
        ];
    }

    public function invalidRegistrationData(): array {
        $bad_reserved_byte = "\x01".str_repeat('a',200);
        $bad_pubkey_start = "\x05\x99".str_repeat('a',200);
        $pubkey_too_short = "\x05\x04".random_bytes(5);
        $handle_too_short = "\x05\x04".random_bytes(64)."\x20".random_bytes(16);
        

        // Certs
        $valid_start = "\x05\x04".random_bytes(64)."\x20".random_bytes(32);
        $bad_cert_start = "\x40".str_repeat('a', 100); // Must start with bxxx10000
        $crazy_long_cert = "\x30\x85".str_repeat('a', 100);
        $too_short_cert = "\x30\x82\x01\x00".str_repeat('a',50); // x0100 bytes long
        return array_map(function(string $s) {
            return [toBase64Web($s)];
        }, [
            $bad_reserved_byte,
            $bad_pubkey_start,
            $pubkey_too_short,
            $handle_too_short,
            $valid_start.$bad_cert_start,
            $valid_start.$crazy_long_cert,
            $valid_start.$too_short_cert,
        ]);
    }

    // -( Helpers )------------------------------------------------------------

    protected function buildJson($clientData, $registrationData): string {
        return sprintf('{"clientData":"%s","registrationData":"%s"}',
            $clientData,
            $registrationData
        );
    }
}
