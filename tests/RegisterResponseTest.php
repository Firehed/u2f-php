<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\RegisterResponse
 * @covers ::<protected>
 * @covers ::<private>
 */
class RegisterResponseTest extends \PHPUnit\Framework\TestCase
{

    /** @var string */
    private $validClientData =
        'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6I'.
        'kJyQWN4dGIxOWFYNTRoN0Y2T0NKWVptQ3prZHlHV0Nib3NEcHpNMUh2MkUiLCJvcmlnaW'.
        '4iOiJodHRwczovL3UyZi5lcmljc3Rlcm4uY29tIiwiY2lkX3B1YmtleSI6IiJ9';

    /** @var string */
    private $validRegistrationData =
        'BQS55FfGvxbgmcNO1cpNhdr4r-CMSbMtuhiMMJbXqd_3FD8Aah2X_n4ZiyBlgBqbbe4Rd'.
        'yksR7ZXoqPYT47-tmeWQJhf7xs1T8ObBRpkFi_VWG5oFJe499mQYxcj9BR0G8B5fjkYbU'.
        'uPCwNRiscOP8P18ep6V1OOulT3tq6kBC-94xQwggItMIIBF6ADAgECAgQFtgV5MAsGCSq'.
        'GSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIw'.
        'MDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKDEmMCQGA1UEAwwdW'.
        'XViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBw'.
        'NCAAT9uN6zoe1w62NsBm62AGmWpflw_LXbiPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0'.
        'yG5z4qEos6qA4yr011ZjeoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgy'.
        'LjEuMTALBgkqhkiG9w0BAQsDggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_m'.
        'yM5FL-2TWE18XziIfp2T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a'.
        '3PSbJiHuXjAt9VW5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8'.
        'th5tTARHqYOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1x'.
        'EvoZl_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6b'.
        'wp0gpxN0_cMNSTR3fFteK3SG2QwRAIgFTLJPY9_a0ZPujRfLufS-9ANCWemIWPHqs3ica'.
        'vMJIgCIFH5MSGDFkuY_NWhKa4mbLdbP6r7wMwspwHPG5_Xf48V';

    /**
     * @covers ::fromJson
     */
    public function testFromJson(): void
    {
        $json = json_encode([
            'registrationData' => $this->validRegistrationData,
            'version' => 'U2F_V2',
            'challenge' => 'BrAcxtb19aX54h7F6OCJYZmCzkdyGWCbosDpzM1Hv2E',
            'appId' => 'https://u2f.ericstern.com',
            'clientData' => $this->validClientData,
        ]);
        assert($json !== false);
        $response = RegisterResponse::fromJson($json);
        $this->assertInstanceOf(RegisterResponse::class, $response);
    }

    /**
     * @dataProvider clientErrors
     */
    public function testErrorResponse(int $code): void
    {
        $json = sprintf('{"errorCode":%d}', $code);
        $this->expectException(ClientErrorException::class);
        $this->expectExceptionCode($code);
        RegisterResponse::fromJson($json);
    }

    public function testFromJsonBadJson(): void
    {
        $json = 'this is not json';
        $this->expectException(InvalidDataException::class);
        // FIXME: code
        RegisterResponse::fromJson($json);
    }

    public function testFromJsonMissingClientData(): void
    {
        $json = sprintf('{"registrationData":"%s"}', $this->validRegistrationData);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        $this->expectExceptionMessageRegExp('/clientData/');
        RegisterResponse::fromJson($json);
    }

    public function testFromJsonMissingRegistrationData(): void
    {
        $json = sprintf('{"clientData":"%s"}', $this->validClientData);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        $this->expectExceptionMessageRegExp('/registrationData/');
        RegisterResponse::fromJson($json);
    }

    /**
     * @dataProvider invalidRegistrationData
     */
    public function testBadRegistrationData(string $registrationData): void
    {
        $json = $this->buildJson($this->validClientData, $registrationData);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MALFORMED_DATA);
        RegisterResponse::fromJson($json);
    }

    /**
     * @covers ::getAttestationCertificate
     * @covers ::getKeyHandleBinary
     * @covers ::getPublicKey
     * @covers ::getRpIdHash
     * @covers ::getSignature
     */
    public function testDataAccuracyAfterSuccessfulParsing(): void
    {
        $pubkey = "\x04".random_bytes(64);
        $handle = random_bytes(32);
        $st = "\x05".$pubkey."\x20".$handle;
        $body = random_bytes(256);
        $sig = random_bytes(4);
        $cert = "\x30\x82".pack('n', strlen($body)).$body;
        $reg = toBase64Web($st.$cert.$sig);
        $json = $this->buildJson($this->validClientData, $reg);
        $response = RegisterResponse::fromJson($json);

        $this->assertSame(
            $pubkey,
            $response->getPublicKey()->getBinary(),
            'Public key was not parsed correctly'
        );
        $this->assertSame(
            $handle,
            $response->getKeyHandleBinary(),
            'Key Handle was not parsed correctly'
        );
        $this->assertSame(
            $cert,
            $response->getAttestationCertificate()->getBinary(),
            'Cert was not parsed correctly'
        );
        $this->assertSame(
            $sig,
            $response->getSignature(),
            'Signature was not parsed correctly'
        );
        $this->assertSame(
            hash('sha256', 'https://u2f.ericstern.com', true),
            $response->getRpIdHash(),
            'Relying party Id hash was not parsed correctly'
        );
    }

    /**
     * @covers ::getSignedData
     */
    public function testGetSignedData(): void
    {
        $json = file_get_contents(__DIR__ . '/register_response.json');
        assert($json !== false);
        $response = RegisterResponse::fromJson($json);

        $expectedSignedData = sprintf(
            '%s%s%s%s%s',
            "\x00",
            hash('sha256', 'https://u2f.ericstern.com', true),
            hash(
                'sha256',
                '{'.
                '"typ":"navigator.id.finishEnrollment",'.
                '"challenge":"PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo",'.
                '"origin":"https://u2f.ericstern.com",'.
                '"cid_pubkey":""'.
                '}',
                true
            ),
            $response->getKeyHandleBinary(),
            $response->getPublicKey()->getBinary()
        );

        $this->assertSame(
            $expectedSignedData,
            $response->getSignedData(),
            'Wrong signed data'
        );
    }

    /**
     * @covers ::getChallenge
     */
    public function testGetChallenge(): void
    {
        $json = file_get_contents(__DIR__ . '/register_response.json');
        assert($json !== false);
        $response = RegisterResponse::fromJson($json);

        $this->assertSame(
            'PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo',
            $response->getChallenge()
        );
    }
    /**
     * @covers ::getRpIdHash
     */
    public function testGetRpIdHash(): void
    {
        $json = file_get_contents(__DIR__ . '/register_response.json');
        assert($json !== false);
        $response = RegisterResponse::fromJson($json);

        $this->assertSame(
            hash('sha256', 'https://u2f.ericstern.com', true),
            $response->getRpIdHash()
        );
    }

    // -( DataProviders )------------------------------------------------------

    /** @return array{int}[] */
    public function clientErrors()
    {
        return [
            [ClientError::OTHER_ERROR],
            [ClientError::BAD_REQUEST],
            [ClientError::CONFIGURATION_UNSUPPORTED],
            [ClientError::DEVICE_INELIGIBLE],
            [ClientError::TIMEOUT],
        ];
    }

    /** @return array{string}[] */
    public function invalidRegistrationData(): array
    {
        $bad_reserved_byte = "\x01".str_repeat('a', 200);
        $bad_pubkey_start = "\x05\x99".str_repeat('a', 200);
        $pubkey_too_short = "\x05\x04".random_bytes(5);
        $handle_too_short = "\x05\x04".random_bytes(64)."\x20".random_bytes(16);
        

        // Certs
        $valid_start = "\x05\x04".random_bytes(64)."\x20".random_bytes(32);
        $bad_cert_start = "\x40".str_repeat('a', 100); // Must start with bxxx10000
        $crazy_long_cert = "\x30\x85".str_repeat('a', 100);
        $too_short_cert = "\x30\x82\x01\x00".str_repeat('a', 50); // x0100 bytes long
        return array_map(function (string $s) {
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

    protected function buildJson(string $clientData, string $registrationData): string
    {
        return sprintf(
            '{"clientData":"%s","registrationData":"%s"}',
            $clientData,
            $registrationData
        );
    }
}
