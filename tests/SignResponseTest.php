<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\SignResponse
 * @covers ::<protected>
 * @covers ::<private>
 */
class SignResponseTest extends \PHPUnit\Framework\TestCase
{

    const JSON_FORMAT = '{"keyHandle":"%s","clientData":"%s","signatureData":"%s"}';

    private $valid_key_handle =
        'JUnVTStPn-V2-bCu0RlvPbukBpHTD5Mi1ZGglDOcN0vD45rnTD0BXdkRt78huTwJ7tVax'.
        'TqSetHjr22tCjmYLQ';

    private $valid_client_data =
        'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoid3Qye'.
        'mU4SXNrY1RPM25Jc08yRDJoRmpFNXRWRDA0MU5wblllc0xwSndlZyIsIm9yaWdpbiI6Im'.
        'h0dHBzOi8vdTJmLmVyaWNzdGVybi5jb20iLCJjaWRfcHVia2V5IjoiIn0';

    private $valid_signature_data =
        'AQAAAC0wRgIhAJPy1RvD1WCw1XZX53BXydX_Kyf_XZQueFSIPigRF-D2AiEAx3bJr5ixr'.
        'XGdUX1XooAfhz15ZIY8rC5H4qaW7gQspJ4';

    /**
     * @covers ::fromJson
     */
    public function testFromJsonWorks()
    {
        $json = sprintf(
            self::JSON_FORMAT,
            $this->valid_key_handle,
            $this->valid_client_data,
            $this->valid_signature_data
        );
        $response = SignResponse::fromJson($json);
        $this->assertInstanceOf(SignResponse::class, $response);
    }

    /**
     * @covers ::getCounter
     * @covers ::getSignature
     * @covers ::getUserPresenceByte
     */
    public function testDataAccuracyAfterSuccessfulParsing()
    {
        $sig = random_bytes(16);
        $counter = random_int(0, pow(2, 32));
        $signature_data = toBase64Web(pack('CNA*', 1, $counter, $sig));

        $challenge = toBase64Web(random_bytes(32));
        $key_handle = toBase64Web(random_bytes(16));

        $json = json_encode([
            "typ" => "navigator.id.getAssertion",
            "challenge" => $challenge,
            "origin" => "https://u2f.example.com",
            "cid_pubkey" => ""
        ]);
        assert($json !== false);
        $client_data = toBase64Web($json);

        $json = sprintf(
            self::JSON_FORMAT,
            $key_handle,
            $client_data,
            $signature_data
        );

        $response = SignResponse::fromJson($json);
        $this->assertSame(
            $key_handle,
            $response->getKeyHandleWeb(),
            'Key Handle was parsed incorrectly'
        );
        $this->assertSame(
            $counter,
            $response->getCounter(),
            'Counter was parsed incorrectly'
        );
        $this->assertSame(
            1,
            $response->getUserPresenceByte(),
            'User presence byte was parsed incorrectly'
        );
        $this->assertSame(
            $sig,
            $response->getSignature(),
            'Signature was parsed incorrectly'
        );
    }

    public function testSignatureWithNullRemainsIntact()
    {
        $sig = "\x00\x00\x00".random_bytes(10)."\x00\x00\x00";
        $sigData = toBase64Web("\x01\x00\x00\x00\x45".$sig);
        $json = sprintf(
            self::JSON_FORMAT,
            $this->valid_key_handle,
            $this->valid_client_data,
            $sigData
        );
        $response = SignResponse::fromJson($json);
        $this->assertSame(
            $sig,
            $response->getSignature(),
            'Signature trimmed a trailing NUL byte'
        );
    }

    public function testSignatureWithSpaceRemainsIntact()
    {
        $sig = '   '.random_bytes(10).'   ';
        $sigData = toBase64Web("\x01\x00\x00\x00\x45".$sig);
        $json = sprintf(
            self::JSON_FORMAT,
            $this->valid_key_handle,
            $this->valid_client_data,
            $sigData
        );
        $response = SignResponse::fromJson($json);
        $this->assertSame(
            $sig,
            $response->getSignature(),
            'Signature trimmed a trailing space'
        );
    }


    public function testFromJsonWithMissingKeyHandle()
    {
        $json = sprintf(
            '{"clientData":"%s","signatureData":"%s"}',
            $this->valid_client_data,
            $this->valid_signature_data
        );
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        SignResponse::fromJson($json);
    }

    public function testFromJsonWithMissingClientData()
    {
        $json = sprintf(
            '{"keyHandle":"%s","signatureData":"%s"}',
            $this->valid_key_handle,
            $this->valid_signature_data
        );
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        SignResponse::fromJson($json);
    }

    public function testFromJsonWithMissingSignatureData()
    {
        $json = sprintf(
            '{"keyHandle":"%s","clientData":"%s"}',
            $this->valid_key_handle,
            $this->valid_client_data
        );
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        SignResponse::fromJson($json);
    }

    public function testFromJsonWithInvalidSignatureData()
    {
        $json = sprintf(
            '{"keyHandle":"%s","clientData":"%s","signatureData":"%s"}',
            $this->valid_key_handle,
            $this->valid_client_data,
            '0000000'
        );
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MALFORMED_DATA);
        SignResponse::fromJson($json);
    }

    /**
     * @covers ::getSignedData
     */
    public function testGetSignedData()
    {
        $json = file_get_contents(__DIR__ . '/sign_response.json');
        assert($json !== false);
        $response = SignResponse::fromJson($json);

        $expectedSignedData = sprintf(
            '%s%s%s%s',
            hash('sha256', 'https://u2f.ericstern.com', true),
            "\x01", // user presence
            "\x00\x00\x00\x2d", // counter (int(45))
            hash(
                'sha256',
                '{'.
                '"typ":"navigator.id.getAssertion",'.
                '"challenge":"wt2ze8IskcTO3nIsO2D2hFjE5tVD041NpnYesLpJweg",'.
                '"origin":"https://u2f.ericstern.com",'.
                '"cid_pubkey":""'.
                '}',
                true
            )
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
    public function testGetChallenge()
    {
        $json = file_get_contents(__DIR__ . '/sign_response.json');
        assert($json !== false);
        $response = SignResponse::fromJson($json);

        $this->assertSame(
            'wt2ze8IskcTO3nIsO2D2hFjE5tVD041NpnYesLpJweg',
            $response->getChallenge()
        );
    }

    /**
     * @dataProvider clientErrors
     */
    public function testErrorResponse(int $code)
    {
        $json = sprintf('{"errorCode":%d}', $code);
        $this->expectException(ClientErrorException::class);
        $this->expectExceptionCode($code);
        SignResponse::fromJson($json);
    }

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
}
