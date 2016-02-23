<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\SignResponse
 * @covers ::<protected>
 * @covers ::<private>
 */
class SignResponseTest extends \PHPUnit_Framework_TestCase
{

    const JSON_FORMAT = '{"keyHandle":"%s","clientData":"%s","signatureData":"%s"}';
    private $valid_key_handle = 'JUnVTStPn-V2-bCu0RlvPbukBpHTD5Mi1ZGglDOcN0vD45rnTD0BXdkRt78huTwJ7tVaxTqSetHjr22tCjmYLQ';
    private $valid_client_data = 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoid3QyemU4SXNrY1RPM25Jc08yRDJoRmpFNXRWRDA0MU5wblllc0xwSndlZyIsIm9yaWdpbiI6Imh0dHBzOi8vdTJmLmVyaWNzdGVybi5jb20iLCJjaWRfcHVia2V5IjoiIn0';
    private $valid_signature_data = 'AQAAAC0wRgIhAJPy1RvD1WCw1XZX53BXydX_Kyf_XZQueFSIPigRF-D2AiEAx3bJr5ixrXGdUX1XooAfhz15ZIY8rC5H4qaW7gQspJ4';

    /**
     * @covers ::fromJson
     */
    public function testFromJsonWorks() {
        $json = sprintf(self::JSON_FORMAT,
            $this->valid_key_handle,
            $this->valid_client_data,
            $this->valid_signature_data);
        $response = SignResponse::fromJson($json);
        $this->assertInstanceOf(SignResponse::class, $response);
    }

    /**
     * @covers ::getCounter
     * @covers ::getSignature
     * @covers ::getUserPresenceByte
     */
    public function testDataAccuracyAfterSuccessfulParsing() {
        $sig = random_bytes(16);
        $counter = random_int(0, pow(2,32));
        $signature_data = toBase64Web(pack('CNA*', 1, $counter, $sig));

        $challenge = toBase64Web(random_bytes(32));
        $key_handle = toBase64Web(random_bytes(16));

        $client_data = toBase64Web(json_encode([
            "typ" => "navigator.id.getAssertion",
            "challenge" => $challenge,
            "origin" => "https://u2f.example.com",
            "cid_pubkey" => ""
        ]));

        $json = sprintf(self::JSON_FORMAT,
            $key_handle,
            $client_data,
            $signature_data);

        $response = SignResponse::fromJson($json);
        $this->assertSame($key_handle, $response->getKeyHandleWeb(),
            'Key Handle was parsed incorrectly');
        $this->assertSame($counter, $response->getCounter(),
            'Counter was parsed incorrectly');
        $this->assertSame(1, $response->getUserPresenceByte(),
            'User presence byte was parsed incorrectly');
        $this->assertSame($sig, $response->getSignature(),
            'Signature was parsed incorrectly');
    }

    public function testSignatureWithNullRemainsIntact() {
        $sig = "\x00\x00\x00".random_bytes(10)."\x00\x00\x00";
        $sigData = toBase64Web("\x01\x00\x00\x00\x45".$sig);
        $json = sprintf(self::JSON_FORMAT,
            $this->valid_key_handle,
            $this->valid_client_data,
            $sigData);
        $response = SignResponse::fromJson($json);
        $this->assertSame($sig, $response->getSignature(),
            'Signature trimmed a trailing NUL byte');
    }

    public function testSignatureWithSpaceRemainsIntact() {
        $sig = '   '.random_bytes(10).'   ';
        $sigData = toBase64Web("\x01\x00\x00\x00\x45".$sig);
        $json = sprintf(self::JSON_FORMAT,
            $this->valid_key_handle,
            $this->valid_client_data,
            $sigData);
        $response = SignResponse::fromJson($json);
        $this->assertSame($sig, $response->getSignature(),
            'Signature trimmed a trailing space');
    }


    public function testFromJsonWithMissingKeyHandle() {
        $json = sprintf('{"clientData":"%s","signatureData":"%s"}',
            $this->valid_client_data, $this->valid_signature_data);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        SignResponse::fromJson($json);
    }

    public function testFromJsonWithMissingClientData() {
        $json = sprintf('{"keyHandle":"%s","signatureData":"%s"}',
            $this->valid_key_handle, $this->valid_signature_data);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        SignResponse::fromJson($json);
    }

    public function testFromJsonWithMissingSignatureData() {
        $json = sprintf('{"keyHandle":"%s","clientData":"%s"}',
            $this->valid_key_handle, $this->valid_client_data);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        SignResponse::fromJson($json);
    }

    public function testFromJsonWithInvalidSignatureData() {
        $json = sprintf('{"keyHandle":"%s","clientData":"%s","signatureData":"%s"}',
            $this->valid_key_handle,
            $this->valid_client_data,
            '0000000');
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MALFORMED_DATA);
        SignResponse::fromJson($json);
    }

    /**
     * @dataProvider clientErrors
     */
    public function testErrorResponse(int $code) {
        $json = sprintf('{"errorCode":%d}', $code);
        $this->expectException(ClientErrorException::class);
        $this->expectExceptionCode($code);
        SignResponse::fromJson($json);
    }

    public function clientErrors() {
        return [
            [ClientError::OTHER_ERROR],
            [ClientError::BAD_REQUEST],
            [ClientError::CONFIGURATION_UNSUPPORTED],
            [ClientError::DEVICE_INELIGIBLE],
            [ClientError::TIMEOUT],
        ];
    }

}
