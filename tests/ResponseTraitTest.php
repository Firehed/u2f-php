<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\ResponseTrait
 * @deprecated
 */
class ResponseTraitTest extends \PHPUnit\Framework\TestCase
{
    /** @var object */
    private $trait;

    public function setUp(): void
    {
        $this->trait = new class {
            use ResponseTrait;
            protected function parseResponse(array $response): self
            {
                $this->setSignature($response['signature']);
                return $this;
            }
        };
    }

    public function testValidJson(): void
    {
        $signature = __METHOD__;
        $json = json_encode([
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwi'.
                'Y2hhbGxlbmdlIjoid3QyemU4SXNrY1RPM25Jc08yRDJoRmpFNXRWRDA0MU5w'.
                'blllc0xwSndlZyIsIm9yaWdpbiI6Imh0dHBzOi8vdTJmLmVyaWNzdGVybi5j'.
                'b20iLCJjaWRfcHVia2V5IjoiIn0',
            'signature' => $signature,

        ]);
        $response = $this->trait::fromJson($json);
        // This is a little goofy because it's an anonymous class, but seems
        // preferable to declaring a one-off class in the test to implement the
        // trait instead.
        $this->assertInstanceOf(
            get_class($this->trait),
            $response,
            'Parsed response was the wrong type'
        );

        $this->assertSame(
            __METHOD__,
            $response->getSignature(),
            'Signature was not parsed correctly'
        );
    }

    public function testFromJsonWithNonJson(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MALFORMED_DATA);
        $this->trait::fromJson('this is not json');
    }

    /**
     * @dataProvider clientErrors
     */
    public function testErrorResponse(int $code): void
    {
        $json = sprintf('{"errorCode":%d}', $code);
        $this->expectException(ClientErrorException::class);
        $this->expectExceptionCode($code);
        $this->trait::fromJson($json);
    }

    /**
     * @dataProvider badClientData
     */
    public function testClientDataValidation(string $json, int $code): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode($code);
        $this->trait::fromJson($json);
    }

    // -( DataProviders )------------------------------------------------------

    /** @return array{int}[] */
    public function clientErrors(): array
    {
        return [
            [ClientError::OTHER_ERROR],
            [ClientError::BAD_REQUEST],
            [ClientError::CONFIGURATION_UNSUPPORTED],
            [ClientError::DEVICE_INELIGIBLE],
            [ClientError::TIMEOUT],
        ];
    }

    /** @return array{string, int}[] */
    public function badClientData(): array
    {
        return [
            ['{}', InvalidDataException::MISSING_KEY],
            ['{"clientData":25}', InvalidDataException::MALFORMED_DATA],
        ];
    }
}
