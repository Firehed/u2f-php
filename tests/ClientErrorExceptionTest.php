<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\ClientErrorException
 */
class ClientErrorExceptionTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @dataProvider clientErrors
     */
    public function testClientError(int $code): void
    {
        $ex = new ClientErrorException($code);
        $this->assertInstanceOf(
            ClientErrorException::class,
            $ex,
            '__construct failed'
        );
        $this->assertNotEmpty(
            $ex->getMessage(),
            'A predefined message should have been used'
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
}
