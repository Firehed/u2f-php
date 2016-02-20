<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\ClientErrorException
 * @covers ::<protected>
 * @covers ::<private>
 */
class ClientErrorExceptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @covers ::__construct
     * @dataProvider clientErrors
     */
    public function testClientError(int $code) {
        $ex = new ClientErrorException($code);
        $this->assertInstanceOf(ClientErrorException::class,
            $ex,
            '__construct failed');
        $this->assertNotEmpty($ex->getMessage(),
            'A predefined message should have been used');
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


}
