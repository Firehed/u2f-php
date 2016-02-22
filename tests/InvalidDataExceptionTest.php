<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\InvalidDataException
 * @covers ::<protected>
 * @covers ::<private>
 */
class InvalidDataExceptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @covers ::__construct
     * @dataProvider invalidDataExceptionCodes 
     */
    public function testInvalidDataException(int $code) {
        $ex = new InvalidDataException($code, 'Prefill');
        $this->assertInstanceOf(InvalidDataException::class,
            $ex,
            '__construct failed');
        $this->assertNotEmpty($ex->getMessage(),
            'A predefined message should have been used');
        $this->assertRegExp('/Prefill/', $ex->getMessage(),
            'The sprintf args were not added to the exception message');
    }

    // -( DataProviders )------------------------------------------------------
    public function invalidDataExceptionCodes() {
        return [
            [InvalidDataException::MISSING_KEY],
            [InvalidDataException::MALFORMED_DATA],
            [InvalidDataException::PUBLIC_KEY_LENGTH],
        ];
    }

}
