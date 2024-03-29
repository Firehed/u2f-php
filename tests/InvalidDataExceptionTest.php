<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\InvalidDataException
 */
class InvalidDataExceptionTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @dataProvider invalidDataExceptionCodes
     */
    public function testInvalidDataException(int $code): void
    {
        $ex = new InvalidDataException($code, 'Prefill');
        $this->assertInstanceOf(
            InvalidDataException::class,
            $ex,
            '__construct failed'
        );
        $this->assertNotEmpty(
            $ex->getMessage(),
            'A predefined message should have been used'
        );
        $this->assertRegExp(
            '/Prefill/',
            $ex->getMessage(),
            'The sprintf args were not added to the exception message'
        );
    }

    // -( DataProviders )------------------------------------------------------
    /** @return array{int}[] */
    public function invalidDataExceptionCodes()
    {
        return [
            [InvalidDataException::MISSING_KEY],
            [InvalidDataException::MALFORMED_DATA],
            [InvalidDataException::PUBLIC_KEY_LENGTH],
        ];
    }
}
