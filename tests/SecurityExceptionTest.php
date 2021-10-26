<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\SecurityException
 */
class SecurityExceptionTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @dataProvider securityExceptionCodes
     */
    public function testSecurityException(int $code): void
    {
        $ex = new SecurityException($code);
        $this->assertInstanceOf(
            SecurityException::class,
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
    public function securityExceptionCodes()
    {
        return [
            [SecurityException::SIGNATURE_INVALID],
            [SecurityException::COUNTER_USED],
            [SecurityException::CHALLENGE_MISMATCH],
            [SecurityException::KEY_HANDLE_UNRECOGNIZED],
            [SecurityException::NO_TRUSTED_CA],
        ];
    }
}
