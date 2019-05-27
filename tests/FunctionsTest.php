<?php
declare(strict_types=1);

namespace Firehed\U2F;

class FunctionsTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @covers Firehed\U2F\fromBase64Web
     * @dataProvider vectors
     */
    public function testFromBase64Web($plain, $encoded)
    {
        $this->assertSame(
            $plain,
            fromBase64Web($encoded),
            'Decoded vector did not match known plaintext version'
        );
    }

    /**
     * @covers Firehed\U2F\toBase64Web
     * @dataProvider vectors
     */
    public function testToBase64Web($plain, $encoded)
    {
        $this->assertSame(
            $encoded,
            toBase64Web($plain),
            'Encoded vector did not match known version'
        );
    }
}
