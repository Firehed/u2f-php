<?php
declare(strict_types=1);

namespace Firehed\U2F;

class functionsTest extends \PHPUnit_Framework_TestCase
{


    /**
     * @covers Firehed\U2F\fromBase64Web
     * @dataProvider vectors
     */
    public function testFromBase64Web($plain, $encoded) {
        $this->assertSame($plain, fromBase64Web($encoded),
            'Decoded vector did not match known plaintext version');
    }

    /**
     * @covers Firehed\U2F\toBase64Web
     * @dataProvider vectors
     */
    public function testToBase64Web($plain, $encoded) {
        $this->assertSame($encoded, toBase64Web($plain),
            'Encoded vector did not match known version');
    }

    public function vectors(): array {
        return [
            // Plain   Encoded
            // Adapted test vctors from RFC4648 Sec. 5 (padding trimmed)
            ["",       ""],
            ["f",      "Zg"],
            ["fo" ,    "Zm8"],
            ["foo",    "Zm9v"],
            ["foob",   "Zm9vYg"],
            ["fooba",  "Zm9vYmE"],
            ["foobar", "Zm9vYmFy"],
            // Added to ensure the -_ <--> +/ conversion is handled
            [hex2bin('000fc107e71c'), "AA_BB-cc"],
        ];
    }
}
