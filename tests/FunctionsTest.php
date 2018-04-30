<?php
declare(strict_types=1);

namespace Firehed\U2F;

class FunctionsTest extends \PHPUnit\Framework\TestCase
{
    use MultibyteWarningTrait;

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

    /**
     * @covers Firehed\U2F\strlen
     * @dataProvider strlenVectors
     */
    public function testStrlen(string $string, int $length)
    {
        $this->assertSame(strlen($string), $length, 'Wrong length returned');
    }

    /**
     * @covers Firehed\U2F\substr
     * @dataProvider substrVectors
     */
    public function testSubstr(string $string, int $start, int $length = null, string $result)
    {
        $this->assertSame(
            $result,
            substr($string, $start, $length),
            sprintf(
                'Wrong substring returned: got bytes %s instead of %s',
                bin2hex(substr($string, $start, $length)),
                bin2hex($result)
            )
        );
    }

    public function vectors(): array
    {
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

    public function strlenVectors(): array
    {
        $this->skipIfNotMultibyte();
        // Strlen should be un-overloaded to just count bytes
        return [
            ['ascii text', 10],
            ['texte français', 15],
            ['русский текст', 25],
            ['日本語テキスト', 21],
            ['✨emoji❤️text🐰', 22],
            ['🐰', 4],
        ];
    }

    public function substrVectors(): array
    {
        $this->skipIfNotMultibyte();
        return [
            // Substr should be un-overloaded to just work on bytes, resulting
            // in multibyte characters potentially getting cut in half
            ['ascii text', 5, null, ' text'],
            ['ascii text', 0, 5, 'ascii'],
            ['texte français', 5, null, ' français'],
            ['texte français', 0, 5, 'texte'],
            ['русский текст', 5, null, chr(0x81).'ский текст'],
            ['русский текст', 0, 5, 'ру'.chr(0xD1)],
            ['日本語テキスト', 5, null, chr(0xAC).'語テキスト'],
            ['日本語テキスト', 0, 5, '日'.chr(0xE6).chr(0x9C)],
            ['✨emoji❤️text🐰', 5, null, 'oji❤️text🐰'],
            ['✨emoji❤️text🐰', 0, 5, '✨em'],
            ['🐰', 1, 2, chr(0x9F).chr(0x90)],
        ];
    }
}
