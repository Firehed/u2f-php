<?php
declare(strict_types=1);

namespace Firehed\U2F\CBOR;

use const INF;
use const NAN;

/**
 * @coversDefaultClass Firehed\U2F\CBOR\Decoder
 * @covers ::<protected>
 * @covers ::<private>
 */
class DecoderTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @covers ::decode
     * @dataProvider githubTestVectors
     * @dataProvider rfcBigintExamples
     * @dataProvider rfcExamples
     * @dataProvider rfcTagExamples
     */
    public function testDecode(string $cbor, $expected)
    {
        $decoder = new Decoder();
        $result = $decoder->decode($cbor);
        if (is_float($expected) && ($expected > \PHP_INT_MAX) || ($expected < \PHP_INT_MIN)) {
            $this->assertEquals($expected, $result);
        } elseif (is_float($expected) && is_nan($expected)) {
            $this->assertTrue(is_nan($result), 'Result should be NAN');
        } else {
            $this->assertSame($expected, $result);
        }
    }

    /**
     * @see https://github.com/cbor/test-vectors
     */
    public function githubTestVectors(): array
    {
        $json = file_get_contents(__DIR__ . '/vectors.json');
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        return array_map(function ($row) {
            return [base64_decode($row['cbor']), $row['decoded']];
        }, array_filter($data, function ($row) {
            return isset($row['decoded']);
        }));
    }

    /**
     * @see RFC7049 Appendix A
     */
    public function rfcExamples(): array
    {
        return array_map(function ($vector) {
            return [hex2bin($vector[1]), $vector[0]];
        }, [
            [0, '00'],
            [1, '01'],
            [10, '0a'],
            [23, '17'],
            [24, '1818'],
            [25, '1819'],
            [100, '1864'],
            [1000, '1903e8'],
            [1000000, '1a000f4240'],
            [1000000000000, '1b000000e8d4a51000'],
            [-1, '20'],
            [-10, '29'],
            [-100, '3863'],
            [-1000, '3903e7'],
            [0.0, 'f90000'],
            [-0.0, 'f98000'],
            [1.0, 'f93c00'],
            [1.1, 'fb3ff199999999999a'],
            [1.5, 'f93e00'],
            [65504.0, 'f97bff'],
            [100000.0, 'fa47c35000'],
            [3.4028234663852886e+38, 'fa7f7fffff'],
            [1.0e+300, 'fb7e37e43c8800759c'],
            [5.960464477539063e-8, 'f90001'],
            [0.00006103515625, 'f90400'],
            [-4.0, 'f9c400'],
            [-4.1, 'fbc010666666666666'],
            [INF, 'f97c00'],
            [NAN, 'f97e00'],
            [-INF, 'f9fc00'],
            [INF, 'fa7f800000'],
            [NAN, 'fa7fc00000'],
            [-INF, 'faff800000'],
            [INF, 'fb7ff0000000000000'],
            [NAN, 'fb7ff8000000000000'],
            [-INF, 'fbfff0000000000000'],
            [false, 'f4'],
            [true, 'f5'],
            [null, 'f6'],
            // [undefined, 'f7'],
            // [simple(16), 'f0'],
            // [simple(24), 'f818'],
            // [simple(255), 'f8ff'],
// | 0("2013-03-21T20:04:00Z")    | 0xc074323031332d30332d32315432303a |
// |                              | 30343a30305a                       |
            // [1(1363896240), 'c11a514b67b0'],
            // [1(1363896240.5), 'c1fb41d452d9ec200000'],
            // [23(h'01020304'), 'd74401020304'],
            // [24(h'6449455446'), 'd818456449455446'],
// | 32("http://www.example.com") | 0xd82076687474703a2f2f7777772e6578 |
// |                              | 616d706c652e636f6d                 |
            ['', '40'],
            ["\x01\x02\x03\x04", '4401020304'],
            ["", '60'],
            ["a", '6161'],
            ["IETF", '6449455446'],
            ["\"\\", '62225c'],
            ["\u{00fc}", '62c3bc'],
            ["\u{6c34}", '63e6b0b4'],
            ["\u{10151}", '64f0908591'],
            [[], '80'],
            [[1, 2, 3], '83010203'],
            [[1, [2, 3], [4, 5]], '8301820203820405'],
            [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
                '98190102030405060708090a0b0c0d0e0f101112131415161718181819'],
            [[], 'a0'],
            [[1 => 2, 3 => 4], 'a201020304'],
            [["a" => 1, "b" => [2, 3]], 'a26161016162820203'],
            [["a", ["b" => "c"]], '826161a161626163'],
            [["a" => "A", "b" => "B", "c" => "C", "d" => "D", "e" => "E"],
                'a56161614161626142616361436164614461656145'],
            ["\x01\x02\x03\x04\x05", '5f42010243030405ff'],
            ["streaming", '7f657374726561646d696e67ff'],
            [[], '9fff'],
            [[1, [2, 3], [4, 5]], '9f018202039f0405ffff'],
            [[1, [2, 3], [4, 5]], '9f01820203820405ff'],
            [[1, [2, 3], [4, 5]], '83018202039f0405ff'],
            [[1, [2, 3], [4, 5]], '83019f0203ff820405'],
            [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
                '9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff'],
            [["a" => 1, "b" => [2, 3]], 'bf61610161629f0203ffff'],
            [["a", ["b" => "c"]], '826161bf61626163ff'],
            [["Fun" => true, "Amt" => -2], 'bf6346756ef563416d7421ff'],
        ]);
    }

    /**
     * These are numbers in the big yellow box in pack()'s documentation
     */
    public function rfcBigintExamples(): array
    {
        return array_map(function ($vector) {
            return [hex2bin($vector[1]), $vector[0]];
        }, [
            ['18446744073709551615', '1bffffffffffffffff'],
            ['-18446744073709551616', '3bffffffffffffffff'],
        ]);
    }

    public function rfcTagExamples(): array
    {
        return array_map(function ($vector) {
            return [hex2bin($vector[1]), $vector[0]];
        }, [
            [18446744073709551616, 'c249010000000000000000'],
            [-18446744073709551617, 'c349010000000000000000'],
        ]);
    }

    /**
     * Uses an example string from RFC7049 2.2.2
     * @covers ::decode
     */
    public function testVariableLengthByteString()
    {
        $cbor = hex2bin('5f44aabbccdd43eeff99ff');
        $decoder = new Decoder();
        $result = $decoder->decode($cbor);
        $this->assertSame(hex2bin('aabbccddeeff99'), $result);
    }
}
