<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\ECPublicKeyTrait
 * @covers ::<protected>
 * @covers ::<private>
 */
class ECPublicKeyTraitTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @covers ::setPublicKey
     * @covers ::getPublicKey
     */
    public function testAccessors() {
        $obj = new class {
            use ECPublicKeyTrait;
        };
        $key = "\x04".\random_bytes(64);
        $this->assertSame($obj, $obj->setPublicKey($key),
            'setPublicKey should return $this');
        $this->assertSame($key, $obj->getPublicKey(),
            'getPublicKey should return the set value');
    }

    /**
     * @covers ::getPublicKeyPem
     */
    public function testGetPublicKeyPem() {
        $obj = new class {
            use ECPublicKeyTrait;
        };
        
        $key = hex2bin(
            '04b4960ae0fa301033fbedc85c33ac30408dffd6098bc8580d8b66159959d89b9'.
            '31daf1d43a1949b07b7d47eea25efcac478bb5cd6ead0a3c3f7b7cb2a7bc1e3be'
        );
        $pem =
            "-----BEGIN PUBLIC KEY-----\r\n".
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtJYK4PowEDP77chcM6wwQI3/1gmL\r\n".
            "yFgNi2YVmVnYm5Mdrx1DoZSbB7fUfuol78rEeLtc1urQo8P3t8sqe8Hjvg==\r\n".
            "-----END PUBLIC KEY-----";

        $obj->setPublicKey($key);
        $this->assertSame($pem, $obj->getPublicKeyPem());
    }

    /**
     * @covers ::setPublicKey
     */
    public function testSetPublicKeyThrowsWithBadFirstByte() {
        $obj = new class {
            use ECPublicKeyTrait;
        };
        $key = "\x01".\random_bytes(64);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MALFORMED_DATA);
        $obj->setPublicKey($key);
    }


    /**
     * @covers ::setPublicKey
     */
    public function testSetPublicKeyThrowsWhenTooShort() {
        $obj = new class {
            use ECPublicKeyTrait;
        };
        $key = "\x04".random_bytes(63);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::PUBLIC_KEY_LENGTH);
        $obj->setPublicKey($key);
    }

    /**
     * @covers ::setPublicKey
     */
    public function testSetPublicKeyThrowsWhenTooLong() {
        $obj = new class {
            use ECPublicKeyTrait;
        };
        $key = "\x04".random_bytes(65);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::PUBLIC_KEY_LENGTH);
        $obj->setPublicKey($key);
    }



}
