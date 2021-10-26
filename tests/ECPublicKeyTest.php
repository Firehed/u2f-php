<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\ECPublicKey
 */
class ECPublicKeyTest extends \PHPUnit\Framework\TestCase
{
    public function testConstruct(): void
    {
        $key = "\x04".\random_bytes(64);
        $obj = new ECPublicKey($key);
        $this->assertInstanceOf(PublicKeyInterface::class, $obj);
    }

    public function testConstructThrowsWithBadFirstByte(): void
    {
        $key = "\x01".\random_bytes(64);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MALFORMED_DATA);
        new ECPublicKey($key);
    }


    public function testConstructThrowsWhenTooShort(): void
    {
        $key = "\x04".random_bytes(63);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::PUBLIC_KEY_LENGTH);
        new ECPublicKey($key);
    }

    public function testConstructThrowsWhenTooLong(): void
    {
        $key = "\x04".random_bytes(65);
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::PUBLIC_KEY_LENGTH);
        new ECPublicKey($key);
    }

    public function testGetBinary(): void
    {
        $key = "\x04".\random_bytes(64);
        $obj = new ECPublicKey($key);
        $this->assertSame(
            $key,
            $obj->getBinary(),
            'getBinary should return the set value'
        );
    }

    public function testGetPublicKeyPem(): void
    {
        $key = hex2bin(
            '04b4960ae0fa301033fbedc85c33ac30408dffd6098bc8580d8b66159959d89b9'.
            '31daf1d43a1949b07b7d47eea25efcac478bb5cd6ead0a3c3f7b7cb2a7bc1e3be'
        );
        assert($key !== false);
        $obj = new ECPublicKey($key);
        $pem =
            "-----BEGIN PUBLIC KEY-----\r\n".
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtJYK4PowEDP77chcM6wwQI3/1gmL\r\n".
            "yFgNi2YVmVnYm5Mdrx1DoZSbB7fUfuol78rEeLtc1urQo8P3t8sqe8Hjvg==\r\n".
            "-----END PUBLIC KEY-----";

        $this->assertSame($pem, $obj->getPemFormatted());
    }

    public function testDebugInfoEncodesBinary(): void
    {
        $x = random_bytes(32);
        $y = random_bytes(32);
        $pk = new ECPublicKey("\x04$x$y");
        $debugInfo = $pk->__debugInfo();
        $this->assertArrayHasKey('x', $debugInfo);
        $this->assertSame('0x'.bin2hex($x), $debugInfo['x'], 'x-coordinate wrong');
        $this->assertSame('0x'.bin2hex($y), $debugInfo['y'], 'y-coordinate wrong');
    }
}
