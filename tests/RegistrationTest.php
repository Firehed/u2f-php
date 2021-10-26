<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\Registration
 */
class RegistrationTest extends \PHPUnit\Framework\TestCase
{

    public function testCounter(): void
    {
        $obj = new Registration();
        $this->assertSame(
            $obj,
            $obj->setCounter(1833),
            'setCounter should return $this'
        );
        $this->assertSame(
            1833,
            $obj->getCounter(),
            'getCounter should return the set value'
        );
    }

    public function testSetCounterRejectsNegativeNumbers(): void
    {
        $obj = new Registration();
        $this->expectException(\OutOfBoundsException::class);
        $obj->setCounter(-1);
    }

    public function testPublicKey(): void
    {
        $pk = $this->createMock(PublicKeyInterface::class);
        $reg = new Registration();
        $reg->setPublicKey($pk);
        $this->assertSame($pk, $reg->getPublicKey());
    }

    public function testAttestationCertificate(): void
    {
        $pk = $this->createMock(AttestationCertificateInterface::class);
        $reg = new Registration();
        $reg->setAttestationCertificate($pk);
        $this->assertSame($pk, $reg->getAttestationCertificate());
    }

    public function testDebugInfoEncodesBinary(): void
    {
        $reg = new Registration();
        $reg->setAttestationCertificate($this->createMock(AttestationCertificateInterface::class));
        $reg->setPublicKey($this->createMock(PublicKeyInterface::class));
        $kh = random_bytes(20);
        $reg->setKeyHandle($kh);
        $reg->setCounter(50);

        $debugInfo = $reg->__debugInfo();
        $this->assertNotSame($kh, $debugInfo['keyHandle']);
        $this->assertRegExp('/^0x[0-9a-f]{40}$/', $debugInfo['keyHandle']);
    }
}
