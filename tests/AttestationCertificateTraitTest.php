<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\AttestationCertificateTrait
 * @covers ::<protected>
 * @covers ::<private>
 */
class AttestationCertificateTraitTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @covers ::getAttestationCertificateBinary
     * @covers ::setAttestationCertificate
     */
    public function testAccessors() {
        $obj = new class {
            use AttestationCertificateTrait;
        };
        $cert = bin2hex(random_bytes(35));
        $this->assertSame($obj, $obj->setAttestationCertificate($cert),
            'setAttestationCertificate should return $this');
        $this->assertSame($cert, $obj->getAttestationCertificateBinary(),
            'getAttestationCertificate should return the challenge that was set');
    }

    /**
     * @covers ::getAttestationCertificatePem
     */
    public function testGetAttestationCertificatePem() {
        $obj = new class {
            use AttestationCertificateTrait;
        };
        $raw = random_bytes(128);
        $expected  = "-----BEGIN CERTIFICATE-----\r\n";
        $expected .= chunk_split(base64_encode($raw), 64);
        $expected .= "-----END CERTIFICATE-----";
        $obj->setAttestationCertificate($raw);
        $this->assertSame($expected, $obj->getAttestationCertificatePem(),
            'PEM-formatted certificate was incorrect');
    }
}
