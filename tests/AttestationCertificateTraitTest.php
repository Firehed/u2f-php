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
     * @covers ::getAttestationCertificate
     * @covers ::setAttestationCertificate
     */
    public function testAccessors() {
        $obj = new class {
            use AttestationCertificateTrait;
        };
        $cert = bin2hex(random_bytes(35));
        $this->assertSame($obj, $obj->setAttestationCertificate($cert),
            'setAttestationCertificate should return $this');
        $this->assertSame($cert, $obj->getAttestationCertificate(),
            'getAttestationCertificate should return the challenge that was set');
    }

}
