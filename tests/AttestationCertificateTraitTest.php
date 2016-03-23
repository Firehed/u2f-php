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

    /**
     * @covers ::verifyIssuerAgainstTrustedCAs
     */
    public function testSuccessfulCAVerification() {
        $class = $this->getObjectWithYubicoCert();
        $certs = [dirname(__DIR__).'/CAcerts/yubico.pem'];
        $this->assertTrue($class->verifyIssuerAgainstTrustedCAs($certs));
    }

    /**
     * @covers ::verifyIssuerAgainstTrustedCAs
     */
    public function testFailedCAVerification() {
        $class = $this->getObjectWithYubicoCert();
        $certs = [__DIR__.'/verisign_only_for_unit_tests.pem'];
        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::NO_TRUSTED_CA);
        $class->verifyIssuerAgainstTrustedCAs($certs);
    }

    /**
     * @covers ::verifyIssuerAgainstTrustedCAs
     */
    public function testFailedCAVerificationFromNoCAs() {
        $class = $this->getObjectWithYubicoCert();
        $certs = [];
        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::NO_TRUSTED_CA);
        $class->verifyIssuerAgainstTrustedCAs($certs);
    }

    // -(Helper methods)-------------------------------------------------------

    /**
     * Returns some concrete implementation of a class using
     * AttestationCertificateTrait
     *
     * @return mixed Some class using AttestationCertificateTrait
     */
    private function getObjectWithYubicoCert() {
        $response = RegisterResponse::fromJson(
            file_get_contents(__DIR__.'/register_response.json'));
        // Sanity check that the response actually imlements this trait, rather
        // than doing all sorts of magic
        $check = AttestationCertificateTrait::class;
        $this->assertContains($check, class_uses($response));
        return $response;
    }
}
