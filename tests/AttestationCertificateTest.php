<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\AttestationCertificate
 */
class AttestationCertificateTest extends \PHPUnit\Framework\TestCase
{
    public function testConstruct(): void
    {
        // Note: a future, stricter implementation which actually parses and
        // examines the ASN.1 format should fail on this. For now it's just
        // a simple bag of bytes.
        $raw = random_bytes(128);
        $cert = new AttestationCertificate($raw);
        $this->assertInstanceOf(AttestationCertificateInterface::class, $cert);
    }

    public function testGetBinary(): void
    {
        $raw = random_bytes(128);
        $cert = new AttestationCertificate($raw);
        $this->assertSame(
            $raw,
            $cert->getBinary(),
            'getBinary should return the untouched raw data'
        );
    }

    public function testGetPemFormatted(): void
    {
        $raw = random_bytes(128);
        $cert = new AttestationCertificate($raw);
        $expected  = "-----BEGIN CERTIFICATE-----\r\n";
        $expected .= chunk_split(base64_encode($raw), 64);
        $expected .= "-----END CERTIFICATE-----";
        $this->assertSame(
            $expected,
            $cert->getPemFormatted(),
            'PEM-formatted certificate was incorrect'
        );
    }

    public function testDebugInfoEncodesBinary(): void
    {
        $cert = new AttestationCertificate(random_bytes(128));
        $debugInfo = $cert->__debugInfo();
        $this->assertArrayHasKey('binary', $debugInfo);
        $this->assertRegExp('/^0x[0-9a-f]{256}$/', $debugInfo['binary']);
    }
}
