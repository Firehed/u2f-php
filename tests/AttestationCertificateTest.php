<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\AttestationCertificate
 * @covers ::<protected>
 * @covers ::<private>
 */
class AttestationCertificateTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @covers ::getBinary
     */
    public function testGetBinary()
    {
        $raw = random_bytes(128);
        $cert = new AttestationCertificate($raw);
        $this->assertSame(
            $raw,
            $cert->getBinary(),
            'getBinary should return the untouched raw data'
        );
    }

    /**
     * @covers ::getPemFormatted
     */
    public function testGetPemFormatted()
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
}
