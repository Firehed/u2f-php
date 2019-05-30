<?php
declare(strict_types=1);

namespace Firehed\U2F;

class AttestationCertificate implements AttestationCertificateInterface
{
    /** @var string (binary) */
    private $binary;

    public function __construct(string $binary)
    {
        $this->binary = $binary;
    }

    public function getBinary(): string
    {
        return $this->binary;
    }

    public function getPemFormatted(): string
    {
        $data = base64_encode($this->binary);
        $pem  = "-----BEGIN CERTIFICATE-----\r\n";
        $pem .= chunk_split($data, 64);
        $pem .= "-----END CERTIFICATE-----";
        return $pem;
    }

    public function __debugInfo(): array
    {
        return ['binary' => '0x' . bin2hex($this->binary)];
    }
}
