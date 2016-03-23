<?php
declare(strict_types=1);

namespace Firehed\U2F;

trait AttestationCertificateTrait
{

    // Stored base64-encoded
    private $attest = '';

    // Binary string of attestation certificate (from device issuer)
    public function getAttestationCertificateBinary(): string {
        return base64_decode($this->attest);
    }

    // PEM formatted cert
    public function getAttestationCertificatePem(): string {
        $pem  = "-----BEGIN CERTIFICATE-----\r\n";
        $pem .= chunk_split($this->attest, 64);
        $pem .= "-----END CERTIFICATE-----";
        return $pem;
    }

    public function setAttestationCertificate(string $cert): self {
        // In the future, this may make assertions about the cert formatting;
        // right now, we're going to leave it be.
        $this->attest = base64_encode($cert);
        return $this;
    }

    public function verifyIssuerAgainstTrustedCAs(array $trusted_cas): bool {
        $result = openssl_x509_checkpurpose(
            $this->getAttestationCertificatePem(),
            \X509_PURPOSE_ANY,
            $trusted_cas);
        if ($result !== true) {
            throw new SecurityException(SecurityException::NO_TRUSTED_CA);
        }
        return $result;
    }

}
