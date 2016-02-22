<?php
declare(strict_types=1);

namespace Firehed\U2F;

trait AttestationCertificateTrait
{

    // Stored base64-encoded
    private $attest = '';

    // Binary string of attestation certificate (from device issuer)
    public function getAttestationCertificate(): string {
        return base64_decode($this->attest);
    }

    public function setAttestationCertificate(string $cert): self {
        // In the future, this may make assertions about the cert formatting;
        // right now, we're going to leave it be.
        $this->attest = base64_encode($cert);
        return $this;
    }

}
