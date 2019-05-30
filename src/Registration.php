<?php
declare(strict_types=1);

namespace Firehed\U2F;

use OutOfBoundsException;

class Registration implements RegistrationInterface
{
    use KeyHandleTrait;

    /** @var AttestationCertificateInterface */
    private $cert;

    /** @var int */
    private $counter = -1;

    /** @var PublicKeyInterface */
    private $pubKey;

    public function getAttestationCertificate(): AttestationCertificateInterface
    {
        return $this->cert;
    }

    public function getCounter(): int
    {
        return $this->counter;
    }

    public function setAttestationCertificate(AttestationCertificateInterface $cert): self
    {
        $this->cert = $cert;
        return $this;
    }

    public function setCounter(int $counter): self
    {
        if ($counter < 0) {
            throw new OutOfBoundsException('Counter may not be negative');
        }
        $this->counter = $counter;
        return $this;
    }

    public function getPublicKey(): PublicKeyInterface
    {
        return $this->pubKey;
    }

    public function setPublicKey(PublicKeyInterface $pubKey): self
    {
        $this->pubKey = $pubKey;
        return $this;
    }
}
