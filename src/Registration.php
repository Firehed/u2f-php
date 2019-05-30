<?php
declare(strict_types=1);

namespace Firehed\U2F;

use OutOfBoundsException;

class Registration implements RegistrationInterface
{
    use ECPublicKeyTrait;
    use KeyHandleTrait;

    /** @var AttestationCertificate */
    private $cert;

    /** @var int */
    private $counter = -1;

    public function getAttestationCertificate(): AttestationCertificate
    {
        return $this->cert;
    }

    public function getCounter(): int
    {
        return $this->counter;
    }

    public function setAttestationCertificate(AttestationCertificate $cert): self
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
}
