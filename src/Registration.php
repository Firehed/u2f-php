<?php
declare(strict_types=1);

namespace Firehed\U2F;
use OutOfBoundsException;

class Registration
{
    use AttestationCertificateTrait;
    use KeyHandleTrait;

    private $counter = -1;
    private $pubKey = '';

    public function getPublicKey(): string {
        return base64_decode($this->pubKey);
    }
    public function setPublicKey(string $pubKey): self {
        $this->pubKey = base64_encode($pubKey);
        return $this;
    }

    public function getCounter(): int {
        return $this->counter;
    }
    public function setCounter(int $counter): self {
        if ($counter < 0) {
            throw new OutOfBoundsException('Counter may not be negative');
        }
        $this->counter = $counter;
        return $this;
    }

}
