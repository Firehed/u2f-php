<?php
declare(strict_types=1);

namespace Firehed\U2F;
use OutOfBoundsException;

class Registration
{
    use AttestationCertificateTrait;
    use ECPublicKeyTrait;
    use KeyHandleTrait;

    private $counter = -1;

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
