<?php
declare(strict_types=1);

namespace Firehed\U2F;

use OutOfBoundsException;

class Registration implements RegistrationInterface, WebAuthn\CredentialInterface
{
    use KeyHandleTrait;

    /** @var AttestationCertificateInterface */
    private $cert;

    /** @var int */
    private $counter = -1;

    /** @var PublicKeyInterface */
    private $publicKey;

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
        return $this->publicKey;
    }

    public function setPublicKey(PublicKeyInterface $publicKey): self
    {
        $this->publicKey = $publicKey;
        return $this;
    }

    // -( CredentialInterface )-
    public function getId(): string
    {
        return $this->getKeyHandleBinary();
    }
    public function getPublicKeyPem(): string
    {
        return $this->getPublicKey()->getPemFormatted();
    }
    public function getSignatureCounter(): int
    {
        return $this->getCounter();
    }

    /**
     * @return array{
     *   cert: AttestationCertificateInterface,
     *   counter: int,
     *   publicKey: PublicKeyInterface,
     *   keyHandle: string,
     * }
     */
    public function __debugInfo(): array
    {
        $hex = function (string $binary): string {
            return '0x' . bin2hex($binary);
        };

        return [
            'cert' => $this->cert,
            'counter' => $this->counter,
            'publicKey' => $this->publicKey,
            'keyHandle' => $hex($this->keyHandle),
        ];
    }
}
