<?php

declare(strict_types=1);

namespace Firehed\U2F;

/**
 * A U2F registration.
 */
interface RegistrationInterface extends KeyHandleInterface
{
    /**
     * @return AttestationCertificateInterface The decoded attestation of the U2F token.
     */
    public function getAttestationCertificate(): AttestationCertificateInterface;

    /**
     * @return int The counter of the U2F registration.
     */
    public function getCounter(): int;

    /**
     * @return PublicKeyInterface The public key of the registration.
     */
    public function getPublicKey(): PublicKeyInterface;
}
