<?php

declare(strict_types=1);

namespace Firehed\U2F;

/**
 * A U2F registration.
 */
interface RegistrationInterface
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
     * @return string The decoded key handle of the U2F registration.
     */
    public function getKeyHandleBinary(): string;

    /**
     * @return PublicKeyInterface The public key of the registration.
     */
    public function getPublicKey(): PublicKeyInterface;
}
