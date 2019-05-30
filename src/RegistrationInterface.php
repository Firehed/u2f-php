<?php

declare(strict_types=1);

namespace Firehed\U2F;

/**
 * A U2F registration.
 */
interface RegistrationInterface
{
    /**
     * @return AttestationCertificate The decoded attestation of the U2F token.
     */
    public function getAttestationCertificate(): AttestationCertificate;

    /**
     * @return int The counter of the U2F registration.
     */
    public function getCounter(): int;

    /**
     * @return string The decoded key handle of the U2F registration.
     */
    public function getKeyHandleBinary(): string;

    /**
     * @return string The decoded public key of the U2F
     * registration.
     */
    public function getPublicKeyBinary(): string;
}
