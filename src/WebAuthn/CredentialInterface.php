<?php

declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

/**
 * @internal Well, sorta. The serialization components will be public for
 * storage reasons.
 */
interface CredentialInterface
{
    public function getId(): string;
    /** Return the associated PK in PEM format */
    public function getPublicKeyPem(): string;
    public function getSignatureCounter(): int;
}
