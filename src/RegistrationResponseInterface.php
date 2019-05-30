<?php
declare(strict_types=1);

namespace Firehed\U2F;

interface RegistrationResponseInterface
{
    public function getAttestationCertificate(): AttestationCertificateInterface;

    public function getChallengeProvider(): ChallengeProvider;

    public function getKeyHandleBinary(): string;

    public function getPublicKey(): PublicKeyInterface;

    public function getRpIdHash(): string;

    public function getSignature(): string;

    public function getSignedData(): string;
}
