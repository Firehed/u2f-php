<?php
declare(strict_types=1);

namespace Firehed\U2F;

interface RegistrationResponseInterface
{
    public function getAttestationCertificate(): AttestationCertificate;

    public function getChallengeProvider(): ChallengeProvider;

    public function getKeyHandleBinary(): string;

    public function getPublicKeyBinary(): string;

    public function getRpIdHash(): string;

    public function getSignature(): string;

    public function getSignedData(): string;
}
