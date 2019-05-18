<?php
declare(strict_types=1);

namespace Firehed\U2F;

interface LoginResponseInterface
{
    public function getChallengeProvider(): ChallengeProvider;

    public function getCounter(): int;

    public function getKeyHandleBinary(): string;

    public function getSignature(): string;

    public function getSignedData(): string;
}
