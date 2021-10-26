<?php

declare(strict_types=1);

namespace Firehed\U2F;

interface ChallengeProviderInterface
{
    public function getChallenge(): string;
}
