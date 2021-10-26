<?php

declare(strict_types=1);

namespace Firehed\U2F;

class Challenge implements ChallengeProviderInterface
{
    /** @var string */
    private $challenge;

    public function __construct(string $challenge)
    {
        $this->challenge = $challenge;
    }

    public function getChallenge(): string
    {
        return $this->challenge;
    }
}
