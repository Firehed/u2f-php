<?php

declare(strict_types=1);

namespace Firehed\U2F;

use JsonSerializable;

class Challenge implements ChallengeProviderInterface, JsonSerializable
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

    public function jsonSerialize(): string
    {
        return $this->challenge;
    }
}
