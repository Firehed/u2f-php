<?php

namespace Firehed\U2F;

trait ChallengeTrait
{
    private $challenge;

    // B64-websafe value (at no point is the binary version used)
    public function getChallenge(): string {
        return ($this->challenge);
    }

    public function setChallenge(string $challenge): self {
        // TODO: make immutable
        $this->challenge = $challenge;
        return $this;
    }
}
