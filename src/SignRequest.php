<?php

namespace Firehed\U2F;

use JsonSerializable;

class SignRequest implements JsonSerializable, ChallengeProvider, KeyHandleInterface
{
    use AppIdTrait;
    use ChallengeTrait;
    use KeyHandleTrait;
    use VersionTrait;

    /**
     * @return array{
     *   version: string,
     *   challenge: string,
     *   keyHandle: string,
     *   appId: string,
     * }
     */
    public function jsonSerialize(): array
    {
        return [
            "version" => $this->version,
            "challenge" => $this->getChallenge(),
            "keyHandle" => $this->getKeyHandleWeb(),
            "appId" => $this->getAppId(),
        ];
    }
}
