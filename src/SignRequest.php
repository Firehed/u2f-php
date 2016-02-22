<?php

namespace Firehed\U2F;

use JsonSerializable;

class SignRequest implements JsonSerializable, ChallengeProvider
{
    use AppIdTrait;
    use ChallengeTrait;
    use KeyHandleTrait;
    use VersionTrait;

    public function jsonSerialize() {
        return [
            "version" => $this->version,
            "challenge" => $this->getChallenge(),
            "keyHandle" => $this->getKeyHandleWeb(),
            "appId" => $this->getAppId(),
        ];
    }

}
