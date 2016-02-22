<?php

namespace Firehed\U2F;

use JsonSerializable;

class RegisterRequest implements JsonSerializable, ChallengeProvider
{
    use AppIdTrait;
    use ChallengeTrait;
    use VersionTrait;

    public function jsonSerialize() {
        return [
            "version" => $this->version,
            "challenge" => $this->getChallenge(),
            "appId" => $this->getAppId(),
        ];
    }
}
