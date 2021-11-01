<?php

namespace Firehed\U2F;

use JsonSerializable;

/**
 * @deprecated
 */
class RegisterRequest implements JsonSerializable, ChallengeProvider
{
    use AppIdTrait;
    use ChallengeTrait;
    use VersionTrait;

    /**
     * @return array{
     *   version: string,
     *   challenge: string,
     *   appId: string,
     * }
     */
    public function jsonSerialize(): array
    {
        return [
            "version" => $this->version,
            "challenge" => $this->getChallenge(),
            "appId" => $this->getAppId(),
        ];
    }
}
