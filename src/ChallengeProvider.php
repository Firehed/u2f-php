<?php
declare(strict_types=1);

namespace Firehed\U2F;

interface ChallengeProvider
{

    public function getChallenge(): string;

}
