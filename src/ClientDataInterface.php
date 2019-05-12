<?php
declare(strict_types=1);

namespace Firehed\U2F;

use JsonSerializable;

interface ClientDataInterface extends JsonSerializable, ChallengeProvider
{
    public function getApplicationParameter(): string;

    public function getChallengeParameter(): string;
}
