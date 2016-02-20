<?php
declare(strict_types=1);

namespace Firehed\U2F;

trait VersionTrait
{
    private $version = 'U2F_V2';

    public function getVersion(): string {
        return $this->version;
    }
}
