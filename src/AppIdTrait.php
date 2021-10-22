<?php
declare(strict_types=1);

namespace Firehed\U2F;

trait AppIdTrait
{
    /** @var string */
    private $appId;

    public function getAppId(): string
    {
        return $this->appId;
    }

    public function setAppId(string $appId): self
    {
        $this->appId = $appId;
        return $this;
    }

    /**
     * @return string The raw SHA-256 hash of the App ID
     */
    public function getApplicationParameter(): string
    {
        return hash('sha256', $this->appId, true);
    }

    /**
     * @return string The raw SHA-256 hash of the Relying Party ID
     */
    public function getRpIdHash(): string
    {
        return hash('sha256', $this->appId, true);
    }
}
