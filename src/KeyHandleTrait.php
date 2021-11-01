<?php

namespace Firehed\U2F;

/**
 * @internal
 */
trait KeyHandleTrait
{
    /** @var string (binary) */
    private $keyHandle;

    // Binary string of key handle
    public function getKeyHandleBinary(): string
    {
        return $this->keyHandle;
    }
    // B64-websafe value
    public function getKeyHandleWeb(): string
    {
        return toBase64Web($this->getKeyHandleBinary());
    }
    // Binary value
    public function setKeyHandle(string $keyHandle): self
    {
        // TODO: make immutable
        $this->keyHandle = $keyHandle;
        return $this;
    }
}
