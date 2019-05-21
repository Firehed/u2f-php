<?php

namespace Firehed\U2F;

trait KeyHandleTrait
{
    /** @var striing */
    private $keyHandle;

    // Binary string of key handle
    public function getKeyHandleBinary(): string
    {
        $decoded = base64_decode($this->keyHandle);
        assert($decoded !== false);
        return $decoded;
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
        $this->keyHandle = base64_encode($keyHandle);
        return $this;
    }
}
