<?php

declare(strict_types=1);

namespace Firehed\U2F;

interface KeyHandleInterface
{
    /**
     * @return string The decoded key handle of the U2F registration.
     */
    public function getKeyHandleBinary(): string;
}
