<?php
declare(strict_types=1);

namespace Firehed\U2F;

class AuthenticatorData
{
    /** @var bool */
    private $isUserPresent;

    /** @var bool */
    private $isUserVerified;

    /** @var string (binary) */
    private $rpIdHash;

    /** @var int */
    private $signCount;

    private $ACD;
    private $EXT;

    /**
     * @see https://w3c.github.io/webauthn/#sec-authenticator-data
     * WebAuthn 6.1
     */
    public static function parse(string $bytes): AuthenticatorData
    {
        assert(strlen($bytes) >= 37);

        $rpidHash = substr($bytes, 0, 32);
        log(bin2hex($rpidHash), 'rpid hash');
        $flags = ord(substr($bytes, 32, 1));
        $UP = ($flags & 0x01) === 0x01; // bit 0
        $UV = ($flags & 0x04) === 0x04; // bit 2
        $AT = ($flags & 0x40) === 0x40; // bit 6
        $ED = ($flags & 0x80) === 0x80; // bit 7
        $signCount = unpack('N', substr($bytes, 33, 4))[1];

        $authData = new AuthenticatorData();
        $authData->isUserPresent = $UP;
        $authData->isUserVerified = $UV;
        $authData->signCount = $signCount;
        return $authData;
    }

    public function isUserPresent(): bool
    {
        return $this->isUserPresent;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }
}
