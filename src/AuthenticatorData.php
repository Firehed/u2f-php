<?php
declare(strict_types=1);

namespace Firehed\U2F;

use Firehed\CBOR\Decoder;

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

    /** @var ?array Attested Credential Data */
    private $ACD;

    private $EXT;

    /**
     * @see https://w3c.github.io/webauthn/#sec-authenticator-data
     * WebAuthn 6.1
     */
    public static function parse(string $bytes): AuthenticatorData
    {
        assert(strlen($bytes) >= 37);

        $rpIdHash = substr($bytes, 0, 32);
        $flags = ord(substr($bytes, 32, 1));
        $UP = ($flags & 0x01) === 0x01; // bit 0
        $UV = ($flags & 0x04) === 0x04; // bit 2
        $AT = ($flags & 0x40) === 0x40; // bit 6
        $ED = ($flags & 0x80) === 0x80; // bit 7
        $signCount = unpack('N', substr($bytes, 33, 4))[1];

        $authData = new AuthenticatorData();
        $authData->isUserPresent = $UP;
        $authData->isUserVerified = $UV;
        $authData->rpIdHash = $rpIdHash;
        $authData->signCount = $signCount;

        $restOfBytes = substr($bytes, 37);
        $restOfBytesLength = strlen($restOfBytes);
        if ($AT) {
            assert($restOfBytesLength >= 18);

            $aaguid = substr($restOfBytes, 0, 16);
            $credentialIdLength = unpack('n', substr($restOfBytes, 16, 2))[1];
            assert($restOfBytesLength >= (18 + $credentialIdLength));
            $credentialId = substr($restOfBytes, 18, $credentialIdLength);

            $rawCredentialPublicKey = substr($restOfBytes, 18 + $credentialIdLength);

            $decoder = new Decoder();
            $credentialPublicKey = $decoder->decode($rawCredentialPublicKey);

            $authData->ACD = [
                'aaguid' => $aaguid,
                'credentialId' => $credentialId,
                'credentialPublicKey' => $credentialPublicKey,
            ];
            // var_dump($decoder->getNumberOfBytesRead());
            // cut rest of bytes down based on that ^ ?
        }
        if ($ED) {
            throw new BadMethodCallException('Not implemented yet');
        }

        return $authData;
    }

    public function isUserPresent(): bool
    {
        return $this->isUserPresent;
    }

    public function getAttestedCredentialData(): ?array
    {
        return $this->ACD;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function __debugInfo(): array
    {
        $hex = function ($str) {
            return '0x' . bin2hex($str);
        };
        return [
            'isUserPresent' => $this->isUserPresent,
            'isUserVerified' => $this->isUserVerified,
            'rpIdHash' => $hex($this->rpIdHash),
            'signCount' => $this->signCount,
            'ACD' => $this->ACD ? [
                'aaguid' => $hex($this->ACD['aaguid']),
                'credentialId' => $hex($this->ACD['credentialId']),
                'credentialPublicKey' => $this->ACD['credentialPublicKey'],
            ] : null,
            'EXT' => $this->EXT,
        ];
    }
}
