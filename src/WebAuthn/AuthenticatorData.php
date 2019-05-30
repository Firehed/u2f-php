<?php
declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

use BadMethodCallException;
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
            // @codeCoverageIgnoreStart
            throw new BadMethodCallException('Not implemented yet');
            // @codeCoverageIgnoreEnd
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

    public function getRpIdHash(): string
    {
        return $this->rpIdHash;
    }

    public function __debugInfo(): array
    {
        $hex = function ($str) {
            return '0x' . bin2hex($str);
        };
        $data = [
            'isUserPresent' => $this->isUserPresent,
            'isUserVerified' => $this->isUserVerified,
            'rpIdHash' => $hex($this->rpIdHash),
            'signCount' => $this->signCount,
        ];

        if ($this->ACD) {
            // See RFC8152 section 7 (COSE key parameters
            $pk = [
                'kty' => $this->ACD['credentialPublicKey'][1], // MUST be 'EC2'; sec 13 tbl 21)
                // kid = 2
                'alg' => $this->ACD['credentialPublicKey'][3] ?? null,
                // key_ops = 4 // must include sign (1)/verify(2) if present, depending on usage
                // Base IV = 5

                // this would be 'k' if 'kty'===4(Symmetric)
                'crv' => $this->ACD['credentialPublicKey'][-1], // (13.1 tbl 22)
                'x' => $hex($this->ACD['credentialPublicKey'][-2] ?? ''), // (13.1.1 tbl 23/13.2 tbl 24)
                'y' => $hex($this->ACD['credentialPublicKey'][-3] ?? ''), // (13.1.1 tbl 23)
                'd' => $hex($this->ACD['credentialPublicKey'][-4] ?? ''), // (13.2 tbl 24)

            ];
            $acd = [
                'aaguid' => $hex($this->ACD['aaguid']),
                'credentialId' => $hex($this->ACD['credentialId']),
                'credentialPublicKey' => $pk,
            ];
            $data['ACD'] = $acd;
        }
        // Future?
        // $this->EXT
        return $data;
    }
}
