<?php
declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

use BadMethodCallException;
use Firehed\CBOR\Decoder;

/**
 * @internal
 *
 * @phpstan-type AttestedCredentialData array{
 *   aaguid: string,
 *   credentialId: string,
 *   credentialPublicKey: array{
 *     1: int,
 *     3?: int,
 *     -1: int,
 *     -2?: string,
 *     -3?: string,
 *     -4?: string,
 *   }
 * }
 */
class AuthenticatorData
{
    /** @var string */
    private $raw;

    /** @var bool */
    private $isUserPresent;

    /** @var bool */
    private $isUserVerified;

    /** @var string (binary) */
    private $rpIdHash;

    /** @var int */
    private $signCount;

    /**
     * @var ?AttestedCredentialData Attested Credential Data
     */
    private $ACD;

    /** @var null RESERVED: WebAuthn Extensions */
    private $extensions;

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
        $authData->raw = $bytes;
        $authData->isUserPresent = $UP;
        $authData->isUserVerified = $UV;
        $authData->rpIdHash = $rpIdHash;
        $authData->signCount = $signCount;

        $restOfBytes = substr($bytes, 37);
        $restOfBytesLength = strlen($restOfBytes);
        // 6.5.1 Attested Credential Data
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

    /** @return ?AttestedCredentialData */
    public function getAttestedCredentialData(): ?array
    {
        return $this->ACD;
    }

    public function getRawBytes(): string
    {
        return $this->raw;
    }

    public function getRpIdHash(): string
    {
        return $this->rpIdHash;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function isUserPresent(): bool
    {
        return $this->isUserPresent;
    }

    public function isUserVerified(): bool
    {
        return $this->isUserVerified;
    }

    /**
     * @return array{
     *   isUserPresent: bool,
     *   isUserVerified: bool,
     *   rpIdHash: string,
     *   signCount: int,
     *   ACD?: array{
     *     aaguid: string,
     *     credentialId: string,
     *     credentialPublicKey: array{
     *       kty: int,
     *       alg: ?int,
     *       crv: int,
     *       x: string,
     *       y: string,
     *       d: string,
     *     },
     *   },
     * }
     */
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
            // See RFC8152 section 7 (COSE key parameters)
            $pk = [
                'kty' => $this->ACD['credentialPublicKey'][1], // MUST be 'EC2' (sec 13 tbl 21)
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
        return $data;
    }

    // https://www.iana.org/assignments/cose/cose.xhtml

    // COSE_Key format constants from RFC8152
    const COSE_KEY_KTY = 1;
    // OPENSSL_KEYTYPE_RSA = 0
    // OPENSSL_KEYTYPE_DSA = 1
    const KEY_TYPE_EC2 = 2; // OPENSSL_KEYTYPE_DH
    const KEY_TYPE_RSA = 3; // OPENSSL_KEYTYPE_EC

    // https://www.w3.org/TR/webauthn-2/#typedefdef-cosealgorithmidentifier
    // (5.8.5)
    const COSE_KEY_ALG = 3;
    const ALG_ES256 = -7;
    // es384=-35
    // es512=-36
    const ALG_PS256 = -37;
    const ALG_RS256 = -257;

    // These are specific to EC2/ES256
    const COSE_KEY_CRV = -1;
    const CURVE_P256 = 1; // RFC8152 s13.1 tbl 22
    // p384=2
    // p521=3
    // Ed25519=6
    //
    const COSE_KEY_X_COORDINATE = -2;
    const COSE_KEY_Y_COORDINATE = -3;
}
