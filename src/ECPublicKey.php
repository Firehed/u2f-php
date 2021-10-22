<?php
declare(strict_types=1);

namespace Firehed\U2F;

class ECPublicKey implements PublicKeyInterface
{
    /** @var string (binary) */
    private $binary = '';

    public function __construct(string $key)
    {
        // RFC5480 2.2 - must be uncompressed value
        if ($key[0] !== "\x04") {
            throw new InvalidDataException(
                InvalidDataException::MALFORMED_DATA,
                'public key: first byte not x04 (uncompressed)'
            );
        }
        if (strlen($key) !== 65) {
            throw new InvalidDataException(
                InvalidDataException::PUBLIC_KEY_LENGTH,
                '65'
            );
        }
        $this->binary = $key;
    }

    /**
     * @return string The decoded public key.
     */
    public function getBinary(): string
    {
        return $this->binary;
    }

    // Prepends the pubkey format headers and builds a pem file from the raw
    // public key component
    public function getPemFormatted(): string
    {
        // Described in RFC 5480
        // Just use an OID calculator to figure out *that* encoding
        $der = hex2bin(
            '3059' // SEQUENCE, length 89
                .'3013' // SEQUENCE, length 19
                    .'0607' // OID, length 7
                        .'2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
                    .'0608' // OID, length 8
                        .'2a8648ce3d030107' // 1.2.840.10045.3.1.7 = P-256 Curve
                .'0342' // BIT STRING, length 66
                    .'00' // prepend with NUL - pubkey will follow
        );
        $der .= $this->binary;

        $pem  = "-----BEGIN PUBLIC KEY-----\r\n";
        $pem .= chunk_split(base64_encode($der), 64);
        $pem .= "-----END PUBLIC KEY-----";
        return $pem;
    }

    /** @return array{x: string, y: string} */
    public function __debugInfo(): array
    {
        return [
            'x' => '0x' . bin2hex(substr($this->binary, 1, 32)),
            'y' => '0x' . bin2hex(substr($this->binary, 33)),
        ];
    }
}
