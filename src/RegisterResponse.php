<?php
declare(strict_types=1);

namespace Firehed\U2F;
use Firehed\U2F\InvalidDataException as IDE;

class RegisterResponse
{
    use AttestationCertificateTrait;
    use ECPublicKeyTrait;
    use ResponseTrait;

    protected function parseResponse(array $response): self {
        $this->validateKeyInArray('registrationData', $response);
        // Binary string as defined by
        // U2F 1.0 Raw Message Format Sec. 4.3
        // https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#registration-response-message-success
        $regData = fromBase64Web($response['registrationData']);

        // Basic fixed length check
        if (strlen($regData) < 67) {
            throw new IDE(IDE::MALFORMED_DATA,
                'registrationData is missing information');
        }

        $offset = 0; // Number of bytes read so far (think fread/fseek)

        $reserved = ord($regData[$offset]);
        if ($reserved !== 5) {
            throw new IDE(IDE::MALFORMED_DATA,
                'reserved byte');
        }
        $offset += 1;

        $this->setPublicKey(substr($regData, $offset, 65));
        $offset += 65;

        $keyHandleLength = ord($regData[$offset]);
        $offset += 1;

        // Dynamic length check through key handle
        if (strlen($regData) < $offset+$keyHandleLength) {
            throw new IDE(IDE::MALFORMED_DATA,
                'key handle length');
        }
        $this->setKeyHandle(substr($regData, $offset, $keyHandleLength));
        $offset += $keyHandleLength;

        // (Notes are 0-indexed)
        // If byte 0 & 0x1F = 0x10, it's a sequence where the next byte
        // determines length (if not, this is not the start of a certificate)
        //
        // If the length byte (byte 1) & 0x80 = 0x80, then the following
        // (byte 1 ^ 0x80) bytes are the remaining length of the sequence. If
        // not, then the legnth byte alone is correct. I.e. > 128 low 7 bits
        // are the byte count for length; <=127 then it is the length.
        //
        // https://msdn.microsoft.com/en-us/library/bb648645(v=vs.85).aspx
        $remain = substr($regData, $offset);
        $b0 = ord($remain[0]);
        if (($b0 & 0x1F) != 0x10) {
            throw new IDE(IDE::MALFORMED_DATA,
                'starting byte of attestation certificate');
        }
        $length = ord($remain[1]);
        if (($length & 0x80) == 0x80) {
            $needed = $length ^ 0x80;
            if ($needed > 4) {
                // This would be a >4GB cert, reject it out of hand
                throw new IDE(IDE::MALFORMED_DATA,
                    'certificate length');
            }
            $bytes = 0;
            // Start 2 bytes in, for SEQUENCE and its LENGTH
            for ($i = 2; $i < $needed+2; $i++) {
                $bytes <<= 8; // shift running total left 8 bytes
                $byte = ord($remain[$i]); // grab next byte
                $bytes |= $byte; // OR in that byte
            }
            $length = $bytes + $needed + 2;
        }
        // Sanity check the length against the remainder of the registration
        // data, in case a malformed cert was provided to trigger an overflow
        // during parsing
        if ($length + $offset > strlen($regData)) {
            throw new IDE(IDE::MALFORMED_DATA,
                'certificate and sigature length');
        }
        $this->setAttestationCertificate(substr($regData, $offset, $length));
        $offset += $length;

        // All remaining data is the signature
        $this->setSignature(substr($regData, $offset));

        return $this;
    }

}
