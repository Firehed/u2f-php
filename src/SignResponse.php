<?php
declare(strict_types=1);

namespace Firehed\U2F;

use Firehed\U2F\InvalidDataException as IDE;

class SignResponse
{
    use ResponseTrait;

    // Decoded SignatureData
    private $counter = -1;
    private $user_presence = 0;

    public function getCounter(): int {
        return $this->counter;
    }
    public function getUserPresenceByte(): int {
        return $this->user_presence;
    }

    protected function parseResponse(array $response): self {
        $this->validateKeyInArray('keyHandle', $response);
        $this->setKeyHandle(fromBase64Web($response['keyHandle']));

        $this->validateKeyInArray('signatureData', $response);
        // Binary string as defined by
        // U2F 1.0 Raw Message Format Sec. 5.4
        // https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#authentication-response-message-success
        $sig_raw = fromBase64Web($response['signatureData']);

        if (strlen($sig_raw) < 6) {
            throw new IDE(IDE::MALFORMED_DATA, 'signatureData');
        }
        $decoded = unpack('cpresence/Ncounter/a*signature', $sig_raw);
        $this->user_presence = $decoded['presence'];
        $this->counter = $decoded['counter'];
        $this->setSignature($decoded['signature']);
        return $this;
    }

}
