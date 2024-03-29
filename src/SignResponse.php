<?php
declare(strict_types=1);

namespace Firehed\U2F;

use Firehed\U2F\InvalidDataException as IDE;

class SignResponse implements LoginResponseInterface
{
    use ResponseTrait;

    // Decoded SignatureData
    /** @var int */
    private $counter = -1;

    /** @var int */
    private $user_presence = 0;

    public function getCounter(): int
    {
        return $this->counter;
    }

    public function getUserPresenceByte(): int
    {
        return $this->user_presence;
    }

    public function getSignedData(): string
    {
        // U2F Spec:
        // https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#authentication-response-message-success
        return sprintf(
            '%s%s%s%s',
            $this->clientData->getApplicationParameter(),
            chr($this->getUserPresenceByte()),
            pack('N', $this->getCounter()),
            // Note: Spec says this should be from the request, but that's not
            // actually available via the JS API. Because we assert the
            // challenge *value* from the Client Data matches the trusted one
            // from the SignRequest and that value is included in the Challenge
            // Parameter, this is safe unless/until SHA-256 is broken.
            $this->clientData->getChallengeParameter()
        );
    }

    /**
     * @param array{
     *   keyHandle: string,
     *   clientData: string,
     *   signatureData: string,
     * } $response
     */
    protected function parseResponse(array $response): self
    {
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
        assert($decoded !== false);
        $this->user_presence = $decoded['presence'];
        $this->counter = $decoded['counter'];
        $this->setSignature($decoded['signature']);
        return $this;
    }

    public function getChallenge(): string
    {
        return $this->clientData->getChallenge();
    }
}
