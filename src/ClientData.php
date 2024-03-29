<?php
declare(strict_types=1);

namespace Firehed\U2F;

use Firehed\U2F\InvalidDataException as IDE;

class ClientData
{
    use ChallengeTrait;

    /** @var string */
    private $originalJson;

    /** @var string */
    private $cid_pubkey;

    /** @var string */
    private $origin;

    /** @var string */
    private $typ;

    public static function fromJson(string $json): ClientData
    {
        $data = json_decode($json, true);
        if (json_last_error() !== \JSON_ERROR_NONE) {
            throw new IDE(IDE::MALFORMED_DATA, 'json');
        }
        $ret = new self;
        $ret->setType($ret->validateKey('typ', $data));
        $ret->setChallenge($ret->validateKey('challenge', $data));
        $ret->origin = $ret->validateKey('origin', $data);
        // This field is optional
        if (isset($data['cid_pubkey'])) {
            $ret->cid_pubkey = $data['cid_pubkey'];
        }
        $ret->originalJson = $json;
        return $ret;
    }

    public function getApplicationParameter(): string
    {
        return hash('sha256', $this->origin, true);
    }

    /**
     * Checks the 'typ' field against the allowed types in the U2F spec (sec.
     * 7.1)
     * @param string $type the 'typ' value
     * @return $this
     * @throws InvalidDataException if a non-conforming value is provided
     */
    private function setType(string $type): self
    {
        switch ($type) {
            case 'navigator.id.getAssertion': // fall through
            case 'navigator.id.finishEnrollment':
                break;
            default:
                throw new IDE(IDE::MALFORMED_DATA, 'typ');
        }
        $this->typ = $type;
        return $this;
    }

    /**
     * Checks for the presence of $key in $data. Returns the value if found,
     * throws an InvalidDataException if missing
     * @param string $key The array key to check
     * @param array<string, string> $data The array to check in
     * @return string The data, if present
     * @throws InvalidDataException if not prsent
     */
    private function validateKey(string $key, array $data): string
    {
        if (!array_key_exists($key, $data)) {
            throw new IDE(IDE::MISSING_KEY, $key);
        }
        return $data[$key];
    }

    // Returns the SHA256 hash of this object per the raw message formats spec
    public function getChallengeParameter(): string
    {
        return hash('sha256', $this->originalJson, true);
    }
}
