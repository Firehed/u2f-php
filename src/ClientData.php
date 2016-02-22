<?php
declare(strict_types=1);

namespace Firehed\U2F;

use JsonSerializable;
use Firehed\U2F\InvalidDataException as IDE;

class ClientData implements JsonSerializable, ChallengeProvider
{
    use ChallengeTrait;

    private $cid_pubkey;
    private $origin;
    private $typ;

    public static function fromJson(string $json) {
        $data = json_decode($json, true);
        if (json_last_error() !== \JSON_ERROR_NONE) {
            throw new IDE(IDE::MALFORMED_DATA, 'json');
        }
        $ret = new self;
        $ret->setType($ret->validateKey('typ', $data));
        $ret->setChallenge($ret->validateKey('challenge', $data));
        $ret->origin = $ret->validateKey('origin', $data);
        $ret->cid_pubkey = $ret->validateKey('cid_pubkey', $data);
        return $ret;
    }

    /**
     * Checks the 'typ' field against the allowed types in the U2F spec (sec.
     * 7.1)
     * @param $type the 'typ' value
     * @return $this
     * @throws InvalidDataException if a non-conforming value is provided
     */
    private function setType(string $type): self {
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
     * @param $key The array key to check
     * @param $data The array to check in
     * @return mixed The data, if present
     * @throws InvalidDataException if not prsent
     */
    private function validateKey(string $key, array $data) {
        if (!array_key_exists($key, $data)) {
            throw new IDE(IDE::MISSING_KEY, $key);
        }
        return $data[$key];
    }

    // Returns the SHA256 hash of this object per the raw message formats spec
    public function getChallengeParameter(): string {
        $json = json_encode($this, \JSON_UNESCAPED_SLASHES);
        return hash('sha256', $json, true);
    }

    public function jsonSerialize() {
        return [
            'typ' => $this->typ,
            'challenge' => $this->getChallenge(),
            'origin' => $this->origin,
            'cid_pubkey' => $this->cid_pubkey,
        ];
    }

}
