<?php
declare(strict_types=1);

namespace Firehed\U2F;
use Firehed\U2F\InvalidDataException as IDE;

trait ResponseTrait
{

    use KeyHandleTrait;

    private $clientData;
    // Stored base64-encoded
    private $signature = '';

    // Binary string of signature
    public function getSignature(): string {
        return base64_decode($this->signature);
    }

    public function getClientData(): ClientData {
        return $this->clientData;
    }

    protected function setSignature(string $signature): self {
        $this->signature = base64_encode($signature);
        return $this;
    }

    public static function fromJson(string $json): self {
        $data = json_decode($json, true);
        if (json_last_error() !== \JSON_ERROR_NONE) {
            throw new IDE(IDE::MALFORMED_DATA, 'JSON');
        }
        if (isset($data['errorCode'])) {
            throw new ClientErrorException($data['errorCode']);
        }

        $ret = new self;
        $ret->validateKeyInArray('clientData', $data);
        $ret->clientData = ClientData::fromJson(fromBase64Web($data['clientData']));
        return $ret->parseResponse($data);
    }

    abstract protected function parseResponse(array $response): self;

    private function validateKeyInArray(string $key, array $data): bool {
        if (!isset($data[$key])) {
            throw new IDE(IDE::MISSING_KEY, $key);
        }
        if (!is_string($data[$key])) {
            throw new IDE(IDE::MALFORMED_DATA, $key);
        }
        return true;
    }

}
