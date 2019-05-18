<?php
declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

use Firehed\U2F\ChallengeProvider;
use Firehed\U2F\LoginResponseInterface;

use function Firehed\U2F\fromBase64Web;
use function assert;
use function hash;
use function is_array;
use function json_decode;

class LoginResponse implements ChallengeProvider, LoginResponseInterface
{
    /** @var AuthenticatorData */
    private $authenticatorData;

    /** @var string (binary) */
    private $authenticatorDataBytes;

    /** @var string (binary) */
    private $challenge;

    /** @var string */
    private $clientDataJson;

    /** @var string (binary) */
    private $keyHandle;

    /** @var string (binary) */
    private $signature;

    /**
     * This takes a JSON representation of a PublicKeyCredential with an
     * AuthenticatorAssertionResponse response type and parses it into a usable
     * object to authenticate.
     * @see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
     * @see https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
     *
     * The JS-native ArrayBuffer objects should be sent as a list-of-bytes by
     * encoding to a `Uint8Array` before `JSON.stringify()`:
     *
     * ```javascript
     * const assertion = await navigator.credentials.get(...)
     * const dataToSend = {
     *   rawId: new Uint8Array(assertion.rawId),
     *   type: assertion.type,
     *   response: {
     *     authenticatorData: new Uint8Array(assertion.response.authenticatorData),
     *     clientDataJSON: new Uint8Array(assertion.response.clientDataJSON),
     *     signature: new Uint8Array(assertion.response.signature),
     *   },
     * }
     * const jsonToSend = JSON.stringify(dataToSend)
     * ```
     */
    public static function fromDecodedJson(array $data): LoginResponse
    {
        assert(isset($data['type']) && $data['type'] === 'public-key');
        assert(isset($data['rawId']));
        assert(isset($data['response']['clientDataJSON']));
        assert(isset($data['response']['signature']));
        assert(isset($data['response']['authenticatorData']));

        $authDataBytes = self::byteArrayToBinaryString($data['response']['authenticatorData']);
        $authData = AuthenticatorData::parse($authDataBytes);
        assert($authData->isUserPresent());

        $jsonText = self::byteArrayToBinaryString($data['response']['clientDataJSON']);
        $clientData = json_decode($jsonText, true);
        assert(is_array($clientData));
        assert($clientData['type'] === 'webauthn.get');

        $response = new LoginResponse();
        $response->authenticatorData = $authData;
        $response->authenticatorDataBytes = $authDataBytes;
        $response->challenge = fromBase64Web($clientData['challenge']);
        $response->clientDataJson = $jsonText;
        $response->keyHandle = self::byteArrayToBinaryString($data['rawId']);
        $response->signature = self::byteArrayToBinaryString($data['response']['signature']);
        return $response;
    }

    private static function byteArrayToBinaryString(array $bytes): string
    {
        return implode('', array_map('chr', $bytes));
    }

    public function getChallenge(): string
    {
        return $this->challenge;
    }

    public function getChallengeProvider(): ChallengeProvider
    {
        return $this;
    }

    public function getCounter(): int
    {
        return $this->authenticatorData->getSignCount();
    }

    public function getKeyHandleBinary(): string
    {
        return $this->keyHandle;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @see WebAuthn 7.2.16 https://w3c.github.io/webauthn/#verifying-assertion
     */
    public function getSignedData(): string
    {
        return sprintf(
            '%s%s',
            $this->authenticatorDataBytes,
            hash('sha256', $this->clientDataJson, true)
        );
    }
}
