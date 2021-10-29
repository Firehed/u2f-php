<?php
declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

use Firehed\U2F\LoginResponseInterface;

use function Firehed\U2F\fromBase64Web;
use function assert;
use function hash;
use function is_array;
use function json_decode;

class LoginResponse implements LoginResponseInterface
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
     *
     * @param array{
     *   type: 'public-key',
     *   rawId: int[],
     *   response: array{
     *     authenticatorData: int[],
     *     clientDataJSON: int[],
     *     signature: int[],
     *   }
     * } $data
     */
    public static function fromDecodedJson(array $data): LoginResponse
    {
        // @phpstan-ignore-next-line
        assert(isset($data['type']) && $data['type'] === 'public-key');
        // @phpstan-ignore-next-line
        assert(isset($data['rawId']));
        // @phpstan-ignore-next-line
        assert(isset($data['response']['clientDataJSON']));
        // @phpstan-ignore-next-line
        assert(isset($data['response']['signature']));
        // @phpstan-ignore-next-line
        assert(isset($data['response']['authenticatorData']));


        // 7.2.8
        $cData = $data['response']['clientDataJSON'];
        $authData = self::byteArrayToBinaryString($data['response']['authenticatorData']);
        $parsedAuthData = AuthenticatorData::parse($authData);
        $sig = self::byteArrayToBinaryString($data['response']['signature']);

        // $authDataBytes = self::byteArrayToBinaryString($data['response']['authenticatorData']);
        // $authData = AuthenticatorData::parse($authDataBytes);

        // 7.2.9
        $jsonText = self::byteArrayToBinaryString($cData);

        // 7.2.10
        $C = json_decode($jsonText, true);
        assert(is_array($C));

        // 7.2.11
        assert($C['type'] === 'webauthn.get');

        // TODO: 7.2.12 verify challenge matches
        // assert($C['challenge'] === session value);

        // TODO: 7.2.13 verify origin matches
        // assert($C['origin'] === ???)

        // TODO?: 7.2.14 token binding (skip?)

        // TODO: 7.2.15 check $authData->getRpIdHash() aligns with server

        // 7.2.16 Check for user presence bit
        assert($parsedAuthData->isUserPresent());
        // TODO 7.2.17 check user verified if needed
        // TODO 7.2.18 extended data etc

        // 7.2.19
        // $hash = hash('sha256', $cData, true);
        $hash = hash('sha256', $jsonText, true);

        // print_r($parsedAuthData);
        $userInfoFromDemo = json_decode(file_get_contents(__DIR__.'/../../../u2f-php-examples/users/touchid.json'), true);
        $regs = $userInfoFromDemo['registrations'];
        $reg = array_pop($regs);
        $registration = new \Firehed\U2F\Registration();
        $registration->setCounter($reg['counter']);
        $registration->setKeyHandle(base64_decode($reg['key_handle']));
        $registration->setPublicKey(new \Firehed\U2F\ECPublicKey(base64_decode($reg['public_key'])));
        $registration->setAttestationCertificate(new \Firehed\U2F\AttestationCertificate(base64_decode($reg['attestation_certificate'])));

        print_r($registration);
        // $storedCredential =RegistrationResponse::fromDecodedJson(
        //     json_decode(
        //         file_get_contents(__DIR__.

        // 7.2.20
        $verifyResult = \openssl_verify(
            $authData . $hash,
            $sig,
            // $credentialPublicKey,
            $registration->getPublicKey()->getPemFormatted(),
            \OPENSSL_ALGO_SHA256
        );
        if ($verifyResult !== 1) {
            throw new \Exception('Sig invalid');
        }




        print_r(get_defined_vars());
        $response = new LoginResponse();
        $response->authenticatorData = $authData;
        $response->authenticatorDataBytes = $authDataBytes;
        $response->challenge = fromBase64Web($clientData['challenge']);
        $response->clientDataJson = $jsonText;
        $response->keyHandle = self::byteArrayToBinaryString($data['rawId']);
        $response->signature = self::byteArrayToBinaryString($data['response']['signature']);
        return $response;
    }

    /**
     * @param int[] $bytes
     */
    private static function byteArrayToBinaryString(array $bytes): string
    {
        return implode('', array_map('chr', $bytes));
    }

    public function getChallenge(): string
    {
        return $this->challenge;
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

    /**
     * @return array{
     *   clientDataJson: string,
     *   challenge: string,
     *   keyHandle: string,
     *   signature: string,
     * }
     */
    public function __debugInfo(): array
    {
        $hex = function (string $binary) {
            return '0x' . bin2hex($binary);
        };
        return [
            'clientDataJson' => $this->clientDataJson,
            'challenge' => $hex($this->challenge),
            'keyHandle' => $hex($this->keyHandle),
            'signature' => $hex($this->signature),
        ];
    }
}
