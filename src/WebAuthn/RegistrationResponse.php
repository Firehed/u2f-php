<?php
declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

use Firehed\CBOR\Decoder;
use Firehed\U2F\AttestationCertificateTrait;
use Firehed\U2F\ChallengeProvider;
use Firehed\U2F\RegistrationResponseInterface;

use function Firehed\U2F\fromBase64Web;

class RegistrationResponse implements RegistrationResponseInterface, ChallengeProvider
{
    use AttestationCertificateTrait;

    /** @var string */
    private $clientDataJson;

    /** @var string (binary) */
    private $challenge;

    /** @var string (binary) */
    private $keyHandleBinary;

    /** @var string (binary) */
    private $publicKeyBinary;

    /** @var string (binary) */
    private $signature;

    /** @var string (binary) */
    private $signedData;

    /**
     * @see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
     * @see https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
     *
     * ```javascript
     * const credential = await navicator.credentials.create(...)
     * const dataToSend = {
     *   rawId: new Uint8Array(publicKeyCredential.rawId),
     *   type: publicKeyCredential.type,
     *   response: {
     *     attestationObject: new Uint8Array(publicKeyCredential.response.attestationObject),
     *     clientDataJSON: new Uint8Array(publicKeyCredential.response.clientDataJSON),
     *   },
     * }
     * const jsonToSend = JSON.stringify(dataToSend)
     * ```
     */
    public static function fromDecodedJson(array $data): RegistrationResponse
    {
        assert(isset($data['response']['clientDataJSON']));
        assert(isset($data['response']['attestationObject']));

        // 7.1.1
        $jsonText = self::byteArrayToBinaryString($data['response']['clientDataJSON']);
        // 7.1.2
        $clientData = json_decode($jsonText, true);
        // 7.1.3
        assert($clientData['type'] === 'webauthn.create');
        // 7.1.4 (validate challenge) is done by server
        // TODO: 7.1.5 (validate origin)
        // TODO: 7.1.6 (tokenBinding)
        // 7.1.7
        $clientDataHash = hash('sha256', $jsonText, true);

        // 7.1.8
        $decoder = new Decoder();
        $attestationObject = $decoder->decode(
            self::byteArrayToBinaryString($data['response']['attestationObject'])
        );

        $aoFmt = $attestationObject['fmt'];
        $aoAuthData = $attestationObject['authData'];
        $aoAttStmt = $attestationObject['attStmt'];

        $authData = AuthenticatorData::parse($aoAuthData);
        // TODO: 7.1.9 validate rpidHash = sha256(rpid)
        $credentialData = $authData->getAttestedCredentialData();
        // print_r($credentialData);

        // 7.1.10
        assert($authData->isUserPresent());
        // 7.1.11 skip? TODO
        // 7.1.12 skip? TODO

        // 7.1.13
        // For now, we're only going to support the FIDO-U2F format. In the
        // future this can become switching logic based on the format to get
        // the relevant data
        assert($aoFmt === 'fido-u2f');

        $publicKey = $credentialData['credentialPublicKey'];
        assert($publicKey[3] === -7); // ES256


        $publicKeyU2F = sprintf(
            '%s%s%s',
            "\x04",
            $publicKey[-2],
            $publicKey[-3]
        );

        $response = new RegistrationResponse();
        $response->challenge = fromBase64Web($clientData['challenge']);
        $response->clientDataJson = $jsonText;
        $response->signature = $aoAttStmt['sig'];
        $response->signedData = sprintf(
            '%s%s%s%s%s',
            "\x00",
            $authData->getRpIdHash(),
            $clientDataHash,
            $credentialData['credentialId'],
            $publicKeyU2F
        );
        $response->keyHandleBinary = $credentialData['credentialId'];
        $response->publicKeyBinary = $publicKeyU2F;
        return $response;
        // 7.1.14 (perform verification of attestation statement) is done in
        //   the server
        // 7.1.15 (get valid roots) is done in the server
        // 7.1.16 (cehck attestation cert) is done in the server
        // 7.1.17 (check credentialId is unregistered) is done in the app
    }

    public function getChallengeProvider(): ChallengeProvider
    {
        return $this;
    }

    public function getChallenge(): string
    {
        return $this->challenge;
    }

    public function getSignedData(): string
    {
        return $this->signedData;
    }
    public function getSignature(): string
    {
        return $this->signature;
    }
    public function getPublicKeyBinary(): string
    {
        return $this->publicKeyBinary;
    }
    public function getKeyHandleBinary(): string
    {
        return $this->keyHandleBinary;
    }
    private static function byteArrayToBinaryString(array $bytes): string
    {
        return implode('', array_map('chr', $bytes));
    }
}
