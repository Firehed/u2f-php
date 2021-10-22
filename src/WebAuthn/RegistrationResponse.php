<?php
declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

use Firehed\CBOR\Decoder;
use Firehed\U2F\AttestationCertificate;
use Firehed\U2F\AttestationCertificateInterface;
use Firehed\U2F\ECPublicKey;
use Firehed\U2F\PublicKeyInterface;
use Firehed\U2F\RegistrationResponseInterface;

use function Firehed\U2F\fromBase64Web;

class RegistrationResponse implements RegistrationResponseInterface
{
    /** @var AttestationCertificateInterface */
    private $attestationCert;

    /** @var string */
    private $clientDataJson;

    /** @var string (binary) */
    private $challenge;

    /** @var string (binary) */
    private $keyHandle;

    /** @var PublicKeyInterface */
    private $publicKey;

    /** @var string (binary) */
    private $rpIdHash;

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
     *
     * @param array{
     *   type: 'public-key',
     *   id: string,
     *   rawId: int[],
     *   response: array{
     *     attestationObject: int[],
     *     clientDataJSON: int[],
     *   }
     * } $data
     */
    public static function fromDecodedJson(array $data): RegistrationResponse
    {
        // @phpstan-ignore-next-line
        assert(isset($data['type']) && $data['type'] === 'public-key');
        // @phpstan-ignore-next-line
        assert(isset($data['response']['clientDataJSON']));
        // @phpstan-ignore-next-line
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
        // 7.1.9 (validate rpIdHash) happens in server
        // 7.1.10
        assert($authData->isUserPresent());
        // 7.1.11 skip? TODO
        // 7.1.12 skip? TODO
        // 7.1.13
        // For now, we're only going to support the FIDO-U2F format. In the
        // future this can become switching logic based on the format to get
        // the relevant data
        assert($aoFmt === 'fido-u2f');
        assert(isset($aoAttStmt['sig']));
        assert(isset($aoAttStmt['x5c']));
        assert(is_array($aoAttStmt['x5c']) && count($aoAttStmt['x5c']) === 1);
        $attestationCert = new AttestationCertificate($aoAttStmt['x5c'][0]);

        $credentialData = $authData->getAttestedCredentialData();
        assert($credentialData !== null);
        $publicKey = $credentialData['credentialPublicKey'];
        assert($publicKey[3] === -7); // ES256 (8.6.2)

        $publicKeyU2F = sprintf(
            '%s%s%s',
            "\x04",
            $publicKey[-2],
            $publicKey[-3]
        ); // 8.6.4
        $publicKey = new ECPublicKey($publicKeyU2F);

        $response = new RegistrationResponse();
        $response->challenge = fromBase64Web($clientData['challenge']);
        $response->clientDataJson = $jsonText;
        $response->rpIdHash = $authData->getRpIdHash();
        $response->signature = $aoAttStmt['sig'];
        $response->signedData = sprintf(
            '%s%s%s%s%s',
            "\x00",
            $authData->getRpIdHash(),
            $clientDataHash,
            $credentialData['credentialId'],
            $publicKeyU2F
        ); // 8.6.5
        $response->keyHandle = $credentialData['credentialId'];
        $response->publicKey = $publicKey;
        $response->attestationCert = $attestationCert;
        return $response;
        // 7.1.14 (perform verification of attestation statement) is done in
        //   the server
        // 7.1.15 (get valid roots) is done in the server
        // 7.1.16 (cehck attestation cert) is done in the server
        // 7.1.17 (check credentialId is unregistered) is done in the app
    }

    public function getAttestationCertificate(): AttestationCertificateInterface
    {
        return $this->attestationCert;
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

    public function getPublicKey(): PublicKeyInterface
    {
        return $this->publicKey;
    }

    public function getKeyHandleBinary(): string
    {
        return $this->keyHandle;
    }

    /**
     * @param int[] $bytes
     */
    private static function byteArrayToBinaryString(array $bytes): string
    {
        return implode('', array_map('chr', $bytes));
    }

    public function getRpIdHash(): string
    {
        return $this->rpIdHash;
    }

    /**
     * @return array{
     *   attestationCert: AttestationCertificateInterface,
     *   clientDataJson: string,
     *   challenge: string,
     *   keyHandle: string,
     *   publicKey: PublicKeyInterface,
     *   rpIdHash: string,
     *   signature: string,
     *   signedData: string,
     * }
     */
    public function __debugInfo(): array
    {
        $hex = function (string $binary) {
            return '0x' . bin2hex($binary);
        };
        return [
            'attestationCert' => $this->attestationCert,
            'clientDataJson' => $this->clientDataJson,
            'challenge' => $hex($this->challenge),
            'keyHandle' => $hex($this->keyHandle),
            'publicKey' => $this->publicKey,
            'rpIdHash' => $hex($this->rpIdHash),
            'signature' => $hex($this->signature),
            'signedData' => $hex($this->signedData),
        ];
    }
}
