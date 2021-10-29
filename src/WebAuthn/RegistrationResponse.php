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
    // private $challenge;

    /** @var string (binary) */
    private $keyHandle;

    /** @var PublicKeyInterface */
    private $publicKey;

    /** @var string (binary) */
    // private $rpIdHash;

    /** @var string (binary) */
    // private $signature;

    /** @var string (binary) */
    // private $signedData;

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
        /**
         * @var array{
         *   type: 'webauthn.create',
         *   challenge: string,
         *   origin: string,
         * }
         */
        $clientData = json_decode($jsonText, true);
        // 7.1.3
        assert($clientData['type'] === 'webauthn.create');
        // 7.1.4 (validate challenge) is done by server
        // TODO: 7.1.5 (validate origin)
        // TODO: 7.1.6 (tokenBinding)
        // 7.1.11
        $clientDataHash = hash('sha256', $jsonText, true);

        // 7.1.12
        $decoder = new Decoder();
        $attestationObject = $decoder->decode(
            self::byteArrayToBinaryString($data['response']['attestationObject'])
        );

        // $attestationCert = self::parseAttestationObject($attestationObject);

        // assert keys exist?
        assert(array_key_exists('fmt', $attestationObject));
        assert(array_key_exists('authData', $attestationObject));
        assert(array_key_exists('attStmt', $attestationObject));

        $authData = AuthenticatorData::parse($attestationObject['authData']);
        // print_r($authData);
        // print_r($clientData);

        // 7.1.13 (also happens in server)
        // FIXME: authData->getRpIdHash() must be validated against the server
        // assert($authData->getRpIdHash() === hash('sha256', $clientData['origin'], true));
        // FIXME: ^^^

        // 7.1.14
        assert($authData->isUserPresent());

        // 7.1.15
        // assert($authData->isUserVerified());

        // 7.1.16 TODO check that alg of authData matches request format from
        //   JS create options
        assert($authData->getAttestedCredentialData()['credentialPublicKey'][3] === -7);

        // 7.1.17 TODO look for/handle extension data in $authData

        // 7.1.18 match on fmt

        if ($attestationObject['fmt'] === 'fido-u2f') {
            /**
             * CBOR validation: 8.6.v.1
             */
            $attStmt = $attestationObject['attStmt'];
            assert(
                array_key_exists('sig', $attStmt)
                && is_string($attStmt['sig'])
            );
            assert(
                array_key_exists('x5c', $attStmt)
                && is_array($attStmt['x5c'])
                && count($attStmt['x5c']) === 1
            );
            $result = self::parseFidoU2F($attStmt, $authData, $clientDataHash);
        } elseif ($attestationObject['fmt'] === 'apple') {
            /**
             * CBOR validation: 8.8.v.1
             *
             * @var array{
             *   fmt: 'apple',
             *   attStmt: array{
             *     x5c: string[],
             *   }
             * } $attestationObject
             */
            $attStmt = $attestationObject['attStmt'];
            $x5c = $attStmt['x5c'];

            $result = self::parseApple($attStmt, $authData, $clientDataHash);
        } else {
            throw new \Exception('Unsupported format');
        }

        $attestationCert = $result;


        // For now, we're only going to support the FIDO-U2F format. In the
        // future this can become switching logic based on the format to get
        // the relevant data
        // assert($aoFmt === 'fido-u2f');
        // assert(isset($aoAttStmt['sig']));
        // assert(isset($aoAttStmt['x5c']));
        // assert(is_array($aoAttStmt['x5c']) && count($aoAttStmt['x5c']) === 1);
        // $attestationCert = new AttestationCertificate($aoAttStmt['x5c'][0]);

        $credentialData = $authData->getAttestedCredentialData();
        assert($credentialData !== null);
        $rawPublicKey = $credentialData['credentialPublicKey'];
        // assert($publicKey[3] === -7); // ES256 (8.6.2)

        $publicKeyU2F = sprintf(
            '%s%s%s',
            "\x04",
            $rawPublicKey[-2],
            $rawPublicKey[-3]
        ); // 8.6.4
        $publicKey = new ECPublicKey($publicKeyU2F);

        $response = new RegistrationResponse();
        // $response->challenge = fromBase64Web($clientData['challenge']);
        $response->clientDataJson = $jsonText;
        // $response->rpIdHash = $authData->getRpIdHash();
        // $response->signature = $aoAttStmt['sig'];
        // $response->signedData = sprintf(
        //     '%s%s%s%s%s',
        //     "\x00",
        //     $authData->getRpIdHash(),
        //     $clientDataHash,
        //     $credentialData['credentialId'],
        //     $publicKeyU2F
        // ); // 8.6.5
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

    // public function getChallenge(): string
    // {
    //     return $this->challenge;
    // }

    // public function getSignedData(): string
    // {
    //     return $this->signedData;
    // }

    // public function getSignature(): string
    // {
    //     return $this->signature;
    // }

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
            // 'challenge' => $hex($this->challenge),
            'keyHandle' => $hex($this->keyHandle),
            'publicKey' => $this->publicKey,
            // 'rpIdHash' => $hex($this->rpIdHash),
            // 'signature' => $hex($this->signature),
            // 'signedData' => $hex($this->signedData),
        ];
    }

    // see also RFC8809
    private static function parseAttestationObject(array $attestationObject): AttestationCertificateInterface
    {
        return match ($attestationObject['fmt']) {
            'apple' => self::parseApple($attestationObject),
            'fido-u2f' => self::parseFidoU2F($attestationObject),
        };
    }

    /**
     * @param array{
     *   sig: string,
     *   x5c: array{string},
     * } $attStmt
     */
    private static function parseFidoU2F(
        array $attStmt,
        AuthenticatorData $authData,
        string $clientDataHash
    ): AttestationCertificateInterface {

        $sig = $attStmt['sig'];
        $attCert = $attStmt['x5c'][0];
        $attCertObj = new AttestationCertificate($attCert);
        $certificatePublicKey = \openssl_pkey_get_public($attCertObj->getPemFormatted());
        $certificatePublicKeyDetails = \openssl_pkey_get_details($certificatePublicKey);
        assert($certificatePublicKeyDetails['type'] === \OPENSSL_KEYTYPE_EC);
        // check curve name/oid (same step)

        // 8.6.v.3
        $rpIdHash = $authData->getRpIdHash();

        $attestedCredentialData = $authData->getAttestedCredentialData();
        $credentialId = $attestedCredentialData['credentialId'];
        $credentialPublicKey = $attestedCredentialData['credentialPublicKey'];

        // 8.6.v.4
        $publicKeyU2F = sprintf(
            '%s%s%s',
            "\x04",
            $credentialPublicKey[-2],
            $credentialPublicKey[-3]
        );

        // 8.6.v.5
        $verificationData = sprintf(
            '%s%s%s%s%s',
            "\x00",
            $rpIdHash,
            $clientDataHash,
            $credentialId,
            $publicKeyU2F
        );

        // 8.6.v.6
        $verificationResult = \openssl_verify(
            $verificationData,
            $sig,
            $certificatePublicKey,
            \OPENSSL_ALGO_SHA256
        );
        if ($verificationResult !== 1) {
            throw new \Exception('Signature verification failed');
        }

        // 8.6.v.7
        // (optionally inspect x5c & check attestation type)

        // 8.6.v.8
        // FIXME: 6.5.3 attestation type, etc
        return $attCertObj;
    }

    /**
     * @param array{
     *   x5c: string[],
     * } $attStmt
     * @param string $authenticatorData The raw authenticator data
     */
    private static function parseApple(
        array $attStmt,
        AuthenticatorData $authData,
        string $clientDataHash
    ): AttestationCertificateInterface {
        $x5c = $attStmt['x5c'];

        // 8.8.v.2
        $nonceToHash = $authData->getRawBytes() . $clientDataHash;

        // 8.8.v.3
        $nonce = hash('sha256', $nonceToHash, true);

        // var_dump(bin2hex($nonce));
        $certs = array_map(fn ($cert) => new AttestationCertificate($cert), $x5c);

        $pems = array_map(fn (AttestationCertificateInterface $cert) => $cert->getPemFormatted(), $certs);
        $pems[] = self::getAppleWebAuthnRootCACertificatePem();
        self::verifyCertificateChain($pems);

        $credCert = $certs[0];
        $parsed = \openssl_x509_parse($credCert->getPemFormatted());
        assert($parsed !== false);
        assert(array_key_exists('extensions', $parsed));
        $certificateExtensions = $parsed['extensions'];
        assert(array_key_exists('1.2.840.113635.100.8.2', $certificateExtensions));
        // var_dump($certificateExtensions);
        $nonceInCertificateExtension = $certificateExtensions['1.2.840.113635.100.8.2'];
        if (strlen($nonceInCertificateExtension) > 32) {
            // This seems to be a wrapped value containing extra...stuff
            // 0x3024a1220420 + actual nonce
            assert(strlen($nonceInCertificateExtension) === 38);
            $prefix = substr($nonceInCertificateExtension, 0, 6);
            // X.690 DER encoding:
            // 0x3024 Sequence (cosntructed), 0x24=36 bytes
            // 0xA122 Context-specific, constructed, (index=1?), 0x22=34 bytes
            // 0x0420 Octet string, 0x20=32 bytes
            assert($prefix === "\x30\x24\xA1\x22\x04\x20");
            $nonceInCertificateExtension = substr($nonceInCertificateExtension, 6);
        }
        // var_dump(bin2hex($nonceInCertificateExtension));
        // print_r($parsed);
        $nonceMatchResult = \hash_equals($nonceInCertificateExtension, $nonce);
        // 8.8.v.4
        if ($nonceMatchResult !== true) {
            throw new \Exception('Nonce in certificate does not match');
        }

        // 8.8.v.5 Verify keys match
        $subjectPublicKey = \openssl_pkey_get_public($credCert->getPemFormatted());
        $spkDetails = \openssl_pkey_get_details($subjectPublicKey);
        // print_r($parsed);
        // print_r($subjectPublicKey);
        // print_r($spkDetails);
        assert($spkDetails['type'] === \OPENSSL_KEYTYPE_EC);
        $ec = $spkDetails['ec'];
        // curve_name = prime256v1
        // curve_oid = 1.2.840.10045.3.1.7
        $credentialPublicKey = $authData->getAttestedCredentialData()['credentialPublicKey'];
        if (!hash_equals($ec['x'], $credentialPublicKey[-2])) {
            throw new \Exception('x coordinate mismatch');
        }
        if (!hash_equals($ec['y'], $credentialPublicKey[-3])) {
            throw new \Exception('y coordinate mismatch');
        }

        // TODO: 8.8.v.6: Return Anonymization CA + trust path

        // FIXME: this somehow needs to deal with the certificate chain..I
        // think?
        // https://webkit.org/blog/11312/meet-face-id-and-touch-id-for-the-web/
        // See "Verifying the statement format"
        // tl;dr: check cert chain for validity using known apple root from
        // https://www.apple.com/certificateauthority/private/

        // The signature counter is not implemented and therefore it is always
        // zero. Secure Enclave is used to prevent the credential private key
        // from leaking instead of a software safeguard.
        return $credCert;
    }

    private static function getAppleWebAuthnRootCACertificatePem(): string
    {
        return '-----BEGIN CERTIFICATE-----
MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
1bWeT0vT
-----END CERTIFICATE-----';
    }

    /**
     * Rough implementation for 7.1.21 for not-None, not-Self attestation
     *
     * @param string[] $pemFormattedCertificates
     */
    private static function verifyCertificateChain(array $pemFormattedCertificates): void
    {
        assert(count($pemFormattedCertificates) >= 2);
        // Re-index, just in case
        $pemFormattedCertificates = array_values($pemFormattedCertificates);

        for ($i = 1; $i < count($pemFormattedCertificates); $i++) {
            // var_dump("Verifying {($i-1)} with chain {$i}");
            $certToVerify = $pemFormattedCertificates[$i - 1];
            $signingCert = $pemFormattedCertificates[$i];

            $verificationResult = openssl_x509_verify($certToVerify, $signingCert);
            if ($verificationResult !== 1) {
                throw new \Exception("Signature could not be verified");
            }
            // print_r(\openssl_x509_parse($certToVerify));
            // print_r(\openssl_x509_parse($signingCert));
            // print_r($signingCert);
            // var_dump($certToVerify, $signingCert);
        }

        // Finally, ensure that last certificate in the chain is a root
        // certificate. Due to workflow (e.g. manually importing the data) this
        // is basically guaranteed, but there's no reason not to add the
        // additional check.
        $parsed = \openssl_x509_parse($signingCert);
        if ($parsed['subject'] !== $parsed['issuer']) {
            throw new \Exception('Final certificate in the chain was not a root');
        }
        $extensions = $parsed['extensions'];
        $basicConstraints = $extensions['basicConstraints'];
        if ($basicConstraints !== 'CA:TRUE') {
            throw new \Exception('Final certificate in the chain was not a CA');
        }
        // Certificates verified
    }
}
