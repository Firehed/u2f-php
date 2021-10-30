<?php

declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

use Firehed\U2F\ChallengeProviderInterface;

use function hash;
use function json_decode;
use function parse_url;
use function openssl_verify;
use function Firehed\U2F\toBase64Web;

use const JSON_THROW_ON_ERROR;
use const OPENSSL_ALGO_SHA256;
use const PHP_URL_HOST;

function log($data) { error_log(print_r($data, true)); }

class RelyingPartyServer
{
    /*
     * $origin should be a "tuple origin", including the scheme, host, and (if
     * nonstandard) port.
     */
    public function __construct(private string $origin)
    {
    }

    /**
     * 7.2. Verifying an Authentication Assertion
     *
     * Starts at step 7
     *
     * @param CredentialInterface[] $storedCredentials
     */
    public function login(Web\AuthenticatorAssertionResponse $response, ChallengeProviderInterface $challenge, array $storedCredentials)
    {
        $storedCredential = self::findCredentalWithId($storedCredentials, $response->rawId);

        // 7.2.7
        $credentialPublicKey = $storedCredential->getPublicKeyPem();

        // 7.2.8
        $cData = $response->clientDataJSON;
        $authData = $response->authenticatorData;
        $sig = $response->signature;
        $parsedAuthData = AuthenticatorData::parse($authData);

        // 7.2.9
        // (nothing to do, already utf8)
        $JSONText = $cData;

        // 7.2.10
        $C = json_decode($JSONText, true, flags: JSON_THROW_ON_ERROR);
        // 7.2.11
        self::assert($C['type'] === 'webauthn.get', 'clientDataJSON.type incorrect');
        // 7.2.12
        self::assert($C['challenge'] === toBase64Web($challenge->getChallenge()), 'clientDataJSON.challenge incorrect');
        // 7.2.13
        self::assert($C['origin'] === $this->origin, 'clientDataJSON.origin incorrect');
        // 7.2.14
        // TODO: C.tokenBinding.status (?)

        // 7.2.15
        $this->validateRpIdHash($parsedAuthData->getRpIdHash());

        // 7.2.16
        self::assert($parsedAuthData->isUserPresent(), 'authData User Present bit missing');

        // 7.2.17
        $userVerificationIsRequired = false; // FIXME: how is this configured?
        if ($userVerificationIsRequired) {
            self::assert($parsedAuthData->isUserVerified(), 'authData User Verified bit missing');
        }

        // 7.2.18
        // Validate client extension outputs
        // TODO

        // 7.2.19
        $hash = self::hash($cData);

        // 7.2.20
        $verifyResult = \openssl_verify(
            $authData . $hash,
            $sig,
            $credentialPublicKey, // TODO: pem or openssl pk (openssl_pkey_get_public)
            OPENSSL_ALGO_SHA256 // This probably depends on the PK
        );
        self::assert($verifyResult === 1, 'Signature verification failed');

        // 7.2.21
        $storedSignCount = $storedCredential->getSignatureCounter();
        if ($parsedAuthData->getSignCount() !== 0 || $storedSignCount !== 0) {
            if ($parsedAuthData->getSignCount() > $storedSignCount) {
                // This is ok, we will update $storedSignCount
                log('sign count ok');
            } else {
                // Incorporate this into "risk scoring"
                // RP _may_ update storedSignCount
                // auth ceremony _may_ fail
                log('sign count problem');
            }
        } else {
            // Stored sign count and response sign count are both zero. This
            // could occur in situations where the token does not support sign
            // counts (apple's touchid/faceid platform authenticator is known
            // to do this), or it's some kind of bogus token IMMEDIATELY
            // following registration where the stored sign count is still at
            // zero.
            // The W3 spec doesn't call out this condition, so it seems like it
            // should be safe to ignore.
        }

        // All done here
        log('done');
    }

    /**
     * Returns a public key in PEM format
     * @param CredentialInterface[] $credentials
     */
    private static function findCredentalWithId(array $credentials, string $id): CredentialInterface
    {
        foreach ($credentials as $credential) {
            if ($credential->getId() === $id) {
                return $credential;
            }
        }
        self::assert(false, 'No credential found with provided id');
    }

    private static function assert(bool $result, string $failureMessage): void
    {
        if ($result === false) {
            throw new \Exception($failureMessage);
        }
    }

    private static function hash(string $data): string
    {
        return hash('sha256', $data, true);
    }

    private function validateRpIdHash(string $rpIdHash): void
    {
        $host = parse_url($this->origin, PHP_URL_HOST);
        // For now, we will only support an exact match. In the future, this
        // may be extended to support checking parent domains. E.g. if
        // $this->origin === 'https://login.example.com:1337', right now only
        // `login.example.com` is permitted; later, checking `example.com` can
        // be allowed. This is nontrivial because each TLD has different
        // registrable components.
        //
        // The process for doing so would be attempting a match of host, and if
        // that match fails, drop the subdomain and try again, repeating until
        // reaching the registrable component. If that also fails, then
        // validation has failed.
        self::assert($rpIdHash === self::hash($host), 'authData rpIdHash invalid');
    }
}
