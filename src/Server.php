<?php
declare(strict_types=1);

namespace Firehed\U2F;

use BadMethodCallException;
use Firehed\U2F\SecurityException as SE;

class Server
{

    use AppIdTrait;

    /**
     * Holds a list of paths to PEM-formatted CA certificates. Unless
     * verification has been explicitly disabled with `disableCAVerification()`,
     * the Attestation Certificate in the `RegisterResponse` will be validated
     * against the provided CAs.
     *
     * This means that you *must* either a) provide a list of trusted
     * certificates, or b) explicitly disable verifiation. By default, it will
     * attempt to validate against an empty list which will always fail. This
     * is by design.
     */
    private $trustedCAs = [];

    /**
     * Indicates whether to verify against `$trustedCAs`. Must be explicitly
     * disabled with `disableCAVerification()`.
     */
    private $verifyCA = true;

    /**
     * Holds a RegisterRequest used by `register()`, which contains the
     * challenge in the signature.
     */
    private $registerRequest;

    /**
     * Holds Registrations that were previously established by the
     * authenticating party during `authenticate()`
     */
    private $registrations = [];

    /**
     * Holds SignRequests used by `authenticate` which contain the challenge
     * that's part of the signed response.
     */
    private $signRequests = [];

    /**
     * This method authenticates a `SignResponse` against outstanding
     * `Registrations` and their corresponding `SignRequest`s. If the
     * response's signature validates and the counter hasn't done anything
     * strange, the Registration will be returned with an updated counter
     * value, which *must* be persisted for the next authentication. If any
     * verification component fails, a `SE` will be thrown.
     *
     * @param SignResponse the parsed response from the user
     * @return Registration if authentication succeeds
     * @throws SE if authentication fails
     * @throws BadMethodCallException if a precondition is not met
     */
    public function authenticate(SignResponse $response): Registration {
        if (!$this->registrations) {
            throw new BadMethodCallException(
                'Before calling authenticate(), provide `Registration`s with '.
                'setRegistrations()');
        }
        if (!$this->signRequests) {
            throw new BadMethodCallException(
                'Before calling authenticate(), provide `SignRequest`s with '.
                'setSignRequests()');
        }

        // Search for the registration to use based on the Key Handle
        $registration = $this->findObjectWithKeyHandle($this->registrations,
            $response->getKeyHandleBinary());
        if (!$registration) {
            // This would suggest either some sort of forgery attempt or
            // a hilariously-broken token responding to handles it doesn't
            // support and not returning a DEVICE_INELIGIBLE client error.
            throw new SE(SE::KEY_HANDLE_UNRECOGNIZED);
        }

        // Search for the Signing Request to use based on the Key Handle
        $request = $this->findObjectWithKeyHandle($this->signRequests,
            $registration->getKeyHandleBinary());
        if (!$request) {
            // Similar to above, there is a bizarre mismatch between the known
            // possible sign requests and the key handle determined above. This
            // would probably be caused by a logic error causing bogus sign
            // requests to be passed to this method.
            throw new SE(SE::KEY_HANDLE_UNRECOGNIZED);
        }

        // If the challenge in the (signed) response ClientData doesn't
        // match the one in the signing request, the client signed the
        // wrong thing. This could possibly be an attempt at a replay
        // attack.
        $this->validateChallenge($response->getClientData(), $request);

        $pem = $registration->getPublicKeyPem();

        // U2F Spec:
        // https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#authentication-response-message-success
        $to_verify = sprintf('%s%s%s%s',
            $request->getApplicationParameter(),
            chr($response->getUserPresenceByte()),
            pack('N', $response->getCounter()),
            // Note: Spec says this should be from the request, but that's not
            // actually available via the JS API. Because we assert the
            // challenge *value* from the Client Data matches the trusted one
            // from the SignRequest and that value is included in the Challenge
            // Parameter, this is safe unless/until SHA-256 is broken.
            $response->getClientData()->getChallengeParameter()
        );

        // Signature must validate against
        $sig_check = openssl_verify(
            $to_verify,
            $response->getSignature(),
            $pem,
            \OPENSSL_ALGO_SHA256
        );
        if ($sig_check !== 1) {
            // We could not validate the signature using the
            // previously-verified public key on file for this registration.
            // This is most likely malicious, since there's either
            // a non-spec-compliant device or the device doesn't have access to
            // the embedded private key that was used to sign the original
            // registration request.
            throw new SE(SE::SIGNATURE_INVALID);
        }
        if ($response->getCounter() <= $registration->getCounter()) {
            // Tokens are required to keep a counter of authentications
            // performed, and this value is included in the signed response.
            // Entering this block means one of two things:
            // 1) The device counter rolled over its integer limit (very, very
            //    unlikely), or
            // 2) A message was compromised and this is an attempt at a replay
            //    attack, or
            // 3) The private key on the device was somehow compromised, but
            //    the counter is unknown to the attacker.
            //    3a) The attacker started low and we caught them, or
            //    3b) The attacker started high, got in, updated the counter on
            //        file, and the device owner just tried to reauthenticate
            //    In either case, this indicates the device was somehow
            //    compromised. The user should be alerted and the device should
            //    no longer be trusted for authentication. However, the
            //    registration assicated with the device should only be
            //    disabled and not deleted, since it should not be allowed to
            //    be re-added to the user's account.
            throw new SE(SE::COUNTER_USED);
        }
        // It's reasonable to check that the gap between these values is
        // relatively small, to handle the case where an attacker is able to
        // compromise a token's private key and performs a single
        // authentication with an arbitrarily-high counter to avoid this
        // rollback detection. Such a scenario would still trigger the above
        // error when the legitimate token-holder attempts to use their token
        // again. There's no perfect way to handle this since

        return (new Registration())
            ->setAttestationCertificate($registration->getAttestationCertificateBinary())
            ->setKeyHandle($registration->getKeyHandleBinary())
            ->setPublicKey($registration->getPublicKey())
            ->setCounter($response->getCounter());
        return true;
    }

    /**
     * This method authenticates a RegisterResponse against its corresponding
     * RegisterRequest by verifying the certificate and signature. If valid, it
     * returns a Registration object; if not, a SE will be
     * thrown and attempt to register the key must be aborted.
     *
     * @param The response to verify
     * @return Registration if the response is proven authentic
     * @throws SE if the response cannot be proven authentic
     * @throws BadMethodCallException if a precondition is not met
     */
    public function register(RegisterResponse $resp): Registration {
        if (!$this->registerRequest) {
            throw new BadMethodCallException(
                'Before calling register(), provide a RegisterRequest '.
                'with setRegisterRequest()');
        }
        $this->validateChallenge($resp->getClientData(), $this->registerRequest);
        // Check the Application Parameter?

        // https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#registration-response-message-success
        $signed_data = sprintf('%s%s%s%s%s',
            chr(0),
            $this->registerRequest->getApplicationParameter(),
            $resp->getClientData()->getChallengeParameter(),
            $resp->getKeyHandleBinary(),
            $resp->getPublicKey()
        );

        $pem = $resp->getAttestationCertificatePem();
        if ($this->verifyCA) {
            $resp->verifyIssuerAgainstTrustedCAs($this->trustedCAs);
        }

        // Signature must validate against device issuer's public key
        $sig_check = openssl_verify(
            $signed_data,
            $resp->getSignature(),
            $pem,
            \OPENSSL_ALGO_SHA256
        );
        if ($sig_check !== 1) {
            throw new SE(SE::SIGNATURE_INVALID);
        }

        return (new Registration())
            ->setAttestationCertificate($resp->getAttestationCertificateBinary())
            ->setCounter(0) // The response does not include this
            ->setKeyHandle($resp->getKeyHandleBinary())
            ->setPublicKey($resp->getPublicKey());
    }

    /**
     * Disables verification of the Attestation Certificate against the list of
     * CA certificates. This lowers overall security, at the benefit of being
     * able to use devices that haven't been explicitly whitelisted.
     *
     * This method or setTrustedCAs() must be called before register() or
     * a SecurityException will always be thrown.
     *
     * @return self
     */
    public function disableCAVerification(): self {
        $this->verifyCA = false;
        return $this;
    }

    /**
     * Provides a list of CA certificates for device issuer verification during
     * registration.
     *
     * This method or disableCAVerification must be called before register() or
     * a SecurityException will always be thrown.
     *
     * @param array<string> A list of file paths to device issuer CA certs
     * @return self
     */
    public function setTrustedCAs(array $CAs): self {
        $this->verifyCA = true;
        $this->trustedCAs = $CAs;
        return $this;
    }

    /**
     * Provide the previously-generated RegisterRequest to be used when
     * verifying a RegisterResponse during register()
     *
     * @param RegisterRequest
     * @return self
     */
    public function setRegisterRequest(RegisterRequest $request): self {
        $this->registerRequest = $request;
        return $this;
    }

    /**
     * Provide a user's existing Registrations to be used during authentication
     *
     * @param array<Registration>
     * @return self
     */
    public function setRegistrations(array $registrations): self {
        array_map(function(Registration $r){}, $registrations); // type check
        $this->registrations = $registrations;
        return $this;
    }

    /**
     * Provide the previously-generated SignRequests, corresponing to the
     * existing Registrations, of of which should be signed and will be
     * verified during authenticate()
     *
     * @param array<SignRequest>
     * @return self
     */
    public function setSignRequests(array $signRequests): self {
        array_map(function(SignRequest $s){}, $signRequests); // type check
        $this->signRequests = $signRequests;
        return $this;
    }

    /**
     * Creates a new RegisterRequest to be sent to the authenticated user to be
     * used by the `u2f.register` API.
     *
     * @return RegisterRequest
     */
    public function generateRegisterRequest(): RegisterRequest {
        return (new RegisterRequest())
            ->setAppId($this->getAppId())
            ->setChallenge($this->generateChallenge());
    }

    /**
     * Creates a new SignRequest for an existing Registration for an
     * authenticating user, used by the `u2f.sign` API.
     *
     * @param Registration one of the user's existing Registrations
     * @return SignRequest
     */
    public function generateSignRequest(Registration $reg): SignRequest {
        return (new SignRequest())
            ->setAppId($this->getAppId())
            ->setChallenge($this->generateChallenge())
            ->setKeyHandle($reg->getKeyHandleBinary());
    }

    /**
     * Wraps generateSignRequest for multiple Registrations
     *
     * @param array<Registration>
     * @return array<SignRequest>
     */
    public function generateSignRequests(array $registrations): array {
        return array_values(array_map([$this, 'generateSignRequest'], $registrations));
    }

    /**
     * Searches through the provided array of objects, and looks for a matching
     * key handle value. If one is found, it is returned; if not, this returns
     * null.
     *
     * @param array<> haystack to search
     * @param string key handle to find in haystack
     * @return mixed element from haystack
     * @return null if no element matches
     */
    private function findObjectWithKeyHandle(
        array $objects,
        string $keyHandle
    ) {
        foreach ($objects as $object) {
            if (hash_equals($object->getKeyHandleBinary(), $keyHandle)) {
                return $object;
            }
        }
        return null;
    }

    /**
     * Generates a random challenge and returns it base64-web-encoded
     *
     * @return string
     */
    private function generateChallenge(): string {
        // FIDO Alliance spec suggests a minimum of 8 random bytes
        return toBase64Web(\random_bytes(16));
    }

    /**
     * Compares the Challenge value from a known source against the
     * user-provided value. A mismatch will throw a SE. Future
     * versions may also enforce a timing window.
     *
     * @param ChallengeProvider source of known challenge
     * @param ChallengeProvider user-provided value
     * @return true on success
     * @throws SE on failure
     */
    private function validateChallenge(
        ChallengeProvider $from,
        ChallengeProvider $to
    ): bool {
        // Note: strictly speaking, this shouldn't even be targetable as
        // a timing attack. However, this opts to be proactive, and also
        // ensures that no weird PHP-isms in string handling cause mismatched
        // values to validate.
        if (!hash_equals($from->getChallenge(), $to->getChallenge())) {
            throw new SE(SE::CHALLENGE_MISMATCH);
        }
        // TOOD: generate and compare timestamps
        return true;
    }
}
