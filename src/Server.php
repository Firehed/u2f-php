<?php
declare(strict_types=1);

namespace Firehed\U2F;

use BadMethodCallException;
use Firehed\U2F\SecurityException as SE;
use RuntimeException;

class Server
{
    use AppIdTrait;

    /**
     * Holds a list of paths to PEM-formatted CA certificates. Unless
     * verification has been explicitly disabled with `disableCAVerification()`,
     * the Attestation Certificate in the `RegistrationResponseInterface` will
     * be validated against the provided CAs.
     *
     * This means that you *must* either a) provide a list of trusted
     * certificates, or b) explicitly disable verifiation. By default, it will
     * attempt to validate against an empty list which will always fail. This
     * is by design.
     *
     * @var string[]
     */
    private $trustedCAs = [];

    /**
     * Indicates whether to verify against `$trustedCAs`. Must be explicitly
     * disabled with `disableCAVerification()`.
     *
     * @var bool
     */
    private $verifyCA = true;

    /**
     * Holds a RegisterRequest used by `register()`, which contains the
     * challenge in the signature.
     *
     * @var ?RegisterRequest
     */
    private $registerRequest;

    /**
     * Holds Registrations that were previously established by the
     * authenticating party during `authenticate()`
     *
     * @var RegistrationInterface[]
     */
    private $registrations = [];

    /**
     * Holds SignRequests used by `authenticate` which contain the challenge
     * that's part of the signed response.
     *
     * @var SignRequest[]
     */
    private $signRequests = [];

    public function __construct()
    {
        $overload = ini_get('mbstring.func_overload');
        // @codeCoverageIgnoreStart
        if ($overload > 0) {
            throw new RuntimeException(
                'The deprecated "mbstring.func_overload" directive must be disabled'
            );
        }
        // @codeCoverageIgnoreEnd
    }
    /**
     * This method authenticates a `LoginResponseInterface` against outstanding
     * registrations and their corresponding `SignRequest`s. If the response's
     * signature validates and the counter hasn't done anything strange, the
     * registration will be returned with an updated counter value, which *must*
     * be persisted for the next authentication. If any verification component
     * fails, a `SE` will be thrown.
     *
     * @param LoginResponseInterface $response the parsed response from the user
     * @return RegistrationInterface if authentication succeeds
     * @throws SE if authentication fails
     * @throws BadMethodCallException if a precondition is not met
     */
    public function authenticate(LoginResponseInterface $response): RegistrationInterface
    {
        if (!$this->registrations) {
            throw new BadMethodCallException(
                'Before calling authenticate(), provide objects implementing'.
                'RegistrationInterface with setRegistrations()'
            );
        }
        if (!$this->signRequests) {
            throw new BadMethodCallException(
                'Before calling authenticate(), provide `SignRequest`s with '.
                'setSignRequests()'
            );
        }

        // Search for the registration to use based on the Key Handle
        /** @var ?Registration */
        $registration = $this->findObjectWithKeyHandle(
            $this->registrations,
            $response->getKeyHandleBinary()
        );
        if (!$registration) {
            // This would suggest either some sort of forgery attempt or
            // a hilariously-broken token responding to handles it doesn't
            // support and not returning a DEVICE_INELIGIBLE client error.
            throw new SE(SE::KEY_HANDLE_UNRECOGNIZED);
        }

        // Search for the Signing Request to use based on the Key Handle
        $request = $this->findObjectWithKeyHandle(
            $this->signRequests,
            $registration->getKeyHandleBinary()
        );
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
        $this->validateChallenge($request, $response);

        $pem = $registration->getPublicKey()->getPemFormatted();

        $toVerify = $response->getSignedData();

        // Signature must validate against
        $sig_check = openssl_verify(
            $toVerify,
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
            ->setAttestationCertificate($registration->getAttestationCertificate())
            ->setKeyHandle($registration->getKeyHandleBinary())
            ->setPublicKey($registration->getPublicKey())
            ->setCounter($response->getCounter());
    }

    /**
     * This method authenticates a RegistrationResponseInterface against its
     * corresponding RegisterRequest by verifying the certificate and signature.
     * If valid, it returns a registration; if not, a SE will be thrown and
     * attempt to register the key must be aborted.
     *
     * @param RegistrationResponseInterface $response The response to verify
     * @return RegistrationInterface if the response is proven authentic
     * @throws SE if the response cannot be proven authentic
     * @throws BadMethodCallException if a precondition is not met
     */
    public function register(RegistrationResponseInterface $response): RegistrationInterface
    {
        if (!$this->registerRequest) {
            throw new BadMethodCallException(
                'Before calling register(), provide a RegisterRequest '.
                'with setRegisterRequest()'
            );
        }
        $this->validateChallenge($this->registerRequest, $response);
        // Check the Application Parameter
        $this->validateRelyingParty($response->getRpIdHash());

        if ($this->verifyCA) {
            $this->verifyAttestationCertAgainstTrustedCAs($response);
        }

        // Signature must validate against device issuer's public key
        $pem = $response->getAttestationCertificate()->getPemFormatted();
        $sig_check = openssl_verify(
            $response->getSignedData(),
            $response->getSignature(),
            $pem,
            \OPENSSL_ALGO_SHA256
        );
        if ($sig_check !== 1) {
            throw new SE(SE::SIGNATURE_INVALID);
        }

        return (new Registration())
            ->setAttestationCertificate($response->getAttestationCertificate())
            ->setCounter(0) // The response does not include this
            ->setKeyHandle($response->getKeyHandleBinary())
            ->setPublicKey($response->getPublicKey());
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
    public function disableCAVerification(): self
    {
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
     * @param string[] $CAs A list of file paths to device issuer CA certs
     * @return self
     */
    public function setTrustedCAs(array $CAs): self
    {
        $this->verifyCA = true;
        $this->trustedCAs = $CAs;
        return $this;
    }

    /**
     * Provide the previously-generated RegisterRequest to be used when
     * verifying a RegisterResponse during register()
     *
     * @param RegisterRequest $request
     * @return self
     */
    public function setRegisterRequest(RegisterRequest $request): self
    {
        $this->registerRequest = $request;
        return $this;
    }

    /**
     * Provide a user's existing registration to be used during
     * authentication
     *
     * @param RegistrationInterface[] $registrations
     * @return self
     */
    public function setRegistrations(array $registrations): self
    {
        array_map(function (RegistrationInterface $r) {
        }, $registrations); // type check
        $this->registrations = $registrations;
        return $this;
    }

    /**
     * Provide the previously-generated SignRequests, corresponing to the
     * existing Registrations, of of which should be signed and will be
     * verified during authenticate()
     *
     * @param SignRequest[] $signRequests
     * @return self
     */
    public function setSignRequests(array $signRequests): self
    {
        array_map(function (SignRequest $s) {
        }, $signRequests); // type check
        $this->signRequests = $signRequests;
        return $this;
    }

    /**
     * Creates a new RegisterRequest to be sent to the authenticated user to be
     * used by the `u2f.register` API.
     *
     * @return RegisterRequest
     */
    public function generateRegisterRequest(): RegisterRequest
    {
        return (new RegisterRequest())
            ->setAppId($this->getAppId())
            ->setChallenge($this->generateChallenge());
    }

    /**
     * Creates a new SignRequest for an existing registration for an
     * authenticating user, used by the `u2f.sign` API.
     *
     * @param RegistrationInterface $reg one of the user's existing Registrations
     * @return SignRequest
     */
    public function generateSignRequest(RegistrationInterface $reg): SignRequest
    {
        return (new SignRequest())
            ->setAppId($this->getAppId())
            ->setChallenge($this->generateChallenge())
            ->setKeyHandle($reg->getKeyHandleBinary());
    }

    /**
     * Wraps generateSignRequest for multiple registrations. Using this API
     * ensures that all sign requests share a single challenge, which greatly
     * simplifies compatibility with WebAuthn
     *
     * @param RegistrationInterface[] $registrations
     * @return SignRequest[]
     */
    public function generateSignRequests(array $registrations): array
    {
        $challenge = $this->generateChallenge();
        $requests = array_map([$this, 'generateSignRequest'], $registrations);
        $requestsWithSameChallenge = array_map(function (SignRequest $req) use ($challenge) {
            return $req->setChallenge($challenge);
        }, $requests);
        return array_values($requestsWithSameChallenge);
    }

    /**
     * Searches through the provided array of objects, and looks for a matching
     * key handle value. If one is found, it is returned; if not, this returns
     * null.
     *
     * @template T of KeyHandleInterface
     *
     * @param T[] $objects haystack to search
     * @param string $keyHandle key handle to find in haystack
     *
     * @return ?T element from haystack if match found, otherwise null
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
    private function generateChallenge(): string
    {
        // FIDO Alliance spec suggests a minimum of 8 random bytes
        return toBase64Web(\random_bytes(16));
    }

    private function validateRelyingParty(string $rpIdHash): void
    {
        // Note: this is a bit delicate at the moment, since different
        // protocols have different rules around the handling of Relying Party
        // verification. Expect this to be revised.
        if (!hash_equals($this->getRpIdHash(), $rpIdHash)) {
            throw new SE(SE::WRONG_RELYING_PARTY);
        }
    }
    /**
     * Compares the Challenge value from a known source against the
     * user-provided value. A mismatch will throw a SE. Future
     * versions may also enforce a timing window.
     *
     * @param ChallengeProvider $from source of known challenge
     * @param ChallengeProvider $to user-provided value
     * @throws SE on failure
     */
    private function validateChallenge(ChallengeProvider $from, ChallengeProvider $to): void
    {
        // Note: strictly speaking, this shouldn't even be targetable as
        // a timing attack. However, this opts to be proactive, and also
        // ensures that no weird PHP-isms in string handling cause mismatched
        // values to validate.
        if (!hash_equals($from->getChallenge(), $to->getChallenge())) {
            throw new SE(SE::CHALLENGE_MISMATCH);
        }
    }

    /**
     * Asserts that the attestation cert provided by the registration is issued
     * by the set of trusted CAs.
     *
     * @param RegistrationResponseInterface $response The response to validate
     * @throws SecurityException upon failure
     * @return void
     */
    private function verifyAttestationCertAgainstTrustedCAs(RegistrationResponseInterface $response): void
    {
        $pem = $response->getAttestationCertificate()->getPemFormatted();

        $result = openssl_x509_checkpurpose(
            $pem,
            \X509_PURPOSE_ANY,
            $this->trustedCAs
        );
        if ($result !== true) {
            throw new SE(SE::NO_TRUSTED_CA);
        }
    }
}
