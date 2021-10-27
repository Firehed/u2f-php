<?php

namespace Firehed\U2F;

use BadMethodCallException;
use TypeError;

/**
 * @covers Firehed\U2F\Server
 */
class ServerTest extends \PHPUnit\Framework\TestCase
{
    const APP_ID = 'https://u2f.ericstern.com';

    const ENCODED_KEY_HANDLE =
        'JUnVTStPn-V2-bCu0RlvPbukBpHTD5Mi1ZGglDOcN0vD45rnTD0BXdkRt78huTwJ7tVax'.
        'TqSetHjr22tCjmYLQ';

    const ENCODED_PUBLIC_KEY =
        'BEyIn4ldTViNAgceMA/YgRX1DlJR3bSF39drG44Fx1E2LaF9Md9RUN2CHyfzSokIjjCHP'.
        '8jMsTYwdt0tKe6qLzc=';

    /** @var Server */
    private $server;

    public function setUp(): void
    {
        $this->server = (new Server(self::APP_ID))
            ->disableCAVerification();
    }

    public function testConstruct(): void
    {
        $server = new Server('test.example.com');
        $this->assertInstanceOf(Server::class, $server);
        self::assertSame('test.example.com', $server->getAppId());
    }

    /**
     * @deprecated
     */
    public function testSetAppId(): void
    {
        $server = new Server();
        self::assertSame('', $server->getAppId());
        $server->setAppId(self::APP_ID);
        self::assertSame(self::APP_ID, $server->getAppId());
    }

    public function testDisableCAVerificationReturnsSelf(): void
    {
        $server = new Server();
        $this->assertSame(
            $server,
            $server->disableCAVerification(),
            'disableCAVerification did not return $this'
        );
    }

    /**
     * @deprecated
     */
    public function testGenerateRegisterRequest(): void
    {
        $req = $this->server->generateRegisterRequest();
        $this->assertInstanceOf(RegisterRequest::class, $req);
        $this->assertSame(
            self::APP_ID,
            $req->getAppId(),
            'RegisterRequest App ID was not the value from the server'
        );
        $this->assertNotEmpty(
            $req->getChallenge(),
            'No challenge value was set'
        );
        $this->assertTrue(
            strlen($req->getChallenge()) >= 8,
            'Challenge was less than 8 bytes long, violating the spec'
        );
    }

    /**
     * @deprecated
     */
    public function testGenerateSignRequest(): void
    {
        $kh = \random_bytes(16);
        $registration = (new Registration())
            ->setKeyHandle($kh);
        $req = $this->server->generateSignRequest($registration);

        $this->assertInstanceOf(SignRequest::class, $req);
        $this->assertSame(
            $kh,
            $req->getKeyHandleBinary(),
            'Key handle was not set correctly'
        );
        $this->assertSame(
            self::APP_ID,
            $req->getAppId(),
            'SignRequest App ID was not the value form the server'
        );
        $this->assertNotEmpty(
            $req->getChallenge(),
            'No challenge value was set'
        );
        $this->assertTrue(
            strlen($req->getChallenge()) >= 8,
            'Challenge was less than 8 bytes long, violating the spec'
        );
    }

    /**
     * @deprecated
     */
    public function testGenerateSignRequests(): void
    {
        $registrations = [
            (new Registration())->setKeyHandle(\random_bytes(16)),
            (new Registration())->setKeyHandle(\random_bytes(16)),
            (new Registration())->setKeyHandle(\random_bytes(16)),
        ];
        $signRequests = $this->server->generateSignRequests($registrations);
        $this->assertIsArray($signRequests);
        $this->assertCount(count($registrations), $signRequests);
        $firstRequest = $signRequests[0];
        foreach ($signRequests as $signRequest) {
            $this->assertInstanceOf(SignRequest::class, $signRequest);
            $this->assertSame(
                $firstRequest->getChallenge(),
                $signRequest->getChallenge(),
                'All sign requests should share a single challenge'
            );
        }
    }

    /**
     * @deprecated
     */
    public function testSetRegisterRequestReturnsSelf(): void
    {
        $req = $this->getDefaultRegisterRequest();
        $this->assertSame(
            $this->server,
            $this->server->setRegisterRequest($req),
            'setRegisterRequest did not return $this'
        );
    }

    /**
     * @deprecated
     */
    public function testSetRegistrationsReturnsSelf(): void
    {
        $reg = $this->getDefaultRegistration();
        $this->assertSame(
            $this->server,
            $this->server->setRegistrations([$reg]),
            'setRegistrations did not return $this'
        );
    }

    public function testSetRegistrationsEnforcesTypeCheck(): void
    {
        $wrong = true;
        $this->expectException(TypeError::class);
        // @phpstan-ignore-next-line
        $this->server->setRegistrations([$wrong]);
    }

    /**
     * @deprecated
     */
    public function testSetSignRequestsReturnsSelf(): void
    {
        $req = $this->getDefaultSignRequest();
        $this->assertSame(
            $this->server,
            $this->server->setSignRequests([$req]),
            'setSignRequests did not return $this'
        );
    }

    public function testSetSignRequestsEnforcesTypeCheck(): void
    {
        $wrong = true;
        $this->expectException(TypeError::class);
        // @phpstan-ignore-next-line
        $this->server->setSignRequests([$wrong]);
    }

    // -( Registration )-------------------------------------------------------

    /**
     * @deprecated
     */
    public function testRegisterThrowsIfNoRegistrationRequestProvided(): void
    {
        $this->expectException(BadMethodCallException::class);
        $this->server->register($this->getDefaultRegisterResponse());
    }

    /**
     * @deprecated
     */
    public function testLegacyRegistration(): void
    {
        $request = $this->getDefaultRegisterRequest();
        $response = $this->getDefaultRegisterResponse();
        $registration = $this->server->setRegisterRequest($request)
            ->register($response);

        $this->assertInstanceOf(
            RegistrationInterface::class,
            $registration,
            'Server->register did not return a registration'
        );
        $this->assertSame(
            0,
            $registration->getCounter(),
            'Counter should start at 0'
        );

        $this->assertSame(
            $response->getAttestationCertificate()->getBinary(),
            $registration->getAttestationCertificate()->getBinary(),
            'Attestation cert was not copied from response'
        );

        $this->assertSame(
            $response->getKeyHandleBinary(),
            $registration->getKeyHandleBinary(),
            'Key handle was not copied from response'
        );

        $this->assertSame(
            $response->getPublicKey()->getBinary(),
            $registration->getPublicKey()->getBinary(),
            'Public key was not copied from response'
        );
    }

    public function testRegistration(): void
    {
        $challenge = $this->getDefaultRegistrationChallenge();
        $response = $this->getDefaultRegistrationResponse();

        $registration = $this->server
            ->validateRegistration($challenge, $response);
        $this->assertInstanceOf(
            RegistrationInterface::class,
            $registration,
            'Server->register did not return a registration'
        );
        $this->assertSame(
            0,
            $registration->getCounter(),
            'Counter should start at 0'
        );

        $this->assertSame(
            $response->getAttestationCertificate()->getBinary(),
            $registration->getAttestationCertificate()->getBinary(),
            'Attestation cert was not copied from response'
        );

        $this->assertSame(
            $response->getKeyHandleBinary(),
            $registration->getKeyHandleBinary(),
            'Key handle was not copied from response'
        );

        $this->assertSame(
            $response->getPublicKey()->getBinary(),
            $registration->getPublicKey()->getBinary(),
            'Public key was not copied from response'
        );
    }

    public function testRegisterDefaultsToTryingEmptyCAList(): void
    {
        $challenge = $this->getDefaultRegistrationChallenge();
        $response = $this->getDefaultRegistrationResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::NO_TRUSTED_CA);
        // Should have CA verification enabled by default with an empty list,
        // meaning that an exception should be thrown unless either a)
        // a matching CA is provided or b) verification is explicitly disabled
        $server = new Server(self::APP_ID);
        $server->validateRegistration($challenge, $response);
    }

    public function testRegisterThrowsIfChallengeDoesNotMatch(): void
    {
        $challenge = $this->getDefaultRegistrationChallenge();
        $response = $this->getDefaultRegistrationResponse([
            'getChallenge' => 'some-other-challenge',
        ]);

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::CHALLENGE_MISMATCH);
        $this->server->validateRegistration($challenge, $response);
    }

    public function testRegisterThrowsIfChallengeDoesNotMatchInverse(): void
    {
        $challenge = new Challenge('some-other-challenge');
        $response = $this->getDefaultRegistrationResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::CHALLENGE_MISMATCH);
        $this->server->validateRegistration($challenge, $response);
    }

    public function testRegisterThrowsWithUntrustedDeviceIssuerCertificate(): void
    {
        $challenge = $this->getDefaultRegistrationChallenge();
        $response = $this->getDefaultRegistrationResponse();

        $this->server->setTrustedCAs([
            // This is a valid root CA, but not one that will verify the
            // device's attestation certificate.
            __DIR__.'/verisign_only_for_unit_tests.pem',
        ]);
        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::NO_TRUSTED_CA);
        $this->server->validateRegistration($challenge, $response);
    }

    public function testRegisterWorksWithCAList(): void
    {
        $challenge = $this->getDefaultRegistrationChallenge();
        $response = $this->getDefaultRegistrationResponse();
        // This contains the actual trusted + verified certificates which are
        // good to use in production. The messages in these tests were
        // generated with a YubiCo device and separately tested against
        // a different reference implementation.
        $CAs = glob(dirname(__DIR__).'/CAcerts/*.pem');
        assert($CAs !== false);
        $this->server->setTrustedCAs($CAs);

        try {
            $reg = $this->server->validateRegistration($challenge, $response);
        } catch (SecurityException $e) {
            if ($e->getCode() === SecurityException::NO_TRUSTED_CA) {
                $this->fail('CA Verification should have succeeded');
            }
            throw $e;
        }
        $this->assertInstanceOf(RegistrationInterface::class, $reg);
    }

    public function testRegisterThrowsWithChangedApplicationParameter(): void
    {
        $challenge = $this->getDefaultRegistrationChallenge();
        $response = $this->getDefaultRegistrationResponse([
            'getRpIdHash' => hash('sha256', 'https://some.otherdomain.com', true),
        ]);

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::WRONG_RELYING_PARTY);
        $this->server->validateRegistration($challenge, $response);
    }

    public function testRegisterThrowsWithChangedSignedData(): void
    {
        $challenge = $this->getDefaultRegistrationChallenge();
        $response = $this->getDefaultRegistrationResponse([
            'getSignedData' => 'value changed',
        ]);

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server->validateRegistration($challenge, $response);
    }

    public function testRegisterThrowsWithBadSignature(): void
    {
        $challenge = $this->getDefaultRegistrationChallenge();
        $response = $this->getDefaultRegistrationResponse([
            'getSignature' => 'value changed',
        ]);

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server->validateRegistration($challenge, $response);
    }

    // -( Authentication )-----------------------------------------------------

    /**
     * @deprecated
     */
    public function testAuthenticateThrowsIfNoRegistrationsPresent(): void
    {
        $this->server->setSignRequests([$this->getDefaultSignRequest()]);
        $this->expectException(BadMethodCallException::class);
        $this->server->authenticate($this->getDefaultSignResponse());
    }

    /**
     * @deprecated
     */
    public function testAuthenticateThrowsIfNoSignRequestsPresent(): void
    {
        $this->server->setRegistrations([$this->getDefaultRegistration()]);
        $this->expectException(BadMethodCallException::class);
        $this->server->authenticate($this->getDefaultSignResponse());
    }

    /**
     * @deprecated
     */
    public function testLegacyAuthenticate(): void
    {
        // All normal
        $registration = $this->getDefaultRegistration();
        $request = $this->getDefaultSignRequest();
        $response = $this->getDefaultSignResponse();

        $return = $this->server
            ->setRegistrations([$registration])
            ->setSignRequests([$request])
            ->authenticate($response);
        $this->assertInstanceOf(
            RegistrationInterface::class,
            $return,
            'A successful authentication should have returned an object '.
            'implementing RegistrationInterface'
        );
        $this->assertNotSame(
            $registration,
            $return,
            'A new object implementing RegistrationInterface should have been '.
            'returned'
        );
        $this->assertSame(
            $response->getCounter(),
            $return->getCounter(),
            'The new registration\'s counter did not match the Response'
        );
    }

    public function testValidateLogin(): void
    {
        // All normal
        $registration = $this->getDefaultRegistration();
        $challenge = $this->getDefaultLoginChallenge();
        $response = $this->getDefaultLoginResponse();

        $updated = $this->server->validateLogin($challenge, $response, [$registration]);
        $this->assertInstanceOf(
            RegistrationInterface::class,
            $updated,
            'A successful authentication should have registrationed an object '.
            'implementing RegistrationInterface'
        );
        $this->assertNotSame(
            $registration,
            $updated,
            'A new object implementing RegistrationInterface should have been '.
            'returned'
        );
        $this->assertSame(
            $response->getCounter(),
            $updated->getCounter(),
            'The new registration\'s counter did not match the Response'
        );
    }

    /**
     * This tries to authenticate with a used response immediately following
     * its successful use.
     */
    public function testValidateLoginThrowsWithObviousReplayAttack(): void
    {
        // All normal
        $registration = $this->getDefaultRegistration();
        $challenge = $this->getDefaultLoginChallenge();
        $response = $this->getDefaultLoginResponse();

        $updatedRegistration = $this->server->validateLogin($challenge, $response, [$registration]);
        // Here is where you would persist $updatedRegistration to update the
        // stored counter value. This simulates fetching that updated value and
        // trying to authenticate with it. Uses a completely new Server
        // instances to fully simulate a new request. The available sign
        // requests should also be cleared from the session by now, but this is
        // a worst-case scenario.
        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::COUNTER_USED);
        $this->server->validateLogin($challenge, $response, [$updatedRegistration]);
    }

    public function testValidateLoginThrowsWhenCounterGoesBackwards(): void
    {
        // Counter from "DB" bumped, suggesting response was cloned
        $registration = $this->getDefaultRegistration([
            'counter' => 82,
        ]);
        $challenge = $this->getDefaultLoginChallenge();
        $response = $this->getDefaultLoginResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::COUNTER_USED);
        $this->server->validateLogin($challenge, $response, [$registration]);
    }

    public function testValidateLoginThrowsWhenChallengeDoesNotMatch(): void
    {
        $registration = $this->getDefaultRegistration();
        // Change request challenge
        $challenge = new Challenge('some-other-challenge');
        $response = $this->getDefaultLoginResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::CHALLENGE_MISMATCH);
        $this->server->validateLogin($challenge, $response, [$registration]);
    }

    public function testValidateLoginThrowsIfNoRegistrationMatchesKeyHandle(): void
    {
        // Change registration KH
        $registration = $this->getDefaultRegistration([
            'keyHandle' => 'some-other-key-handle',
        ]);
        $challenge = $this->getDefaultLoginChallenge();
        $response = $this->getDefaultLoginResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::KEY_HANDLE_UNRECOGNIZED);
        $this->server->validateLogin($challenge, $response, [$registration]);
    }

    /**
     * @deprecated
     */
    public function testAuthenticateThrowsIfNoRequestMatchesKeyHandle(): void
    {
        $registration = $this->getDefaultRegistration();
        // Change request KH
        $request = (new SignRequest())
            ->setAppId('https://u2f.ericstern.com')
            ->setChallenge('wt2ze8IskcTO3nIsO2D2hFjE5tVD041NpnYesLpJweg')
            ->setKeyHandle(fromBase64Web('some-other-key-handle'))
            ;
        $response = $this->getDefaultSignResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::KEY_HANDLE_UNRECOGNIZED);
        $this->server
            ->setRegistrations([$registration])
            ->setSignRequests([$request])
            ->authenticate($response);
    }

    public function testValidateLoginThrowsIfSignatureIsInvalid(): void
    {
        $challenge = $this->getDefaultLoginChallenge();
        $response = $this->getDefaultLoginResponse([
            'getSignature' => 'some-other-signature',
        ]);
        $registration = $this->getDefaultRegistration();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server->validateLogin($challenge, $response, [$registration]);
    }

    public function testValidateLoginThrowsIfWrongDataIsSigned(): void
    {
        $challenge = $this->getDefaultLoginChallenge();
        $response = $this->getDefaultLoginResponse([
            'getSignedData' => 'some other signed data',
        ]);
        $registration = $this->getDefaultRegistration();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server->validateLogin($challenge, $response, [$registration]);
    }

    /**
     * Arguably the most important authentication test: ensure that
     * a perfectly-valid signature is rejected if it's not actually from the
     * registered keypair.
     */
    public function testValidateLoginThrowsIfRequestIsSignedWithWrongKey(): void
    {
        // This was a different key genearated with:
        // $ openssl ecparam -name prime256v1 -genkey -out private.pem
        // $ openssl ec -in private.pem -pubout -out public.pem
        // Then taking the trailing 65 bytes of the base64-decoded value (the
        // leading bytes are formatting; see ECPublicKeyTrait)
        $pk = base64_decode(
            'BCXk9bGiuzLRJaX6pFONm+twgIrDkOSNDdXgltt+KhOD'.
            '9OxeRv2zYiz7SrVa8eb4LbGR9IDUE7gJySiiuQYWt1w='
        );
        assert($pk !== false);
        $registration = $this->getDefaultRegistration([
            'publicKey' => new ECPublicKey($pk),
        ]);
        $challenge = $this->getDefaultLoginChallenge();
        $response = $this->getDefaultLoginResponse();
        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server->validateLogin($challenge, $response, [$registration]);
    }

    // -( Alternate formats (see #14) )----------------------------------------

    /**
     * @deprecated
     */
    public function testRegistrationWithoutCidPubkeyBug14Case1(): void
    {
        $registerRequest = new RegisterRequest();
        $registerRequest->setAppId($this->server->getAppId())
            ->setChallenge('dNqjowssvlxx9zBhvsy03A');

        $json = '{"registrationData":"BQSFDYsZaHlRBQcdLyu4jZ-Bukb1vw6QtSfmvTQO'.
            'IXpjZpfqYptdtpBznuNBslzlZdodspfqRkqwJIt3a0W2P_HlQImHG1FoSkYdPwSzp'.
            '3WvlDisShW5fveiaaI4Zk8oZBkyWoQ6v1c2ypcd5OWPX6rAH-N7cPjw1Vg_w1q_YL'.
            'c3mR8wggE0MIHboAMCAQICCjJ1rwmwx867ew8wCgYIKoZIzj0EAwIwFTETMBEGA1U'.
            'EAxMKVTJGIElzc3VlcjAaFwswMDAxMDEwMDAwWhcLMDAwMTAxMDAwMFowFTETMBEG'.
            'A1UEAxMKVTJGIERldmljZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCLzJT4vt'.
            'kl-799Ks5wINHdVRIKCLq-kX6oIajh_2Dv4Sk0cBVteQt1xdGau1XzEaGYIOvU5hU'.
            'm2J2pxVBQIzaajFzAVMBMGCysGAQQBguUcAgEBBAQDAgUgMAoGCCqGSM49BAMCA0g'.
            'AMEUCIQDBo6aOLxanIUYnBX9iu3KMngPnobpi0EZSTkVtLC8_cwIgC1945RGqGBKf'.
            'byNtkhMifZK05n7fU-gW37Bdnci5D94wRQIgEPJVWZ7zgVQUctG3xpWBv77s3u2R7'.
            'OJP-UjkWdcUs2QCIQC1fqlZIrl4kIEsSQTRMauvcaoeunV-I24WYnp3rgC_Dg","v'.
            'ersion":"U2F_V2","challenge":"dNqjowssvlxx9zBhvsy03A","appId":"ht'.
            'tps://u2f.ericstern.com","clientData":"eyJjaGFsbGVuZ2UiOiJkTnFqb3'.
            'dzc3ZseHg5ekJodnN5MDNBIiwib3JpZ2luIjoiaHR0cHM6Ly91MmYuZXJpY3N0ZXJ'.
            'uLmNvbSIsInR5cCI6Im5hdmlnYXRvci5pZC5maW5pc2hFbnJvbGxtZW50In0"}';
        $registerResponse = RegisterResponse::fromJson($json);

        $registration = $this->server->validateRegistration($registerRequest, $registerResponse);
        $this->assertInstanceOf(Registration::class, $registration);
    }

    /**
     * @deprecated
     */
    public function testRegistrationWithoutCidPubkeyBug14Case2(): void
    {
        $registerRequest = new RegisterRequest();
        $registerRequest->setAppId($this->server->getAppId())
            ->setChallenge('E23usdC7VkxjN1mwRAeyjg');

        $json = '{"registrationData":"BQSTffB-e9hdFwhsfb2t-2ppwyxZAltnDf6TYwv4'.
            '1VtleEO4488JwNFGr_bks_4EzA4DoluDBCgfmULGpZpXykTZQMOMz9DfbESHnuBY9'.
            'cmTxVTVtrsTFTQA-IPETCYJ2dYACULXRN7_qLq_2WnDQJaME7zWyZEB0NFu-hosav'.
            'uqjncwggEbMIHCoAMCAQICCiIygbKxS2KpYY8wCgYIKoZIzj0EAwIwFTETMBEGA1U'.
            'EAxMKVTJGIElzc3VlcjAaFwswMDAxMDEwMDAwWhcLMDAwMTAxMDAwMFowFTETMBEG'.
            'A1UEAxMKVTJGIERldmljZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCdqjfpHR'.
            '9L8a6-pVRv9PWu-pORC9sO9eDk6ZlFIXaclyfxbLJqAehvIWJuzij_BxJOLbQPD_9'.
            'fX5uKh9tDv8nowCgYIKoZIzj0EAwIDSAAwRQIhAMGjpo4vFqchRicFf2K7coyeA-e'.
            'humLQRlJORW0sLz9zAiALX3jlEaoYEp9vI22SEyJ9krTmft9T6BbfsF2dyLkP3jBE'.
            'AiAHD70-wA4f3SZk6s0RocHAA4nDCGaVFvTBG4gZXcZTnQIge2joenpQxVP0r1o9E'.
            'zL9C3aR-HEKhSHr86MX4eUTMlw","version":"U2F_V2","challenge":"E23us'.
            'dC7VkxjN1mwRAeyjg","appId":"https://u2f.ericstern.com","clientDat'.
            'a":"eyJjaGFsbGVuZ2UiOiJFMjN1c2RDN1ZreGpOMW13UkFleWpnIiwib3JpZ2luI'.
            'joiaHR0cHM6Ly91MmYuZXJpY3N0ZXJuLmNvbSIsInR5cCI6Im5hdmlnYXRvci5pZC'.
            '5maW5pc2hFbnJvbGxtZW50In0"}';
        $registerResponse = RegisterResponse::fromJson($json);

        $registration = $this->server->validateRegistration($registerRequest, $registerResponse);
        $this->assertInstanceOf(Registration::class, $registration);
    }

    // -( Helpers )------------------------------------------------------------

    /**
     * @deprecated
     */
    private function getDefaultRegisterRequest(): RegisterRequest
    {
        // This would have come from a session, database, etc.
        return (new RegisterRequest())
            ->setAppId('https://u2f.ericstern.com')
            ->setChallenge('PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo');
    }

    private function getDefaultRegistrationChallenge(): ChallengeProviderInterface
    {
        return new Challenge('PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo');
    }

    /**
     * @deprecated
     */
    private function getDefaultRegisterResponse(): RegisterResponse
    {
        return RegisterResponse::fromJson($this->safeReadFile('register_response.json'));
    }

    /**
     * @param array{
     *   getAttestationCertificate?: AttestationCertificateInterface,
     *   getChallenge?: string,
     *   getKeyHandleBinary?: string,
     *   getPublicKey?: PublicKeyInterface,
     *   getRpIdHash?: string,
     *   getSignature?: string,
     *   getSignedData?: string,
     * } $overrides
     */
    private function getDefaultRegistrationResponse(array $overrides = []): RegistrationResponseInterface
    {
        // This data was manually extracted from an actual key exchange. It
        // does NOT correspond to the values from getDefaultLoginResponse().
        $keyHandleBinary = hex2bin(
            '6d4a7a7393fa51cf24dbe035f26cacc9868a9385320a099b17062ac0ddc11fc0'.
            '0cb96b1a8fffe4736b7144c508fc343af81c104ba25e086ee5c1ba71da0c7d6d'
        );
        // @phpstan-ignore-next-line
        $pk = new ECPublicKey(hex2bin(
            '04'.
            '43e68d1b03d1f9558d77c5a308163be26ab1b8778692b6282b4c6f023e5bd298'.
            'f4028967599eeaec31609df19d34546fc7eba72c23f78bc9d75ac63eebd52d09'
        ));
        $signature = hex2bin(
            '304402207646e5d330cb99cd86fddd67029bdb4c1d128146e4f70a046c5953ab'.
            '64a40a6a0220683fa0c3bb1f6328f7ace7b00894e7dcd6d735474ac7ea517d3b'.
            '2b441ebc95e4'
        );

        $challengeParamaeterJson = '{"typ":"navigator.id.finishEnrollment","c'.
            'hallenge":"PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo","origin"'.
            ':"https://u2f.ericstern.com","cid_pubkey":""}';
        $signedData = sprintf(
            '%s%s%s%s%s',
            chr(0),
            hash('sha256', 'https://u2f.ericstern.com', true),
            hash('sha256', $challengeParamaeterJson, true),
            $keyHandleBinary,
            $pk->getBinary()
        );
        $defaults = [
            'getAttestationCertificate' => $this->getDefaultAttestationCertificate(),
            'getChallenge' => 'PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo', // getDefaultRegistrationChallenge
            'getKeyHandleBinary' => $keyHandleBinary,
            'getPublicKey' => $pk,
            'getRpIdHash' => hash('sha256', 'https://u2f.ericstern.com', true),
            'getSignature' => $signature,
            'getSignedData' => $signedData,
        ];

        $data = array_merge($defaults, $overrides);

        $mock = self::createMock(RegistrationResponseInterface::class);
        foreach ($data as $method => $value) {
            $mock->method($method)->willReturn($value);
        }
        return $mock;
    }

    /**
     * @deprecated
     */
    private function getDefaultSignRequest(): SignRequest
    {
        // This would have come from a session, database, etc
        return (new SignRequest())
            ->setAppId('https://u2f.ericstern.com')
            ->setChallenge('wt2ze8IskcTO3nIsO2D2hFjE5tVD041NpnYesLpJweg')
            ->setKeyHandle(fromBase64Web(self::ENCODED_KEY_HANDLE))
            ;
    }

    private function getDefaultLoginChallenge(): ChallengeProviderInterface
    {
        return new Challenge('wt2ze8IskcTO3nIsO2D2hFjE5tVD041NpnYesLpJweg');
    }

    /**
     * @param array{
     *   counter?: int,
     *   keyHandle?: string,
     *   publicKey?: PublicKeyInterface,
     * } $overrides
     */
    private function getDefaultRegistration(array $overrides = []): RegistrationInterface
    {
        $defaults = [
            'counter' => 2,
            'keyHandle' => fromBase64Web(self::ENCODED_KEY_HANDLE),
            'publicKey' => $this->getDefaultPublicKey(),
        ];
        /**
         * @var array{
         *   counter: int,
         *   keyHandle: string,
         *   publicKey: PublicKeyInterface,
         * } (phpstan/phpstan#5846)
         */
        $data = array_merge($defaults, $overrides);
        // From database attached to the authenticating user
        return  (new Registration())
            ->setKeyHandle($data['keyHandle'])
            ->setAttestationCertificate($this->getDefaultAttestationCertificate())
            ->setPublicKey($data['publicKey'])
            ->setCounter($data['counter'])
            ;
    }

    /**
     * @param array{
     *   getChallenge?: string,
     *   getCounter?: int,
     *   getKeyHandleBinary?: string,
     *   getSignature?: string,
     *   getSignedData?: string,
     * } $overrides
     */
    private function getDefaultLoginResponse(array $overrides = []): LoginResponseInterface
    {
        // This data was manually extracted from an actual key exchange. It
        // does NOT correspond to the values from
        // getDefaultRegistrationResponse().
        $keyHandleBinary = hex2bin(
            '2549d54d2b4f9fe576f9b0aed1196f3dbba40691d30f9322d591a094339c374b'.
            'c3e39ae74c3d015dd911b7bf21b93c09eed55ac53a927ad1e3af6dad0a39982d'
        );
        $signature = hex2bin(
            '304602210093f2d51bc3d560b0d57657e77057c9d5ff2b27ff5d942e7854883e'.
            '281117e0f6022100c776c9af98b1ad719d517d57a2801f873d7964863cac2e47'.
            'e2a696ee042ca49e'
        );
        $challengeParamaeterJson = '{"typ":"navigator.id.getAssertion","chall'.
            'enge":"wt2ze8IskcTO3nIsO2D2hFjE5tVD041NpnYesLpJweg","origin":"ht'.
            'tps://u2f.ericstern.com","cid_pubkey":""}';
        $signedData = sprintf(
            '%s%s%s%s',
            hash('sha256', 'https://u2f.ericstern.com', true),
            chr(1),
            pack('N', 45),
            hash('sha256', $challengeParamaeterJson, true)
        );

        $defaults = [
            'getChallenge' => 'wt2ze8IskcTO3nIsO2D2hFjE5tVD041NpnYesLpJweg', // getDefaultLoginChallenge
            'getCounter' => 45,
            'getKeyHandleBinary' => $keyHandleBinary,
            'getSignature' => $signature,
            'getSignedData' => $signedData,
        ];
        $data = array_merge($defaults, $overrides);
        $mock = self::createMock(LoginResponseInterface::class);
        foreach ($data as $method => $result) {
            $mock->method($method)->willReturn($result);
        }
        return $mock;
    }

    /**
     * @deprecated
     */
    private function getDefaultSignResponse(): SignResponse
    {
        // Value from user
        return SignResponse::fromJson($this->safeReadFile('sign_response.json'));
    }

    private function getDefaultAttestationCertificate(): AttestationCertificateInterface
    {
        $attest = hex2bin(
            '3082022d30820117a003020102020405b60579300b06092a864886f70d01010b'.
            '302e312c302a0603550403132359756269636f2055324620526f6f7420434120'.
            '53657269616c203435373230303633313020170d313430383031303030303030'.
            '5a180f32303530303930343030303030305a30283126302406035504030c1d59'.
            '756269636f205532462045452053657269616c20393538313530333330593013'.
            '06072a8648ce3d020106082a8648ce3d03010703420004fdb8deb3a1ed70eb63'.
            '6c066eb6006996a5f970fcb5db88fc3b305d41e5966f0c1b54b852fef0a0907e'.
            'd17f3bffc29d4d321b9cf8a84a2ceaa038cabd35d598dea3263024302206092b'.
            '0601040182c40a020415312e332e362e312e342e312e34313438322e312e3130'.
            '0b06092a864886f70d01010b03820101007ed3fb6ccc252013f82f218c2a37da'.
            '6031d20e7f3081dafcaeb128fc7f9b233914bfb64d6135f17ce221fa764f453e'.
            'f1273a8ce965956442bb2f1e47483f737dcbc98b585377fef50b270e0289f884'.
            '36f1adcf49b2621ee5e302df555b9ab74272e069f918149b3dec4f12228b10c0'.
            'f88de36af58a74bb442b85ae005364bda6702058fc1f2d879b530111ea60e86c'.
            '63f17fa5944cc83f0aa269848b3ee388a6c09e6b05953fcbb8f47e83a27e0072'.
            'a63c32ad64864e926d7112fa1997f7839656fbb32be8f7889d0f0145519a27af'.
            'dd8e46b04ca4290d8540b634b886161e7588c86299dcdd6435d1678a3a6f0a74'.
            '829c4dd3f70c3524d1ddf16d78add21b64'
        );
        assert($attest !== false);
        return new AttestationCertificate($attest);
    }

    public function getDefaultPublicKey(): PublicKeyInterface
    {
        $pk = base64_decode(self::ENCODED_PUBLIC_KEY);
        assert($pk !== false);
        return new ECPublicKey($pk);
    }

    private function safeReadFile(string $file): string
    {
        $body = file_get_contents(__DIR__.'/'.$file);
        assert($body !== false);
        return $body;
    }
}
