<?php

namespace Firehed\U2F;

use BadMethodCallException;
use TypeError;

/**
 * @coversDefaultClass Firehed\U2F\Server
 * @covers ::<protected>
 * @covers ::<private>
 */
class ServerTest extends \PHPUnit_Framework_TestCase
{
    const APP_ID = 'https://u2f.example.com';
    const ENCODED_KEY_HANDLE = 'JUnVTStPn-V2-bCu0RlvPbukBpHTD5Mi1ZGglDOcN0vD45rnTD0BXdkRt78huTwJ7tVaxTqSetHjr22tCjmYLQ';
    const ENCODED_PUBLIC_KEY = 'BEyIn4ldTViNAgceMA/YgRX1DlJR3bSF39drG44Fx1E2LaF9Md9RUN2CHyfzSokIjjCHP8jMsTYwdt0tKe6qLzc=';

    private $server;

    public function setUp() {
        $this->server = (new Server())
            ->disableCAVerification()
            ->setAppId(self::APP_ID);
    }

    /**
     * @covers ::disableCAVerification
     */
    public function testDisableCAVerificationReturnsSelf() {
        $server = new Server();
        $this->assertSame($server, $server->disableCAVerification(),
            'disableCAVerification did not return $this');
    }

    /**
     * @covers ::generateRegisterRequest
     */
    public function testGenerateRegisterRequest() {
        $req = $this->server->generateRegisterRequest();
        $this->assertInstanceOf(RegisterRequest::class, $req);
        $this->assertSame(self::APP_ID, $req->getAppId(),
            'RegisterRequest App ID was not the value from the server');
        $this->assertNotEmpty($req->getChallenge(),
            'No challenge value was set');
        $this->assertTrue(strlen($req->getChallenge()) >= 8,
            'Challenge was less than 8 bytes long, violating the spec');
    }

    /**
     * @covers ::generateSignRequest
     */
    public function testGenerateSignRequest() {
        $kh = \random_bytes(16);
        $registration = (new Registration())
            ->setKeyHandle($kh);
        $req = $this->server->generateSignRequest($registration);

        $this->assertInstanceOf(SignRequest::class, $req);
        $this->assertSame($kh, $req->getKeyHandleBinary(),
            'Key handle was not set correctly');
        $this->assertSame(self::APP_ID, $req->getAppId(),
            'SignRequest App ID was not the value form the server');
        $this->assertNotEmpty($req->getChallenge(),
            'No challenge value was set');
        $this->assertTrue(strlen($req->getChallenge()) >= 8,
            'Challenge was less than 8 bytes long, violating the spec');
    }

    /**
     * @covers ::setRegisterRequest
     */
    public function testSetRegisterRequestReturnsSelf() {
        $req = $this->getDefaultRegisterRequest();
        $this->assertSame($this->server,
            $this->server->setRegisterRequest($req),
            'setRegisterRequest did not return $this');
    }

    /**
     * @covers ::setRegistrations
     */
    public function testSetRegistrationsReturnsSelf() {
        $reg = $this->getDefaultRegistration();
        $this->assertSame($this->server,
            $this->server->setRegistrations([$reg]),
            'setRegistrations did not return $this');
    }

    /**
     * @covers ::setRegistrations
     */
    public function testSetRegistrationsEnforcesTypeCheck() {
        $wrong = true;
        $this->expectException(TypeError::class);
        $this->server->setRegistrations([$wrong]);
    }

    /**
     * @covers ::setSignRequests
     */
    public function testSetSignRequestsReturnsSelf() {
        $req = $this->getDefaultSignRequest();
        $this->assertSame($this->server,
            $this->server->setSignRequests([$req]),
            'setSignRequests did not return $this');
    }

    /**
     * @covers ::setSignRequests
     */
    public function testSetSignRequestsEnforcesTypeCheck() {
        $wrong = true;
        $this->expectException(TypeError::class);
        $this->server->setSignRequests([$wrong]);
    }

    // -( Registration )-------------------------------------------------------

    /**
     * @covers ::register
     */
    public function testRegisterThrowsIfNoRegistrationRequestProvided() {
        $this->expectException(BadMethodCallException::class);
        $this->server->register($this->getDefaultRegisterResponse());
    }

    /**
     * @covers ::register
     */
    public function testRegistration() {
        $request = $this->getDefaultRegisterRequest();
        $response = $this->getDefaultRegisterResponse();

        $registration = $this->server
            ->setRegisterRequest($request)
            ->register($response);
        $this->assertInstanceOf(Registration::class, $registration,
            'Server->register did not return a registration');
        $this->assertSame(0, $registration->getCounter(),
            'Counter should start at 0');

        $this->assertSame($response->getAttestationCertificateBinary(),
            $registration->getAttestationCertificateBinary(),
            'Attestation cert was not copied from response');

        $this->assertSame($response->getKeyHandleBinary(),
            $registration->getKeyHandleBinary(),
            'Key handle was not copied from response');

        $this->assertSame($response->getPublicKey(),
            $registration->getPublicKey(),
            'Public key was not copied from response');
    }

    /**
     * @covers ::register
     */
    public function testRegisterDefaultsToTryingEmptyCAList() {
        $request = $this->getDefaultRegisterRequest();
        $response = $this->getDefaultRegisterResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::NO_TRUSTED_CA);
        // Should have CA verification enabled by default with an empty list,
        // meaning that an exception should be thrown unless either a)
        // a matching CA is provided or b) verification is explicitly disabled
        $server = (new Server())->setAppId(self::APP_ID);
        $server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsIfChallengeDoesNotMatch() {
        // This would have come from a session, database, etc.
        $request = (new RegisterRequest())
            ->setAppId('https://u2f.ericstern.com')
            ->setChallenge('some-other-challenge');
        $response = $this->getDefaultRegisterResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::CHALLENGE_MISMATCH);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithUntrustedDeviceIssuerCertificate() {
        $request = $this->getDefaultRegisterRequest();
        $response = $this->getDefaultRegisterResponse();

        $this->server->setTrustedCAs([
            // This is a valid root CA, but not one that will verify the
            // device's attestation certificate.
            __DIR__.'/verisign_only_for_unit_tests.pem',
        ]);
        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::NO_TRUSTED_CA);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     * @covers ::setTrustedCAs
     */
    public function testRegisterWorksWithCAList() {
        $request = $this->getDefaultRegisterRequest();
        $response = $this->getDefaultRegisterResponse();
        // This contains the actual trusted + verified certificates which are
        // good to use in production. The messages in these tests were
        // generated with a YubiCo device and separately tested against
        // a different reference implementation.
        $CAs = glob(dirname(__DIR__).'/CAcerts/*.pem');
        $this->server->setTrustedCAs($CAs);

        try {
            $this->server
                ->setRegisterRequest($request)
                ->register($response);
        } catch (SecurityException $e) {
            if ($e->getCode() === SecurityException::NO_TRUSTED_CA) {
                $this->fail('CA Verification should have succeeded');
            }
            throw $e;
        }
        // Implicit pass - no exceptions should be thrown at all
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithChangedApplicationParameter() {
        $request = (new RegisterRequest())
            ->setAppId('https://not.my.u2f.example.com')
            ->setChallenge('PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo');

        $response = $this->getDefaultRegisterResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithChangedChallengeParameter() {
        $request = $this->getDefaultRegisterRequest();
        // Mess up some known-good data: challenge parameter
        $json = file_get_contents(__DIR__.'/register_response.json');
        $data = json_decode($json, true);
        $cli = fromBase64Web($data['clientData']);
        $obj = json_decode($cli, true);
        $obj['origin'] = 'https://not.my.u2f.example.com';
        $cli = toBase64Web(json_encode($obj));
        $data['clientData'] = $cli;
        $response = RegisterResponse::fromJson(json_encode($data));

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithChangedKeyHandle() {
        $request = $this->getDefaultRegisterRequest();
        // Mess up some known-good data: key handle
        $json = file_get_contents(__DIR__.'/register_response.json');
        $data = json_decode($json, true);
        $reg = $data['registrationData'];
        $reg[70] = $reg[70] ^ 0xFF; // Invert a byte in the key handle
        $data['registrationData'] = $reg;
        $response = RegisterResponse::fromJson(json_encode($data));

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithChangedPubkey() {
        $request = $this->getDefaultRegisterRequest();
        // Mess up some known-good data: public key
        $json = file_get_contents(__DIR__.'/register_response.json');
        $data = json_decode($json, true);
        $reg = $data['registrationData'];
        $reg[3] = $reg[3] ^ 0xFF; // Invert a byte in the public key
        $data['registrationData'] = $reg;
        $response = RegisterResponse::fromJson(json_encode($data));

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithBadSignature() {
        $request = $this->getDefaultRegisterRequest();
        // Mess up some known-good data: signature
        $json = file_get_contents(__DIR__.'/register_response.json');
        $data = json_decode($json, true);
        $reg = $data['registrationData'];
        $last = str_rot13(substr($reg, -5)); // rot13 a few chars in signature
        $data['registrationData'] = substr($reg,0,-5).$last;
        $response = RegisterResponse::fromJson(json_encode($data));

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    // -( Authentication )-----------------------------------------------------

    /**
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsIfNoRegistrationsPresent() {
        $this->server->setSignRequests([$this->getDefaultSignRequest()]);
        $this->expectException(BadMethodCallException::class);
        $this->server->authenticate($this->getDefaultSignResponse());
    }

    /**
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsIfNoSignRequestsPresent() {
        $this->server->setRegistrations([$this->getDefaultRegistration()]);
        $this->expectException(BadMethodCallException::class);
        $this->server->authenticate($this->getDefaultSignResponse());
    }

    /**
     * @covers ::authenticate
     */
    public function testAuthenticate() {
        // All normal
        $registration = $this->getDefaultRegistration();
        $request = $this->getDefaultSignRequest();
        $response = $this->getDefaultSignResponse();

        $return = $this->server
                ->setRegistrations([$registration])
                ->setSignRequests([$request])
                ->authenticate($response);
        $this->assertInstanceOf(Registration::class, $return,
            'A successful authentication should have returned a Registration');
        $this->assertNotSame($registration, $return,
            'A new instance of Registration should have been returned');
        $this->assertSame($response->getCounter(), $return->getCounter(),
            'The new Registration\'s counter did not match the Response');
    }

    /**
     * Re-run testAuthenticate after ensuring that mbstring.func_overload is
     * being used
     *
     * @coversNothing
     */
    public function testAuthenticateWithMultibyteSettings()
    {
        $overload = ini_get('mbstring.func_overload');
        if ($overload != 7) {
            $cmd = 'php -d mbstring.func_overload=7 '.
                implode(' ', $_SERVER['argv']);
            $this->markTestSkipped(sprintf(
                "mbstring.func_overload cannot be changed at runtime. Re-run ".
                "this test with the following command:\n\n%s",
                $cmd));
        }

        $this->testAuthenticate();
    }

    /**
     * This tries to authenticate with a used response immediately following
     * its successful use.
     *
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsWithObviousReplayAttack() {
        // All normal
        $registration = $this->getDefaultRegistration();
        $request = $this->getDefaultSignRequest();
        $response = $this->getDefaultSignResponse();

        $new_registration = $this->server
                ->setRegistrations([$registration])
                ->setSignRequests([$request])
                ->authenticate($response);
        // Here is where you would persist $new_registration to update the
        // stored counter value. This simulates fetching that updated value and
        // trying to authenticate with it. Uses a completely new Server
        // instances to fully simulate a new request. The available sign
        // requests should also be cleared from the session by now, but this is
        // a worst-case scenario.
        $server = (new Server())
            ->setRegistrations([$new_registration])
            ->setSignRequests([$request]);
        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::COUNTER_USED);
        $server->authenticate($response);
    }

    /**
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsWhenCounterGoesBackwards() {
        // Counter from "DB" bumped, suggesting response was cloned
        $registration = (new Registration())
            ->setKeyHandle(fromBase64Web(self::ENCODED_KEY_HANDLE))
            ->setPublicKey(base64_decode(self::ENCODED_PUBLIC_KEY))
            ->setCounter(82)
            ;
        $request = $this->getDefaultSignRequest();
        $response = $this->getDefaultSignResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::COUNTER_USED);
        $this->server
            ->setRegistrations([$registration])
            ->setSignRequests([$request])
            ->authenticate($response);
    }

     /**
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsWhenChallengeDoesNotMatch() {
        $registration = $this->getDefaultRegistration();
        // Change request challenge
        $request = (new SignRequest())
            ->setAppId('https://u2f.ericstern.com')
            ->setChallenge('some-other-challenge')
            ->setKeyHandle(fromBase64Web(self::ENCODED_KEY_HANDLE))
            ;
        $response = $this->getDefaultSignResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::CHALLENGE_MISMATCH);
        $this->server
            ->setRegistrations([$registration])
            ->setSignRequests([$request])
            ->authenticate($response);
    }

    /**
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsIfNoRegistrationMatchesKeyHandle() {
        // Change registration KH
        $registration = (new Registration())
            ->setKeyHandle(fromBase64Web('some-other-key-handle'))
            ->setPublicKey(base64_decode(self::ENCODED_PUBLIC_KEY))
            ->setCounter(2)
            ;
        $request = $this->getDefaultSignRequest();
        $response = $this->getDefaultSignResponse();

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::KEY_HANDLE_UNRECOGNIZED);
        $this->server
            ->setRegistrations([$registration])
            ->setSignRequests([$request])
            ->authenticate($response);
    }

    /**
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsIfNoRequestMatchesKeyHandle() {
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

    /**
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsIfSignatureIsInvalid() {
        $registration = $this->getDefaultRegistration();
        $request = $this->getDefaultSignRequest();
        // Trimming a byte off the signature to cause a mismatch
        $data = json_decode(
            file_get_contents(__DIR__.'/sign_response.json'),
            true);
        $data['signatureData'] = substr($data['signatureData'], 0, -1);
        $response = SignResponse::fromJson(json_encode($data));

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server
            ->setRegistrations([$registration])
            ->setSignRequests([$request])
            ->authenticate($response);
    }

    /**
     * Arguably the most important authentication test: ensure that
     * a perfectly-valid signature is rejected if it's not actually from the
     * registered keypair.
     *
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsIfRequestIsSignedWithWrongKey() {
        // This was a different key genearated with:
        // $ openssl ecparam -name prime256v1 -genkey -out private.pem
        // $ openssl ec -in private.pem -pubout -out public.pem
        // Then taking the trailing 65 bytes of the base64-decoded value (the
        // leading bytes are formatting; see ECPublicKeyTrait)
        $registration = (new Registration())
            ->setKeyHandle(fromBase64Web(self::ENCODED_KEY_HANDLE))
            ->setPublicKey(base64_decode(
                'BCXk9bGiuzLRJaX6pFONm+twgIrDkOSNDdXgltt+KhOD'.
                '9OxeRv2zYiz7SrVa8eb4LbGR9IDUE7gJySiiuQYWt1w='))
            ->setCounter(2)
            ;
        $request = $this->getDefaultSignRequest();
        $response = $this->getDefaultSignResponse();
        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server
            ->setRegistrations([$registration])
            ->setSignRequests([$request])
            ->authenticate($response);
    }

    // -( Helpers )------------------------------------------------------------

    private function getDefaultRegisterRequest(): RegisterRequest {
        // This would have come from a session, database, etc.
        return (new RegisterRequest())
            ->setAppId('https://u2f.ericstern.com')
            ->setChallenge('PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo');
    }

    private function getDefaultRegisterResponse(): RegisterResponse {
        return RegisterResponse::fromJson(
            file_get_contents(__DIR__.'/register_response.json'));
    }

    private function getDefaultSignRequest(): SignRequest {
        // This would have come from a session, database, etc
        return (new SignRequest())
            ->setAppId('https://u2f.ericstern.com')
            ->setChallenge('wt2ze8IskcTO3nIsO2D2hFjE5tVD041NpnYesLpJweg')
            ->setKeyHandle(fromBase64Web(self::ENCODED_KEY_HANDLE))
            ;
    }

    private function getDefaultRegistration(): Registration {
        // From database attached to the authenticating user
        return  (new Registration())
            ->setKeyHandle(fromBase64Web(self::ENCODED_KEY_HANDLE))
            ->setPublicKey(base64_decode(self::ENCODED_PUBLIC_KEY))
            ->setCounter(2)
            ;
    }

    private function getDefaultSignResponse(): SignResponse {
        // Value from user
        return SignResponse::fromJson(
            file_get_contents(__DIR__.'/sign_response.json'));
    }
}
