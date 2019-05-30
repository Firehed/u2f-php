<?php

namespace Firehed\U2F;

use BadMethodCallException;
use TypeError;

/**
 * @coversDefaultClass Firehed\U2F\Server
 * @covers ::<protected>
 * @covers ::<private>
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

    private $server;

    public function setUp(): void
    {
        $this->server = (new Server())
            ->disableCAVerification()
            ->setAppId(self::APP_ID);
    }

    /**
     * @covers ::__construct
     */
    public function testConstruct()
    {
        $server = new Server();
        $this->assertInstanceOf(Server::class, $server);
    }

    /**
     * @covers ::disableCAVerification
     */
    public function testDisableCAVerificationReturnsSelf()
    {
        $server = new Server();
        $this->assertSame(
            $server,
            $server->disableCAVerification(),
            'disableCAVerification did not return $this'
        );
    }

    /**
     * @covers ::generateRegisterRequest
     */
    public function testGenerateRegisterRequest()
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
     * @covers ::generateSignRequest
     */
    public function testGenerateSignRequest()
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
     * @covers ::generateSignRequests
     */
    public function testGenerateSignRequests()
    {
        $registrations = [
            (new Registration())->setKeyHandle(\random_bytes(16)),
            (new Registration())->setKeyHandle(\random_bytes(16)),
        ];
        $signRequests = $this->server->generateSignRequests($registrations);

        $this->assertIsArray($signRequests);
        foreach ($signRequests as $signRequest) {
            $this->assertInstanceOf(SignRequest::class, $signRequest);
        }
        // This method is a simple map operation, so testGenerateSignRequest
        // does the heavy lifting.
    }

    /**
     * @covers ::setRegisterRequest
     */
    public function testSetRegisterRequestReturnsSelf()
    {
        $req = $this->getDefaultRegisterRequest();
        $this->assertSame(
            $this->server,
            $this->server->setRegisterRequest($req),
            'setRegisterRequest did not return $this'
        );
    }

    /**
     * @covers ::setRegistrations
     */
    public function testSetRegistrationsReturnsSelf()
    {
        $reg = $this->getDefaultRegistration();
        $this->assertSame(
            $this->server,
            $this->server->setRegistrations([$reg]),
            'setRegistrations did not return $this'
        );
    }

    /**
     * @covers ::setRegistrations
     */
    public function testSetRegistrationsEnforcesTypeCheck()
    {
        $wrong = true;
        $this->expectException(TypeError::class);
        $this->server->setRegistrations([$wrong]);
    }

    /**
     * @covers ::setSignRequests
     */
    public function testSetSignRequestsReturnsSelf()
    {
        $req = $this->getDefaultSignRequest();
        $this->assertSame(
            $this->server,
            $this->server->setSignRequests([$req]),
            'setSignRequests did not return $this'
        );
    }

    /**
     * @covers ::setSignRequests
     */
    public function testSetSignRequestsEnforcesTypeCheck()
    {
        $wrong = true;
        $this->expectException(TypeError::class);
        $this->server->setSignRequests([$wrong]);
    }

    // -( Registration )-------------------------------------------------------

    /**
     * @covers ::register
     */
    public function testRegisterThrowsIfNoRegistrationRequestProvided()
    {
        $this->expectException(BadMethodCallException::class);
        $this->server->register($this->getDefaultRegisterResponse());
    }

    /**
     * @covers ::register
     */
    public function testRegistration()
    {
        $request = $this->getDefaultRegisterRequest();
        $response = $this->getDefaultRegisterResponse();

        $registration = $this->server
            ->setRegisterRequest($request)
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

    /**
     * @covers ::register
     */
    public function testRegisterDefaultsToTryingEmptyCAList()
    {
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
    public function testRegisterThrowsIfChallengeDoesNotMatch()
    {
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
    public function testRegisterThrowsWithUntrustedDeviceIssuerCertificate()
    {
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
    public function testRegisterWorksWithCAList()
    {
        $request = $this->getDefaultRegisterRequest();
        $response = $this->getDefaultRegisterResponse();
        // This contains the actual trusted + verified certificates which are
        // good to use in production. The messages in these tests were
        // generated with a YubiCo device and separately tested against
        // a different reference implementation.
        $CAs = glob(dirname(__DIR__).'/CAcerts/*.pem');
        $this->server->setTrustedCAs($CAs);

        try {
            $reg = $this->server
                ->setRegisterRequest($request)
                ->register($response);
        } catch (SecurityException $e) {
            if ($e->getCode() === SecurityException::NO_TRUSTED_CA) {
                $this->fail('CA Verification should have succeeded');
            }
            throw $e;
        }
        $this->assertInstanceOf(RegistrationInterface::class, $reg);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithChangedApplicationParameter()
    {
        $request = $this->getDefaultRegisterRequest();

        $challengeProvider = $this->createMock(ChallengeProvider::class);
        $challengeProvider->method('getChallenge')
            ->willReturn($request->getChallenge());
        $response = $this->createMock(RegistrationResponseInterface::class);
        $response->method('getChallengeProvider')
            ->willReturn($challengeProvider);
        $response->method('getRpIdHash')
            ->willReturn(hash('sha256', 'https://some.otherdomain.com', true));

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::WRONG_RELYING_PARTY);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithChangedChallengeParameter()
    {
        $request = $this->getDefaultRegisterRequest();
        // Mess up some known-good data: challenge parameter
        $data = $this->readJsonFile('register_response.json');
        $cli = fromBase64Web($data['clientData']);
        $obj = json_decode($cli, true);
        $obj['cid_pubkey'] = 'nonsense';
        $cli = toBase64Web($this->safeEncode($obj));
        $data['clientData'] = $cli;
        $response = RegisterResponse::fromJson($this->safeEncode($data));

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithChangedKeyHandle()
    {
        $request = $this->getDefaultRegisterRequest();
        // Mess up some known-good data: key handle
        $data = $this->readJsonFile('register_response.json');
        $reg = $data['registrationData'];
        $reg[70] = chr(ord($reg[70]) + 1); // Change a byte in the key handle
        $data['registrationData'] = $reg;
        $response = RegisterResponse::fromJson($this->safeEncode($data));

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithChangedPubkey()
    {
        $request = $this->getDefaultRegisterRequest();
        // Mess up some known-good data: public key
        $data = $this->readJsonFile('register_response.json');
        $reg = $data['registrationData'];
        $reg[3] = chr(ord($reg[3]) + 1); // Change a byte in the public key
        $data['registrationData'] = $reg;
        $response = RegisterResponse::fromJson($this->safeEncode($data));

        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(SecurityException::SIGNATURE_INVALID);
        $this->server
            ->setRegisterRequest($request)
            ->register($response);
    }

    /**
     * @covers ::register
     */
    public function testRegisterThrowsWithBadSignature()
    {
        $request = $this->getDefaultRegisterRequest();
        // Mess up some known-good data: signature
        $data = $this->readJsonFile('register_response.json');
        $reg = $data['registrationData'];
        $last = str_rot13(substr($reg, -5)); // rot13 a few chars in signature
        $data['registrationData'] = substr($reg, 0, -5).$last;
        $response = RegisterResponse::fromJson($this->safeEncode($data));

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
    public function testAuthenticateThrowsIfNoRegistrationsPresent()
    {
        $this->server->setSignRequests([$this->getDefaultSignRequest()]);
        $this->expectException(BadMethodCallException::class);
        $this->server->authenticate($this->getDefaultSignResponse());
    }

    /**
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsIfNoSignRequestsPresent()
    {
        $this->server->setRegistrations([$this->getDefaultRegistration()]);
        $this->expectException(BadMethodCallException::class);
        $this->server->authenticate($this->getDefaultSignResponse());
    }

    /**
     * @covers ::authenticate
     */
    public function testAuthenticate()
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

    /**
     * This tries to authenticate with a used response immediately following
     * its successful use.
     *
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsWithObviousReplayAttack()
    {
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
    public function testAuthenticateThrowsWhenCounterGoesBackwards()
    {
        // Counter from "DB" bumped, suggesting response was cloned
        $registration = (new Registration())
            ->setKeyHandle(fromBase64Web(self::ENCODED_KEY_HANDLE))
            ->setPublicKey($this->getDefaultPublicKey())
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
    public function testAuthenticateThrowsWhenChallengeDoesNotMatch()
    {
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
    public function testAuthenticateThrowsIfNoRegistrationMatchesKeyHandle()
    {
        // Change registration KH
        $registration = (new Registration())
            ->setKeyHandle(fromBase64Web('some-other-key-handle'))
            ->setPublicKey($this->getDefaultPublicKey())
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
    public function testAuthenticateThrowsIfNoRequestMatchesKeyHandle()
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

    /**
     * @covers ::authenticate
     */
    public function testAuthenticateThrowsIfSignatureIsInvalid()
    {
        $registration = $this->getDefaultRegistration();
        $request = $this->getDefaultSignRequest();
        // Trimming a byte off the signature to cause a mismatch
        $data = $this->readJsonFile('sign_response.json');
        $data['signatureData'] = substr($data['signatureData'], 0, -1);
        $response = SignResponse::fromJson($this->safeEncode($data));

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
    public function testAuthenticateThrowsIfRequestIsSignedWithWrongKey()
    {
        $pk = base64_decode(
            'BCXk9bGiuzLRJaX6pFONm+twgIrDkOSNDdXgltt+KhOD'.
            '9OxeRv2zYiz7SrVa8eb4LbGR9IDUE7gJySiiuQYWt1w='
        );
        assert($pk !== false);
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
        $registration = (new Registration())
            ->setKeyHandle(fromBase64Web(self::ENCODED_KEY_HANDLE))
            ->setPublicKey(new ECPublicKey($pk))
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

    private function getDefaultRegisterRequest(): RegisterRequest
    {
        // This would have come from a session, database, etc.
        return (new RegisterRequest())
            ->setAppId('https://u2f.ericstern.com')
            ->setChallenge('PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo');
    }

    private function getDefaultRegisterResponse(): RegisterResponse
    {
        return RegisterResponse::fromJson($this->safeReadFile('register_response.json'));
    }

    private function getDefaultSignRequest(): SignRequest
    {
        // This would have come from a session, database, etc
        return (new SignRequest())
            ->setAppId('https://u2f.ericstern.com')
            ->setChallenge('wt2ze8IskcTO3nIsO2D2hFjE5tVD041NpnYesLpJweg')
            ->setKeyHandle(fromBase64Web(self::ENCODED_KEY_HANDLE))
            ;
    }

    private function getDefaultRegistration(): RegistrationInterface
    {
        // From database attached to the authenticating user
        return  (new Registration())
            ->setKeyHandle(fromBase64Web(self::ENCODED_KEY_HANDLE))
            ->setAttestationCertificate($this->getDefaultAttestationCertificate())
            ->setPublicKey($this->getDefaultPublicKey())
            ->setCounter(2)
            ;
    }

    private function getDefaultSignResponse(): SignResponse
    {
        // Value from user
        return SignResponse::fromJson($this->safeReadFile('sign_response.json'));
    }

    private function getDefaultAttestationCertificate(): AttestationCertificate
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

    private function readJsonFile(string $file): array
    {
        return $this->safeDecode($this->safeReadFile($file));
    }

    private function safeReadFile(string $file): string
    {
        $body = file_get_contents(__DIR__.'/'.$file);
        assert($body !== false);
        return $body;
    }

    private function safeDecode(string $json): array
    {
        $data = json_decode($json, true);
        assert($data !== false);
        return $data;
    }

    private function safeEncode(array $data): string
    {
        $json = json_encode($data);
        assert($json !== false);
        return $json;
    }
}
