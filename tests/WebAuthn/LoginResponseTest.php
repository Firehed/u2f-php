<?php
declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

use Firehed\U2F\ChallengeProvider;
use Firehed\U2F\LoginResponseInterface;

/**
 * @coversDefaultClass Firehed\U2F\WebAuthn\LoginResponse
 * @covers ::<protected>
 * @covers ::<private>
 */
class LoginResponseTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @covers ::fromDecodedJson
     * @covers ::getChallenge
     * @covers ::getCounter
     * @covers ::getSignature
     * @covers ::getKeyHandleBinary
     * @covers ::getSignedData
     */
    public function testFromDecodedJson()
    {
        $json = file_get_contents(__DIR__ . '/loginresponse.json');
        assert($json !== false);
        $data = json_decode($json, true);

        $response = LoginResponse::fromDecodedJson($data);
        $this->assertInstanceOf(ChallengeProvider::class, $response);
        $this->assertInstanceOf(LoginResponseInterface::class, $response);

        // Check against known values from vector
        $this->assertSame(121, $response->getCounter(), 'Counter');
        $this->assertSame(hex2bin(
            'd58c3b6b71d17dabf4467e3291ac7b8d'.
            'a40729818b1165f24b414d5dd3368d0f'.
            '61ad41eb1f27c2ca4767c124c5b23fc9'.
            '9043a8a2e94cbd59bcc51cb1ccfc9561'
        ), $response->getKeyHandleBinary(), 'KHB');
        $this->assertSame(hex2bin(
            '3046022100991c271ff8b8e2f42f5d3f'.
            '1d817b55a89111a86e6e2de54ad2dc50'.
            '4e7d3ac8b7022100c96faf2f7df51c6e'.
            'ce348fa6c431ad31a578d7688f37e814'.
            '412ea1ef3bce99dd'
        ), $response->getSignature(), 'Signature');
        $this->assertSame(hex2bin(
            '49960de5880e8c687434170f6476605b8fe4aeb9'.
            'a28632c7995cf3ba831d97630100000079'. // raw auth data
            'a205dca85807c67218c688c30d8899bf'.
            '13c087cc2bc012c6a823a4706a3371fa' // json hash
        ), $response->getSignedData(), 'Signed data');

        $this->assertSame(
            'A902wrYRwZM2RV544aj--Q',
            $response->getChallengeProvider()->getChallenge(),
            'Challenge'
        );
    }
}
