<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\RegisterRequest
 */
class RegisterRequestTest extends \PHPUnit\Framework\TestCase
{
    public function testJsonSerialize(): void
    {
        $appId = 'https://u2f.example.com';
        $challenge = 'some-random-string';

        $request = new RegisterRequest();
        $request
            ->setAppId($appId)
            ->setChallenge($challenge);
        $json = json_encode($request);
        assert($json !== false);
        $decoded = json_decode($json, true);
        $this->assertSame(
            $appId,
            $request->getAppId(),
            'getAppId returned the wrong value'
        );
        $this->assertSame(
            $appId,
            $decoded['appId'],
            'json appId property did not match'
        );
        $this->assertSame(
            $challenge,
            $request->getChallenge(),
            'getChallenge returned the wrong value'
        );
        $this->assertSame(
            $challenge,
            $decoded['challenge'],
            'json challenge property did not match'
        );
        $this->assertSame(
            'U2F_V2',
            $request->getVersion(),
            'getVersion returned the wrong value'
        );
        $this->assertSame(
            'U2F_V2',
            $decoded['version'],
            'json version was incorrect'
        );
    }
}
