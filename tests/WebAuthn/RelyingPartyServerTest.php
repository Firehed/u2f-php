<?php

declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

use Firehed\U2F\Challenge;

/**
 * @covers Firehed\U2FWebAuthn\RelyingPartyServer
 */
class RelyingPartyServerTest extends \PHPUnit\Framework\TestCase
{
    public function testReg(): void
    {
        $json = file_get_contents(__DIR__ . '/apple_registration.json');
        $attest = Web\AuthenticatorAttestationResponse::parseJson($json);
        $challenge = new Challenge('6_h4_KZQ6tWsyvQnD1trsg');

        $server = new RelyingPartyServer('http://localhost:8887');
        $server->register($attest, $challenge);
    }

    public function testLogin(): void
    {
    }
}
