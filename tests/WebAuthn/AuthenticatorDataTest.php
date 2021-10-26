<?php
declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

/**
 * @covers Firehed\U2F\WebAuthn\AuthenticatorData
 */
class AuthenticatorDataTest extends \PHPUnit\Framework\TestCase
{
    public function testParseOfRegistration(): void
    {
        $data = hex2bin(
            '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763'.
            '410000000000000000000000000000000000000000004089d8daecf079d5e11e'.
            '4d3f27f8d6636df14f048d21ce2893623a7c4d3cec862440332960e33055f7c0'.
            '1242de0a5717b081b2ba0af4a0293b21753f0dd97f11f4a50102032620012158'.
            '20acb4d70da1504f2376361e0fb331ad41793e9698fa046945f51352820e7c2b'.
            '7822582035c628978409d8c97ef0bb464a5989a0274b24d91bf48901de8dd045'.
            '0e265680'
        );
        assert($data !== false);

        $authData = AuthenticatorData::parse($data);

        $this->assertTrue($authData->isUserPresent(), 'User is present');

        $this->assertSame(
            hash('sha256', 'localhost', true),
            $authData->getRpIdHash(),
            'Relying Party ID hash'
        );

        $this->assertSame(0, $authData->getSignCount(), 'Sign count');

        $data = $authData->getAttestedCredentialData();
        $this->assertIsArray($data, 'Attested credentials');

        $this->assertSame(hex2bin(
            '89d8daecf079d5e11e4d3f27f8d6636df14f048d21ce2893623a7c4d3cec8624'.
            '40332960e33055f7c01242de0a5717b081b2ba0af4a0293b21753f0dd97f11f4'
        ), $data['credentialId'], 'Credential ID');

        $pk = $data['credentialPublicKey'];
        $this->assertSame(-7, $pk[3]); // alg=-7=ES256
        $this->assertSame(1, $pk[-1]); // crv
        $this->assertSame(hex2bin(
            'acb4d70da1504f2376361e0fb331ad41793e9698fa046945f51352820e7c2b78'
        ), $pk[-2], 'Key curve x-coordinate');
        $this->assertSame(hex2bin(
            '35c628978409d8c97ef0bb464a5989a0274b24d91bf48901de8dd0450e265680'
        ), $pk[-3], 'Key curve y-coordinate');
    }

    public function testParseOfLogin(): void
    {
        $data = hex2bin(
            '49960de5880e8c687434170f6476605b'.
            '8fe4aeb9a28632c7995cf3ba831d9763'.
            '0100000079'
        );
        assert($data !== false);
        $authData = AuthenticatorData::parse($data);

        $this->assertTrue($authData->isUserPresent(), 'User is present');

        $this->assertSame(
            hash('sha256', 'localhost', true),
            $authData->getRpIdHash(),
            'Relying Party ID hash'
        );

        $this->assertSame(121, $authData->getSignCount(), 'Sign count');

        $this->assertNull($authData->getAttestedCredentialData(), 'Attested credentials');
    }

    public function testDebugInfoDoesntPrintBinary(): void
    {
        $data = hex2bin(
            '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763'.
            '410000000000000000000000000000000000000000004089d8daecf079d5e11e'.
            '4d3f27f8d6636df14f048d21ce2893623a7c4d3cec862440332960e33055f7c0'.
            '1242de0a5717b081b2ba0af4a0293b21753f0dd97f11f4a50102032620012158'.
            '20acb4d70da1504f2376361e0fb331ad41793e9698fa046945f51352820e7c2b'.
            '7822582035c628978409d8c97ef0bb464a5989a0274b24d91bf48901de8dd045'.
            '0e265680'
        );
        assert($data !== false);

        $authData = AuthenticatorData::parse($data);

        $debug = print_r($authData, true);
        $this->assertRegExp(
            '/[^\x20-\x7f]/',
            $debug,
            'Debug output contained non-ascii'
        );
    }
}
