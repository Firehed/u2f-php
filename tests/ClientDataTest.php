<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\ClientData
 * @covers ::<protected>
 * @covers ::<private>
 */
class ClientDataTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @covers ::fromJson
     */
    public function testFromValidJson()
    {
        $goodData = [
            'typ' => 'navigator.id.finishEnrollment',
            'challenge' => 'PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo',
            'origin' => 'https://u2f.ericstern.com',
            'cid_pubkey' => '',
        ];
        $goodJson = json_encode($goodData);
        assert($goodJson !== false);
        $clientData = ClientData::fromJson($goodJson);
        $this->assertInstanceOf(ClientData::class, $clientData);
    }

    /**
     * @covers ::getChallengeParameter
     */
    public function testGetChallengeParameter()
    {
        $expected_param = base64_decode('exDPjyyKbizXMAAUNLpv0QYJNyXClbUqewUWojPtp0g=');
        assert($expected_param !== false);
        // Sanity check
        $this->assertSame(
            32,
            strlen($expected_param),
            'Test vector should have been 32 bytes'
        );

        $goodJson = '{"typ":"navigator.id.finishEnrollment","challenge":"PfsWR'.
            '1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo","origin":"https://u2f.eri'.
            'cstern.com","cid_pubkey":""}';

        assert($goodJson !== false);
        $clientData = ClientData::fromJson($goodJson);
        $this->assertTrue(
            hash_equals($expected_param, $clientData->getChallengeParameter()),
            'Challenge parameter did not match expected value'
        );
    }

    /**
     * @covers ::getApplicationParameter
     */
    public function testGetApplicationParameter()
    {
        $goodData = [
            'typ' => 'navigator.id.finishEnrollment',
            'challenge' => 'PfsWR1Umy2V5Al1Bam2tG0yfPLeJElfwRzzAzkYPgzo',
            'origin' => 'https://u2f.ericstern.com',
            'cid_pubkey' => '',
        ];
        $goodJson = json_encode($goodData);
        assert($goodJson !== false);
        $clientData = ClientData::fromJson($goodJson);
        $this->assertSame(
            hash('sha256', 'https://u2f.ericstern.com', true),
            $clientData->getApplicationParameter()
        );
    }

    /**
     * @covers ::fromJson
     */
    public function testBadJson()
    {
        $json = 'this is not json';
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MALFORMED_DATA);
        ClientData::fromJson($json);
    }

    /**
     * @covers ::fromJson
     * @dataProvider missingData
     */
    public function testDataValidation($json)
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionCode(InvalidDataException::MISSING_KEY);
        ClientData::fromJson($json);
    }

    /**
     * @dataProvider types
     */
    public function testTypes(string $type, bool $allowed)
    {
        $all = [
            'typ' => $type,
            'challenge' => 'SOMECHALLENGE',
            'origin' => 'https://u2f.example.com',
            'cid_pubkey' => '',
        ];
        $json = json_encode($all);
        assert($json !== false);
        if (!$allowed) {
            $this->expectException(InvalidDataException::class);
            $this->expectExceptionCode(InvalidDataException::MALFORMED_DATA);
        }
        $data = ClientData::fromJson($json);
        // Implicitly, allowed == true because no exceptionw was thrown
        $this->assertInstanceOf(ClientData::class, $data);
    }

    // -( DataProviders )------------------------------------------------------

    public function missingData(): array
    {
        $all = [
            'typ' => 'navigator.id.finishEnrollment',
            'challenge' => 'SOMECHALLENGE',
            'origin' => 'https://u2f.example.com',
            'cid_pubkey' => '',
        ];
        $without = function (string $i) use ($all): array {
            unset($all[$i]);
            return [json_encode($all)];
        };
        return [
            $without('typ'),
            $without('challenge'),
            $without('origin'),
        ];
    }

    public function types(): array
    {
        return [
            ['navigator.id.getAssertion', true],
            ['navigator.id.finishEnrollment', true],
            ['navigator.id.madeThisUp', false],
        ];
    }
}
