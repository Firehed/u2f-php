<?php

declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\Challenge
 */
class ChallengeTest extends \PHPUnit\Framework\TestCase
{
    public function testGetChallengeIsUnmodified(): void
    {
        $wrapped = bin2hex(random_bytes(10));
        $challenge = new Challenge($wrapped);
        self::assertSame($wrapped, $challenge->getChallenge());
    }

    public function testJsonSerialize(): void
    {
        $wrapped = bin2hex(random_bytes(10));
        $challenge = new Challenge($wrapped);
        $decoded = json_decode(json_encode($challenge));
        self::assertSame($wrapped, $decdoed);
    }
}
