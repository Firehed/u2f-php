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
        $json = json_encode($challenge);
        assert($json !== false);
        $decoded = json_decode($json);
        self::assertSame($wrapped, $decoded);
    }
}
