<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\ChallengeTrait
 */
class ChallengeTraitTest extends \PHPUnit\Framework\TestCase
{

    public function testAccessors(): void
    {
        $obj = new class {
            use ChallengeTrait;
        };
        $challenge = bin2hex(random_bytes(15));
        $this->assertSame(
            $obj,
            $obj->setChallenge($challenge),
            'setChallenge should return $this'
        );
        $this->assertSame(
            $challenge,
            $obj->getChallenge(),
            'getChallenge should return the challenge that was set'
        );
    }
}
