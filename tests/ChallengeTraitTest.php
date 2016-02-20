<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\ChallengeTrait
 * @covers ::<protected>
 * @covers ::<private>
 */
class ChallengeTraitTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @covers ::getChallenge
     * @covers ::setChallenge
     */
    public function testAccessors() {
        $obj = new class {
            use ChallengeTrait;
        };
        $challenge = bin2hex(random_bytes(15));
        $this->assertSame($obj, $obj->setChallenge($challenge),
            'setChallenge should return $this');
        $this->assertSame($challenge, $obj->getChallenge(),
            'getChallenge should return the challenge that was set');
    }
}
