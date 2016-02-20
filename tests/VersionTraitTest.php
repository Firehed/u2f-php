<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\VersionTrait
 * @covers ::<protected>
 * @covers ::<private>
 */
class VersionTraitTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @covers ::getVersion
     */
    public function testGetVersion() {
        $obj = new class {
            use VersionTrait;
        };
        $this->assertSame('U2F_V2', $obj->getVersion(),
            'getVersion should always return the string "U2F_V2" per the spec');
    }


}
