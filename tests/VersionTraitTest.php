<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\VersionTrait
 */
class VersionTraitTest extends \PHPUnit\Framework\TestCase
{
    public function testGetVersion(): void
    {
        $obj = new class {
            use VersionTrait;
        };
        $this->assertSame(
            'U2F_V2',
            $obj->getVersion(),
            'getVersion should always return the string "U2F_V2" per the spec'
        );
    }
}
