<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\KeyHandleTrait
 */
class KeyHandleTraitTest extends \PHPUnit\Framework\TestCase
{
    public function testAccessors(): void
    {
        $obj = new class {
            use KeyHandleTrait;
        };
        $kh = random_bytes(14)."\x00 ";
        $this->assertSame(
            $obj,
            $obj->setKeyHandle($kh),
            'setKeyHandle should return $this'
        );
        $this->assertSame(
            $kh,
            $obj->getKeyHandleBinary(),
            'getKeyHandleBinary should return the set value'
        );
    }

    public function testGetKeyHandleWeb(): void
    {
        $obj = new class {
            use KeyHandleTrait;
        };
        $kh = random_bytes(14)."\x00 ";
        $webKh = toBase64Web($kh);
        $obj->setKeyHandle($kh);
        $this->assertSame(
            $webKh,
            $obj->getKeyHandleWeb(),
            'getKeyHandleWeb was encoded wrong'
        );
    }
}
