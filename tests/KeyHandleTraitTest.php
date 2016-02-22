<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\KeyHandleTrait
 * @covers ::<protected>
 * @covers ::<private>
 */
class KeyHandleTraitTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @covers ::getKeyHandleBinary
     * @covers ::setKeyHandle
     */
    public function testAccessors() {
        $obj = new class {
            use KeyHandleTrait;
        };
        $kh = random_bytes(14)."\x00 ";
        $this->assertSame($obj, $obj->setKeyHandle($kh),
            'setKeyHandle should return $this');
        $this->assertSame($kh, $obj->getKeyHandleBinary(),
            'getKeyHandleBinary should return the set value');
    }

    /**
     * @covers ::getKeyHandleWeb
     */
    public function testGetKeyHandleWeb() {
        $obj = new class {
            use KeyHandleTrait;
        };
        $kh = random_bytes(14)."\x00 ";
        $webKh = toBase64Web($kh);
        $obj->setKeyHandle($kh);
        $this->assertSame($webKh, $obj->getKeyHandleWeb(),
            'getKeyHandleWeb was encoded wrong');
    }

}
