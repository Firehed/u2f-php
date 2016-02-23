<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\Registration
 * @covers ::<protected>
 * @covers ::<private>
 */
class RegistrationTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @covers ::setCounter
     * @covers ::getCounter
     */
    public function testCounter() {
        $obj = new Registration();
        $this->assertSame($obj, $obj->setCounter(1833),
            'setCounter should return $this');
        $this->assertSame(1833, $obj->getCounter(),
            'getCounter should return the set value');
    }

    /**
     * @covers ::setCounter
     */
    public function testSetCounterRejectsNegativeNumbers() {
        $obj = new Registration();
        $this->expectException(\OutOfBoundsException::class);
        $obj->setCounter(-1);
    }
}
