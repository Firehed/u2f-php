<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @coversDefaultClass Firehed\U2F\AppIdTrait
 * @covers ::<protected>
 * @covers ::<private>
 */
class AppIdTraitTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @covers ::getAppId
     * @covers ::setAppId
     */
    public function testAccessors() {
        $obj = new class {
            use AppIdTrait;
        };
        $appId = 'https://u2f.example.com';

        $this->assertSame($obj, $obj->setAppId($appId),
            'setAppId should return $this');
        $this->assertSame($appId, $obj->getAppId(),
            'getAppId should return the set value');
    }

    /**
     * @covers ::getApplicationParameter
     */
    public function testGetApplicationParameter() {
        $obj = new class { use AppIdTrait; };
        $appId = 'https://u2f.example.com';
        $obj->setAppId($appId);
        $this->assertSame(hash('sha256', $appId, true),
            $obj->getApplicationParameter(),
            'getApplicationParamter should return the raw SHA256 hash of the application id');
    }

}
