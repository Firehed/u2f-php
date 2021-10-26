<?php
declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @covers Firehed\U2F\AppIdTrait
 */
class AppIdTraitTest extends \PHPUnit\Framework\TestCase
{

    public function testAccessors(): void
    {
        $obj = new class {
            use AppIdTrait;
        };
        $appId = 'https://u2f.example.com';

        $this->assertSame(
            $obj,
            $obj->setAppId($appId),
            'setAppId should return $this'
        );
        $this->assertSame(
            $appId,
            $obj->getAppId(),
            'getAppId should return the set value'
        );
    }

    public function testGetApplicationParameter(): void
    {
        $obj = new class {
            use AppIdTrait;
        };
        $appId = 'https://u2f.example.com';
        $obj->setAppId($appId);
        $this->assertSame(
            hash('sha256', $appId, true),
            $obj->getApplicationParameter(),
            'getApplicationParamter should return the raw SHA256 hash of the application id'
        );
    }

    public function testGetRpIdHash(): void
    {
        $obj = new class {
            use AppIdTrait;
        };
        $appId = 'https://u2f.example.com';
        $obj->setAppId($appId);
        $this->assertSame(
            hash('sha256', $appId, true),
            $obj->getRpIdHash(),
            'getRpIdHash should return the raw SHA256 hash of the application id'
        );
    }
}
