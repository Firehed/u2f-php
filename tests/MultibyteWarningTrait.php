<?php
declare(strict_types=1);

namespace Firehed\U2F;

trait MultibyteWarningTrait
{
    protected function skipIfNotMultibyte()
    {
        $overload = ini_get('mbstring.func_overload');
        if ($overload != 7) {
            $cmd = 'php -d mbstring.func_overload=7 '.
                implode(' ', $_SERVER['argv']);
            $this->markTestSkipped(sprintf(
                "mbstring.func_overload cannot be changed at runtime. Re-run ".
                "this test with the following command:\n\n%s",
                $cmd
            ));
        }
    }
}
