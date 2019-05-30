<?php
declare(strict_types=1);

namespace Firehed\U2F;

interface AttestationCertificateInterface
{
    public function getBinary(): string;

    public function getPemFormatted(): string;
}
