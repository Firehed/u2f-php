<?php
declare(strict_types=1);

namespace Firehed\U2F;
use Exception;

class ClientErrorException extends Exception
{
    public function __construct(int $code) {
        parent::__construct(ClientError::MESSAGES[$code] ?? '', $code);
    }
}
