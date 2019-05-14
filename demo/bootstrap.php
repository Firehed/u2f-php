<?php
declare(strict_types=1);
namespace Firehed\U2F;

chdir(dirname(__DIR__));
require 'vendor/autoload.php';

function log($data, string $label = '')
{
    if ($label) {
        error_log($label);
    }
    error_log(print_r($data, true));
}

function unbyte(array $bytes): string
{
    return implode('', array_map('chr', $bytes));
}

$server = new Server();
$server->setAppId('localhost');
$server->setTrustedCAs([
    'CACerts/yubico.pem',
]);
return $server;
