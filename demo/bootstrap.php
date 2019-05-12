<?php
chdir(dirname(__DIR__));
require 'vendor/autoload.php';

$server = new Firehed\U2F\Server();
$server->setAppId('localhost');
$server->setTrustedCAs([
    'CACerts/yubico.pem',
]);
return $server;
