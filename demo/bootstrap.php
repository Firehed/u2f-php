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

$sqliteFile = 'demo/example.sqlite3';
$createTables = !file_exists($sqliteFile);
$pdo = new \PDO(sprintf('sqlite:%s', $sqliteFile));
if ($createTables) {
    $pdo->exec('CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password_hash TEXT
    )');
    $pdo->exec('CREATE TABLE user_keys (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        counter INTEGER,
        key_handle TEXT,
        public_key TEXT,
        attestation_certificate TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )');
}

$server = new Server();
$server->setAppId('localhost');
$server->setTrustedCAs([
    'CACerts/yubico.pem',
]);
return [
    'server' => $server,
    'pdo' => $pdo,
];
