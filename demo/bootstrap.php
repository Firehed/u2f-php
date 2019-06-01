<?php
declare(strict_types=1);
namespace Firehed\U2F;

chdir(dirname(__DIR__));
require 'vendor/autoload.php';

header('Content-type: application/json');

function log($data, string $label = '')
{
    if ($label) {
        error_log($label);
    }
    error_log(print_r($data, true));
}

function decodePostJson(): array
{
    $input = trim(file_get_contents('php://input'));
    log($input, 'raw json');
    return json_decode($input, true, 512, JSON_THROW_ON_ERROR);
}

function getRegistrations(\PDO $pdo, int $userId): array
{
    $stmt = $pdo->prepare('SELECT * FROM user_keys WHERE user_id = :user_id');
    $stmt->execute([':user_id' => $userId]);

    $regs = [];
    while ($userKey = $stmt->fetch(\PDO::FETCH_ASSOC)) {
        $reg = new Registration();
        $reg->setCounter((int)$userKey['counter']);
        $reg->setKeyHandle($userKey['key_handle']);
        $reg->setPublicKey(new ECPublicKey($userKey['public_key']));
        $reg->setAttestationCertificate(new AttestationCertificate($userKey['attestation_certificate']));
        $regs[] = $reg;
    }
    return $regs;
}


$sqliteFile = 'demo/example.sqlite3';
$createTables = !file_exists($sqliteFile);
$pdo = new \PDO(sprintf('sqlite:%s', $sqliteFile));
$pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
if ($createTables) {
    $pdo->exec('CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
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
