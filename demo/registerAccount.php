<?php
declare(strict_types=1);

namespace Firehed\U2F;

$config = require 'bootstrap.php';
$server = $config['server'];
$pdo = $config['pdo'];

$data = decodePostJson();

$stmt = $pdo->prepare('INSERT INTO users (username, password_hash) VALUES (:username, :password_hash)');
$result = $stmt->execute([
    ':username' => $data['username'],
    ':password_hash' => \password_hash($data['password'], \PASSWORD_DEFAULT),
]);

echo json_encode(['result' => $result]);
