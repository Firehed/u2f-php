<?php
declare(strict_types=1);

namespace Firehed\U2F;

$config = require 'bootstrap.php';
$server = $config['server'];
$pdo = $config['pdo'];

$data = decodePostJson();

$stmt = $pdo->prepare('SELECT * FROM users WHERE username = :username');
$stmt->execute([
    ':username' => $data['username'],
]);

$user = $stmt->fetch(\PDO::FETCH_ASSOC);

if ($user === false) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['result' => false, 'error' => 'user not found']);
    return;
}
if (!password_verify($data['password'], $user['password_hash'])) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['result' => false, 'error' => 'wrong password']);
    return;
}

if (password_needs_rehash($user['password_hash'], \PASSWORD_DEFAULT)) {
    $newPassword = password_hash($data['password'], \PASSWORD_DEFAULT);
    $update = $pdo->prepare('UPDATE users SET password_hash = :hash WHERE id = :id');
    $update->execute([':hash' => $newPasswordHash, ':id' => $user['id']]);
}
session_start();
$_SESSION['user_id'] = $user['id'];

$stmt = $pdo->prepare('SELECT count(*) AS key_count FROM user_keys WHERE user_id = :user_id');
$stmt->execute([':user_id' => $user['id']]);
$count = (int)$stmt->fetch(\PDO::FETCH_ASSOC)['key_count'];
$_SESSION['needs_2fa'] = ($count > 0);
echo json_encode([
    'result' => true,
    'key_count' => $count,
]);
