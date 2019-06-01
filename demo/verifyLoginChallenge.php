<?php
declare(strict_types=1);

namespace Firehed\U2F;

$config = require 'bootstrap.php';
$server = $config['server'];
$pdo = $config['pdo'];

session_start();

if (!isset($_SESSION['user_id'])) {
    throw new \Exception('not logged in');
}

$regs = getRegistrations($pdo, (int)$_SESSION['user_id']);
$server->setRegistrations($regs);

if (!isset($_SESSION['sign_requests'])) {
    throw new Exception('no registrations in session');
}
$signReqs = $_SESSION['sign_requests'];
unset($_SESSION['sign_requests']);
$server->setSignRequests($signReqs);

// This expects a (roughly) straight JSONified PublicKeyCredential
$data = decodePostJson();
$response = WebAuthn\LoginResponse::fromDecodedJson($data);
log($response, 'login response');

$updatedRegistration = $server->authenticate($response);

$stmt = $pdo->prepare('UPDATE user_keys SET counter = :counter WHERE user_id = :user_id AND key_handle = :key_handle');
$stmt->execute([
    ':counter' => $updatedRegistration->getCounter(),
    ':user_id' => $_SESSION['user_id'],
    ':key_handle' => $updatedRegistration->getKeyHandleBinary(),
]);

echo json_encode([
    'result' => true,
    'new counter' => $updatedRegistration->getCounter(),
]);
