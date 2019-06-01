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

// FIXME: each of these sign requests include a different challenge, which is
// fundamentally incompatbile with webauthn
$signRequests = $server->generateSignRequests($regs);
$_SESSION['sign_requests'] = $signRequests;

echo json_encode($signRequests);
