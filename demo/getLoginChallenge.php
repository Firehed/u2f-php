<?php
$config = require 'bootstrap.php';
$server = $config['server'];

session_start();
if (!isset($_SESSION['user_registrations'])) {
    throw new \Exception('not registered?');
}
$regs = $_SESSION['user_registrations'];

// FIXME: each of these sign requests include a different challenge, which is
// fundamentally incompatbile with webauthn
$signRequests = $server->generateSignRequests($regs);
$_SESSION['sign_requests'] = $signRequests;

header('Content-type: application/json');

echo json_encode($signRequests);
