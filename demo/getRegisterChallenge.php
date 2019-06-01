<?php
$config = require 'bootstrap.php';
$server = $config['server'];

session_start();
if (!isset($_SESSION['register_challenge'])) {
    $_SESSION['register_challenge'] = $server->generateRegisterRequest();
}

header('Content-type: application/json');
$challenge = $_SESSION['register_challenge']->getChallenge();

echo json_encode($challenge);
