<?php
declare(strict_types=1);

namespace Firehed\U2F;

$server = require 'bootstrap.php';

session_start();

if (!isset($_SESSION['user_registrations'])) {
    throw new Exception('no registrations in session');
}

$regs = $_SESSION['user_registrations'];
$server->setRegistrations($regs);

if (!isset($_SESSION['sign_requests'])) {
    throw new Exception('no registrations in session');
}
$signReqs = $_SESSION['sign_requests'];
unset($_SESSION['sign_requests']);
$server->setSignRequests($signReqs);

// This expects a (roughly) straight JSONified PublicKeyCredential
$input = trim(file_get_contents('php://input'));
log($input, 'raw json');
$data = json_decode($input, true, 512, JSON_THROW_ON_ERROR);

$response = WebAuthn\LoginResponse::fromDecodedJson($data);
log($response);


$updatedRegistration = $server->authenticate($response);
header('Content-type: application/json');
echo '"all good?"';
