<?php

namespace Firehed\U2F;

use Firehed\CBOR\Decoder;

$server = require 'bootstrap.php';

session_start();
if (!isset($_SESSION['register_challenge'])) {
    throw new Exception('no challenge in session');
}

$registerRequest = $_SESSION['register_challenge'];
unset($_SESSION['register_challenge']); // force fresh every time

$server->setRegisterRequest($registerRequest);


// This expects a (roughly) straight JSONified PublicKeyCredential
$input = trim(file_get_contents('php://input'));
log($input, 'raw json');
$data = json_decode($input, true, 512, JSON_THROW_ON_ERROR);

assert($data['type'] === 'public-key');

$response = WebAuthn\RegistrationResponse::fromDecodedJson($data);

log($response, 'register response');

$registration = $server->register($response);
// this would be save to db
$_SESSION['user_registrations'] = [$registration];

header('Content-type: application/json');
echo json_encode([
    'counter' => $registration->getCounter(),
    'khw' => $registration->getKeyHandleWeb(),
    'pk_pem' => $registration->getPublicKeyPem(),
    'ac_pem' => $registration->getAttestationCertificatePem(),
]);
