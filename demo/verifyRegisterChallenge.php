<?php

namespace Firehed\U2F;

use Firehed\CBOR\Decoder;

$config = require 'bootstrap.php';
$server = $config['server'];
$pdo = $config['pdo'];

session_start();
if (!isset($_SESSION['register_challenge'])) {
    throw new Exception('no challenge in session');
}
if (!isset($_SESSION['user_id'])) {
    throw new Exception('not logged in');
}

$registerRequest = $_SESSION['register_challenge'];
unset($_SESSION['register_challenge']); // force fresh every time

$server->setRegisterRequest($registerRequest);


// This expects a (roughly) straight JSONified PublicKeyCredential
$data = decodePostJson();

assert($data['type'] === 'public-key');

$response = WebAuthn\RegistrationResponse::fromDecodedJson($data);

log($response, 'register response');

$registration = $server->register($response);
$stmt = $pdo->prepare('INSERT INTO user_keys (
    user_id,
    counter,
    key_handle,
    public_key,
    attestation_certificate
) VALUES (
    :user_id,
    :counter,
    :key_handle,
    :public_key,
    :attestation_certificate
)');
$stmt->execute([
    ':user_id' => $_SESSION['user_id'],
    ':counter' => $registration->getCounter(),
    ':key_handle' => $registration->getKeyHandleBinary(),
    ':public_key' => $registration->getPublicKey()->getBinary(),
    ':attestation_certificate' => $registration->getAttestationCertificate()->getBinary(),
]);
echo json_encode([
    'counter' => $registration->getCounter(),
    'khw' => $registration->getKeyHandleWeb(),
    'pk_pem' => $registration->getPublicKey()->getPemFormatted(),
    'ac_pem' => $registration->getAttestationCertificate()->getPemFormatted(),
]);
