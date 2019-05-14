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

// parse response
$response = new \Firehed\U2F\RegisterResponse();

// attestationObject is a CBOR
// @see https://w3c.github.io/webauthn/#sctn-attestation (6.4)
$attestationObject = (new Decoder())->decode(unbyte($data['response']['attestationObject']));

// 6.4.4 general format conformance
assert(isset($attestationObject['authData']));
assert(isset($attestationObject['fmt']));
assert(isset($attestationObject['attStmt']));
// u2f-specific 8.6 (fmt defines the attStmt body, defined all over the spec,
// search for "$$attStmtType")
assert($attestationObject['fmt'] === 'fido-u2f');
$statement = $attestationObject['attStmt'];
assert(isset($statement['x5c']) && is_array($statement['x5c']));
assert(count($statement['x5c']) === 1);
assert(isset($statement['sig']));


$response->setSignature($statement['sig']);
$response->setAttestationCertificate($statement['x5c'][0]);

// -( Parse Authenticator Data )------
//
// FIXME: Somewhere in here, we need to sanity check that $ad['rpIdHash']
// actually is valid for the server origin
//
$ad = WebAuthn\AuthenticatorData::parse($attestationObject['authData']);
$acd = $ad->getAttestedCredentialData();
assert($acd !== null);
$response->setKeyHandle($acd['credentialId']);
// Maybe check [1] === 2 (kty === signing)
assert($acd['credentialPublicKey'][3] === -7, 'Not ES256');
$response->setPublicKey(sprintf(
    '%s%s%s',
    "\x04",
    $acd['credentialPublicKey'][-2],
    $acd['credentialPublicKey'][-3]
));

$cdj = unbyte($data['response']['clientDataJSON']);
$response->setClientData(WebAuthn\ClientData::fromJson($cdj));


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
