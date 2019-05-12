<?php

namespace X;

$server = require 'bootstrap.php';

session_start();
if (!isset($_SESSION['register_challenge'])) {
    throw new Exception('no challenge in session');
}

$registerRequest = $_SESSION['register_challenge'];

$server->setRegisterRequest($registerRequest);


$data = json_decode(trim(file_get_contents('php://input')), true);
// log($data, 'decoded POST');
// {
//   id: string  (b64-web?)
//   rawId: byteArray
//   type: "public-key"
//   clientDataJson: jsonString: {
//     challenge: string
//     clientExtensions: {},
//     hashAlgorithm: "SHA-256",
//     origin: "http://localhost:8080"
//     type: "webauthn.create"
//  }
//  attestationObjectByteArray: cbor-byte-array: {
//    authData: binString
//    fmt: "fido-u2f",
//    attStmt: {
//      sig: binString
//      x5c: binString
//    }
//  }
// }

assert($data['type'] === 'public-key');

$aoCBOR = $data['attestationObjectByteArray'];
// log(bin2hex($aoCBOR), 'cbor bin');
$ao = (new \Firehed\U2F\CBOR\Decoder())->decodeFromByteArray($aoCBOR);
log($ao, 'attestion object decoded');

// webAuthn 6.1
function decodeAuthenticatorData(string $bytes)
{
    $i = 0;
    $read = function ($count) use (&$i, $bytes) {
        $ret = substr($bytes, $i, $count);
        $i += $count;
        return $ret;
    };
    assert(strlen($bytes) >= 37);
    $rpidHash = $read(32);
    // FIXME: validate this hash_equals origin
    log(bin2hex($rpidHash), 'rpid hash hex');
    $flags = ord($read(1));
    $signCount = $read(4); // todo: unpack(N)
    log($flags, 'flags');
    $includedAT = ($flags & 0b01000000) > 0;
    $includedED = ($flags & 0b10000000) > 0;

    if ($includedAT) {
        log('AT included');
        $aaguid = $read(16);
        $credentialIdLength = $read(2);
        $credentialIdLength = (ord($credentialIdLength[0]) << 8) + ord($credentialIdLength[1]);
        $credentialId = $read($credentialIdLength); // FIXME: overflow risk
        log($credentialId, 'credentialId');

        $restOfData = $read(strlen($bytes) - $i);
        $publicKey = (new \Firehed\U2F\CBOR\Decoder())->decode($restOfData);
        log($publicKey, 'pk');
/*
    [attest:Firehed\U2F\RegisterResponse:private] =>
    [pubKey:Firehed\U2F\RegisterResponse:private] =>
    [clientData:Firehed\U2F\RegisterResponse:private] =>
    [signature:Firehed\U2F\RegisterResponse:private] =>
    [keyHandle:Firehed\U2F\RegisterResponse:private] =>
 */
    }
    $response = new \Firehed\U2F\RegisterResponse();
    $response->setKeyHandle($credentialId);
    $response->setPublicKey(sprintf('%s%s%s', "\x04", $publicKey[-2], $publicKey[-3]));

    return $response;
}

// log($authData, 'auth data');
$authData = $ao['authData'];
$response = decodeAuthenticatorData($authData);
log($ao['attStmt'], 'attestation statement');
$response->setSignature($ao['attStmt']['sig']);

// $keyHandle = implode('', array_map('chr', $data['rawId']));
// $response->setKeyHandle($keyHandle);

assert(count($ao['attStmt']['x5c']) === 1); // 8.6 verification
$x5c = $ao['attStmt']['x5c'][0];
log($x5c);
$response->setAttestationCertificate($x5c);

$decClientData = json_decode($data['clientDataJson'], true, 512, \JSON_THROW_ON_ERROR);

$clientData = \Firehed\U2F\WebAuthnClientData::fromJson($data['clientDataJson']);
// $clientData = new \Firehed\U2F\ClientData();
// $base64WebEncodedChallenge = $decClientData['challenge'];
// $clientData->setChallenge(\Firehed\U2F\fromBase64Web($base64WebEncodedChallenge));
$response->setClientData($clientData);


log($response, 'register response');



$registration = $server->register($response);
header('Content-type: application/json');
echo json_encode([
    'counter' => $registration->getCounter(),
    'khw' => $registration->getKeyHandleWeb(),
    'pk_pem' => $registration->getPublicKeyPem(),
    'ac_pem' => $registration->getAttestationCertificatePem(),
]);

function log($data, string $label = '')
{
    if ($label) {
        error_log($label);
    }
    error_log(print_r($data, true));
}
