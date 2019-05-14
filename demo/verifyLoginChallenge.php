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

// parse response
$response = new \Firehed\U2F\SignResponse();

$cdj = unbyte($data['response']['clientDataJSON']);
$sig = unbyte($data['response']['signature']);
$rawAd = unbyte($data['response']['authenticatorData']);

assert(strlen($rawAd) >= 37);
$rpidHash = substr($rawAd, 0, 32);
log(bin2hex($rpidHash), 'rpid hash');
$flags = ord(substr($rawAd, 32, 1));
$UP = ($flags & 0x01) === 0x01;
$UV = ($flags & 0x04) === 0x04;
$AT = ($flags & 0x40) === 0x40;
$ED = ($flags & 0x80) === 0x80;
$signCounter = unpack('N', substr($rawAd, 33, 4))[1];

$response->setKeyHandle(unbyte($data['rawId']));
$response->setCounter($signCounter);
$response->setUserPresenceByte($UP ? 1 : 0);
$response->setClientData(WebAuthnClientData::fromJson($cdj));
$response->setSignature($sig);

log($response);


$updatedRegistration = $server->authenticate($response);
header('Content-type: application/json');
echo '"not done"';
