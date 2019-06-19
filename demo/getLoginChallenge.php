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

$signRequests = $server->generateSignRequests($regs);
$_SESSION['sign_requests'] = $signRequests;

echo json_encode([
    'challenge' => $signRequests[0]->getChallenge(),
    'key_handles' => array_map(function (SignRequest $sr) {
        return $sr->getKeyHandleWeb();
    }, $signRequests),
]);
