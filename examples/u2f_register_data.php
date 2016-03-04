<?php declare(strict_types=1);

require_once 'vendor/autoload.php';
require_once 'common.php';

$user = $_SESSION['user'];
$data = get_user_data($user);
$regs = $data['registrations'] ?? [];

$reg_req = $server->generateRegisterRequest();
$sigs = $server->generateSignRequests($regs);

$out = [
    'request' => $reg_req,
    'signatures' => $sigs,
];
$_SESSION['request'] = $reg_req;

echo json_encode($out);
