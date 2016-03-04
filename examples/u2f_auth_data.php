<?php declare(strict_types=1);

require_once 'common.php';

$user = $_SESSION['user'];
$data = get_user_data($user);
$registrations = $data['registrations'] ?? [];

$sign_reqs = $server->generateSignRequests($registrations);

$_SESSION['sign_reqs'] = $sign_reqs;

echo json_encode(array_values($sign_reqs));

