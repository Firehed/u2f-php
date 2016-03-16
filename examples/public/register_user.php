<?php declare(strict_types=1);
require_once '../common.php';

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

$data = get_user_data($username);
if ($data) {
    header('HTTP/1.1 400 Bad Request');
    echo json_encode("already registered");
}
else {
    $data['password'] = password_hash($password, \PASSWORD_DEFAULT);
    $data['registrations'] = [];
    write_user_data($username, $data);
    echo json_encode($_SESSION);
}
