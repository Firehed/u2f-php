<?php
require_once '../common.php';

$_SESSION = [];
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

$data = get_user_data($username);
if (!$data) {
    header('HTTP/1.1 400 Bad Request');
    echo json_encode("not registered");
}
else {
    $check = password_verify($password, $data['password']);
    if ($check) {
        $_SESSION['user'] = $username;
	echo json_encode($_SESSION);
    } else {
        header('HTTP/1/1 403 Unauthorized');
        echo json_encode("wrong password");
    }
}
