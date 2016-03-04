<?php declare(strict_types=1);

require_once 'vendor/autoload.php';
require_once 'common.php';

use Firehed\U2F\RegisterResponse;

$user = $_SESSION['user'];

$reg_req = $_SESSION['request'];
unset($_SESSION['request']);

$data = get_user_data($user);

$server->setRegisterRequest($reg_req);

try {
    // Parse response JSON
    $resp = RegisterResponse::fromJson($_POST['signature_str'] ?? '');

    // Attempt to register with parsed response
    $registration = $server->register($resp);

    // Store Registration alongside user
    $kha = substr($registration->getKeyHandleWeb(), 0, 10);
    $data['registrations'][$kha] = $registration;
    write_user_data($user, $data);

    // Return some JSON for the AJAX handler to use
    echo json_encode($_SESSION);
} catch (SecurityException $e) {
    header('HTTP/1.1 403 Unauthorized');
    echo json_encode($e->getMessage());
} catch (InvalidDataException $e) {
    header('HTTP/1.1 400 Bad Request');
    echo json_encode($e->getMessage());
} catch (\Throwable $e) {
    header('HTTP/1.1 500 Internal Server Error');
    echo json_encode($e->getMessage());    
}
