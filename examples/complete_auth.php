<?php declare(strict_types=1);

require_once 'common.php';

use Firehed\U2F\SignResponse;

$user = $_SESSION['user'] ?? '';

$sign_reqs = $_SESSION['sign_reqs'] ?? [];
unset($_SESSION['sign_reqs']);

$data = get_user_data($user);
$registrations = $data['registrations'] ?? [];

$server->setRegistrations($registrations)
    ->setSignRequests($sign_reqs);


try {
    // Parse response JSON
    $sign_response = SignResponse::fromJson($_POST['signature_str'] ?? '');

    // Attempt to authenticate with parsed response
    $registration = $server->authenticate($sign_response);

    // Update registration (so new counter is saved)
    $kha = substr($registration->getKeyHandleWeb(), 0, 10);
    $data['registrations'][$kha] = $registration;
    write_user_data($user, $data);
    $_SESSION['is_mfa'] = true;

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

