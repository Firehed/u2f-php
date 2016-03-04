<?php declare(strict_types=1);

require_once 'vendor/autoload.php';

const SECRET = 'asdfklj209flwjaflksdnflk2ifnas';

use Firehed\JWT\{
    Algorithm,
    SessionHandler
};
use Firehed\U2F\Server;

$sh = new SessionHandler([
    '20160303' => [
        'alg' => Algorithm::HMAC_SHA_256(),
        'secret' => SECRET,
    ],
]);
ini_set('session.use_cookies', 'false');
session_set_cookie_params(
    $lifetime = 0,
    $path = '/',
    $domain = '',
    $secure = true,
    $httponly = true
);
session_set_save_handler($sh);
session_start();

// This will intentionally leak into the other files' scope; normally, you'd set this up in a dependency inversion container or config file
$server = (new Server())
    ->setTrustedCAs(glob(__DIR__.'/CAcerts/*.pem'))
    ->setAppId('https://u2f.ericstern.com');

// This is a dumbed-down "load user by username" function
function get_user_data(string $user): array {
    $user = basename($user);
    if (!file_exists("users/$user.dat")) {
        return [];
    }
    return unserialize(file_get_contents("users/$user.dat"));
}
// This is a dumbed-down "save user" function
function write_user_data(string $user, $data) {
    $user = basename($user);
    file_put_contents("users/$user.dat", serialize($data));
}
