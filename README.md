# U2F

A PHP implementation of the FIDO U2F authentication standard

## Introduction

U2F, or Universal Second Factor, is a new authentication protocol designed "to augment the security of their existing password infrastructure by adding a strong second factor to user login"[1](https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-overview.html#background). It allows websites to replace the need for a companion app (such as Google Authenticator) with a single hardware token that will work across any website supporting the U2F protocol.

This library is designed to allow easy integration of the U2F protocol to an existing user authentication scheme.
It handles the parsing and validating all of the raw message formats, and translates them into standard PHP objects.

Note that use of the word "key" throughout this document should be interpreted to mean "FIDO U2F Token".
These are often USB "keys" but can also be NFC or Bluetooth devices.

There are two main operations that you will need to understand for a successful integration: registration and authentication.
Registration is the act of associating a key that the end-user is physically in posession of with their existing account; authentication is where that key is used to cryptographically sign a message from your application to verify posession of said key.

Additional resources:

* [FIDO U2F Overview](https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-overview.html)
* [FIDO U2F Javascript API](https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-javascript-api.html)

## Usage

Usage will be described in three parts: setup, registration, and authentication.
The code in setup should be used before both registration and authentication.

The API is designed to "fail loudly"; that is, failures will throw an exception, ensuring that return values are always the result of a successful operation.
This reduces the need for complex error checking and handling during use, since the whole thing can be simply wrapped in a `try/catch` block and assume that everything went well if no exceptions are caught.

### Setup

All operations are performed by the U2F Server class, so it needs to be instanciated and configured:

```php
use Firehed\U2F\Server;
$server = new Server();
$server->setTrustedCAs(glob('path/to/certs/*.pem'))
       ->setAppId('https://u2f.example.com');
```

The trusted CAs are whitelisted vendors, and must be an array of absolute paths to PEM-formatted CA certs (as strings).
Some provider certificates are provided in the `CACerts/` directory in the repository root; in a deployed project, these should be available via `$PROJECT_ROOT/vendor/firehed/u2f/CACerts/*.pem`.

You may also choose to disable CA verification, by calling `->disableCAVerification()` instead of `setTrustedCAs()`.
This removes trust in the hardware vendors, but ensures that as new vendors issue tokens, they will be forward-compatible with your website.

The URI provided to `setAppId()` must be the HTTPS domain component of your website. See [FIDO U2F AppID and Facet Specification](https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-appid-and-facets.html#appid-example-1) for additional information.

The client needs an U2F Javascript API implementation; the example code below is based on [Google's implementation](https://github.com/google/u2f-ref-code/blob/master/u2f-gae-demo/war/js/u2f-api.js)

### Registration

Registering a token to a user's account is a two-step process: generating a challenge, and verifying the response to that challenge.

#### Genrating the challenge

Start by generating a challenge:

```php
$request = $server->generateRegisterRequest();
```

Store this object temporarily (probably in a session) since it is needed during verification, and send it to the user as JSON.

If the user has already registered one or more keys, you must also generate sign requests for the existing registrations:

```php
$registrations = $user->getU2FRegistrations();
$sign_requests = $server->generateSignRequests($registrations);
```

Send the sign requests to the user as JSON as well.

Pass both of these values into the U2F JS API:

```js
var request = JSON.parse(register_request_from_php);
var sign_requests = JSON.parse(sign_requests_from_php);
u2f.register([request], sign_requests, complete_registration_callback);
```

The `complete_registration_callback` should stringify the response object and POST it to your server for verification, described below.

#### Verifying the response

When a response is received, it should be POSTed to your server and verified:

```php
use Firehed\U2F\RegisterResponse;
$server->setRegisterRequest($previously_generated_request);
$response = RegisterResponse::fromJson($_POST['some_form_field']);
$registration = $server->register($response)
// (store Registration)
```

The `$registration` should be associated with the user (typically by persisting to a database).

Registrations SHOULD be persisted as a one-to-many relationship with the user, since a user may own multiple keys and may want to associate all of them with their account (e.g. a backup key is kept on a spouse's keychain). It is RECOMMENDED to use `(user_id, $registration->getKeyHandleWeb())` as a unique composite identifier.

At minimum, a persisted Registration must store the Key Handle, Counter, and Public Key; implementations SHOULD also store the Attestation Certificate

This is not a requirement of the specification, but leads to a better user experience.

### Authentication

Authentication is a similar process as registration: generate challenges to sign for each of the user's registrations, and validate the response when received.

#### Generating the challenge:

This is done identically to registration:

```php
$registrations = $user->getU2FRegistrations();
$sign_requests = $server->generateSignRequests($registrations);
```

Store these in the session for use in the next step, JSON-encode them, and send these to the user to pass into the U2F JS API:

```js
var sign_requests = JSON.parse(sign_requests_from_php);
u2f.sign(sign_requests, complete_auth_callback);
```

Like registration, the `complete_auth_callback` should POST the stringified response to the server for verification.

#### Verifying the response

This is also similar to registration:

```php
use Firehed\U2F\SignResponse;
$server->setRegistrations($user->getU2FRegistrations()
       ->setSignRequests($previously_generated_requests);
$response = SignResponse::fromJson($_POST['some_form_field']);
$registration = $server->authenticate($response);
// (update Registration in storage with above)
```

If no exception is thrown, `$registration` will be a Registration object with an updated `counter`; you MUST persist this updated counter to wherever the registrations are stored.
Failure to do so **is insecure** and exposes your application to token cloning attacks.

## Demo

You may try all of this at https://u2f.ericstern.com, and see the corresponding code at https://github.com/Firehed/u2f-php-examples

The example code is only designed to show how the APIs interact with each other, and intentionally leaves out best practices such as use of routers and dependency inversion containers to keep the examples as simple as possible.
See its README for more information.

## Tests

If you are using Arcanist, `arc unit` workflows will work as expected.

Otherwise, all tests are in the `tests/` directory and can be run with `vendor/bin/phpunit tests/`.

## License

MIT
