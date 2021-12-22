# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<<<<<<< Updated upstream
=======
Intended changes:
- Update server constructor to handle validation mode?

Keep:
- Server::generateRegisterRequest
- RegisterRequest
- WA\RegistrationResponse
- SignRequest
- WA\LoginResponse
- Registration

Drop:

TODO:
- server setAppId
## 2.0.0
### Removed
- ChallengeProvider
- RegisterRequest
- RegisterResponse (Replaced by WebAuthn/RegistrationResponse)
- ResponseTrait (internal)
- SignRequest
- SignResponse (Replaced by WebAuthn/LoginResponse)
- Server::authenticate(LoginResponseInterface)
- Server::register(RegistrationResponseInterface)
- Server::setRegisterRequest(RegisterRequest)
- Server::setRegistrations(RegistrationInterface[])
- Server::setSignRequests(SignRequest[])
- Server::generateRegisterRequest()
- Server::generateSignRequest(RegistrationInterface)
- Server::generateSignRequests(RegistrationInterface[])

## [1.3.0] - Unreleased

### Added
- Challenge class
- ChallengeProviderInterface (will replace ChallengeProvider)
- Server::generateChallenge(): ChallengeProviderInterface (now public; signature changed from previous private implementation)
- Server::validateLogin(ChallengeProviderInterface, LoginResponseInterface, RegistrationInterface[]): RegistrationInterface (will replace Server::setRegistrations + Server::setSignRequests + Server::authenticate)
- Server::validateRegistration(ChallengeProviderInterface, RegistrationResponseInterface): RegistrationInterface (will replace Server::setRegisterRequest + Server::register)

### Changed
- Server's constructor now can take `string $appId` as a parameter
- WebAuthn\AuthenticatorData marked as internal
- All traits marked as internal
- webauthn ns going away

### Deprecated
- ChallengeProvider
- Server::authenticate(LoginResponseInterface)
- Server::register(RegistrationResponseInterface)
- Server::setAppId(string)
- Server::setRegisterRequest(RegisterRequest)
- Server::setRegistrations(RegistrationInterface[])
- Server::setSignRequests(SignRequest[])
- Server::generateRegisterRequest()
- Server::generateSignRequest(RegistrationInterface)
- Server::generateSignRequests(RegistrationInterface[])
- RegisterRequest
- RegisterResponse (Replaced by WebAuthn/RegistrationResponse)
- SignRequest
- SignResponse (Replaced by WebAuthn/LoginResponse)
- ClientData (internal)
- ResponseTrait (internal)

## [1.2.0] - 2021-10-26
### Added
Support for WebAuthn protocols and APIs

- WebAuthn\RegistrationResponse
- WebAuthn\LoginResponse

## [1.1.0] - 2021-10-25
### Added
- AttestationCertificate
- AttestationCertificateInterface
- ECPublicKey
- KeyHandleInterface
- LoginResponseInterface
- PublicKeyInterface
- RegistrationInterface
- RegistrationResponseInterface

### Changed
- Type information improved throughout
- RegisterResponse implements RegistrationResponseInterface
- Registration implements RegistrationInterface
- SignResponse implements LoginResponseInterface-

## [1.0.1] - 2019-06-07
### Changed
- Handle missing `cid_pubkey` field in response client data

## [1.0.0] - 2018-04-29
Initial Release
