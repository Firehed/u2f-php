const log = (data) => {

  if (typeof data === 'object') {
    data = {...data}
    if (data.password !== undefined) {
      data.password = '**redacted**'
    }
  }
  console.log(data)

  if (typeof data === 'object') {
    data = JSON.stringify(data)
  }
  document.getElementById("log").value += data + "\n\n";

}

const POST = async (url, data) => {
  return fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
    },
    mode: 'no-cors',
    body: JSON.stringify(data)
  })
}

const fromBase64Web = s => atob(s.replace(/\-/g,'+').replace(/_/g,'/'))

const sleep = async (ms) => new Promise(resolve => setTimeout(resolve, ms))

const getRegistrationChallenge = async () => {
  const response = await fetch('/getRegisterChallenge.php')
  const challenge = await response.json()
  log("Registration challenge from server")
  log(challenge)
  return challenge
}

const getLoginChallenge = async () => {
  const response = await fetch('/getLoginChallenge.php')
  const challenge = await response.json()
  log("Login challenge from server")
  log(challenge)
  return challenge
}

const getCreationOptions = async () => {
  const userId = "UZSL85T9AFC"
  const challenge = await getRegistrationChallenge()

  return {
    rp: {
      name: "Duo Security",
      // id: "duosecurity.com",
    },
    user: {
      id: Uint8Array.from(userId, c => c.charCodeAt(0)),
      name: "lee@webauthn.guide",
      displayName: "Lee",
    },

    challenge: Uint8Array.from(challenge, c => c.charCodeAt(0)),
    pubKeyCredParams: [{alg: -7, type: "public-key"}],

    timeout: 60000,
    // excludeCredentials
    authenticatorSelection: {
      authenticatorAttachment: "cross-platform",
      userVerification: "preferred",
    },
    attestation: "direct"
  }
}


const getLoginOptions = async () => {
  const challenges = await getLoginChallenge()
  return {
    // FIXME: reintegrate this with single-challenge format
    challenge: Uint8Array.from(challenges.challenge, c => c.charCodeAt(0)),
    allowCredentials: challenges.key_handles.map(kh => ({
      id: Uint8Array.from(fromBase64Web(kh), c => c.charCodeAt(0)),
      type: 'public-key',
      transports: ['usb', 'ble', 'nfc'],
    })),
    timeout: 60000,
  }
}

const sendRegistration = async (publicKeyCredential) => {
  // turn ArrayBuffers to int arrays
  const dataToSend = {
    id: publicKeyCredential.id,
    rawId: new Uint8Array(publicKeyCredential.rawId),
    type: publicKeyCredential.type,
    response: {
      attestationObject: new Uint8Array(publicKeyCredential.response.attestationObject),
      clientDataJSON: new Uint8Array(publicKeyCredential.response.clientDataJSON),
    },
  }
  log("will POST dataToSend")
  log(dataToSend)

  const response = await POST('/verifyRegisterChallenge.php', dataToSend)
  const responseJson = await response.json()
  return responseJson

}

const sendLogin = async (assertion) => {
  const dataToSend = {
    rawId: new Uint8Array(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: new Uint8Array(assertion.response.authenticatorData),
      clientDataJSON: new Uint8Array(assertion.response.clientDataJSON),
      signature: new Uint8Array(assertion.response.signature),
      // userHandle: 
    },
  }
  log('login dts')
  log(dataToSend)

  const response = await POST('/verifyLoginChallenge.php', dataToSend)
  const responseJson = await response.json()
  return responseJson
}

const registerKey = async (e) => {
  e.preventDefault()
  const publicKeyCredentialCreationOptions = await getCreationOptions()
  log("PK Creation Options")
  log(publicKeyCredentialCreationOptions)

  const credential = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions
  });

  log("Credential")
  log(credential)

  let response = await sendRegistration(credential)
  let responseJson = await response.json()
  log(responseJson)
  return responseJson
}

const loginWithKey = async (e) => {
  e.preventDefault()
  const publicKeyCredentialRequestOptions = await getLoginOptions()
  log("Login options")
  log(publicKeyCredentialRequestOptions)

  const assertion = await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions
  });
  log("assertion")
  log(assertion)

  const loginResponse = await sendLogin(assertion)
  log("login response")
  log(loginResponse)
}

const registerAccount = async (e) => {
  e.preventDefault()
  const registrationData = {
    username: document.getElementById('register_username').value,
    password: document.getElementById('register_password').value,
  }

  log(registrationData)
  const response = await POST('/registerAccount.php', registrationData)
  const result = await response.json()
  log(result)
}

const loginToExistingAccount = async (e) => {
  e.preventDefault()
  const loginData = {
    username: document.getElementById('login_username').value,
    password: document.getElementById('login_password').value,
  }
  log(loginData)

  const response = await POST('/loginToAccount.php', loginData)
  const result = await response.json()
  log(result)
}

const setup = () => {
  log('Performing setup')
  if (navigator.credentials === undefined) {
    log("WebAuthn not supported in this browser :(")
    return
  }

  document.getElementById('register').addEventListener('submit', registerAccount)
  document.getElementById('login').addEventListener('submit', loginToExistingAccount)

  document.getElementById('add_key').addEventListener('submit', registerKey)
  document.getElementById('login_with_key').addEventListener('submit', loginWithKey)
  log('Event listeners bound')
}
setup()
