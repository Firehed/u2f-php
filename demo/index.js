const log = (str) => {
  console.log(str)

  if (typeof str === 'object') {
    str = JSON.stringify(str)
  }
  document.getElementById("log").value += str + "\n\n";

}

const getChallenge = async () => {
  const response = await fetch('/getRegisterChallenge.php')
  const challenge = await response.json()
  log("Challenge from server")
  log(challenge)
  return challenge
}

const getCreationOptions = async () => {
  const userId = "UZSL85T9AFC"
  const challenge = await getChallenge()

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

const arrayBuffertoBinaryString = (arrayBuffer) => {
  const bytes = new Uint8Array(arrayBuffer)
  let bin = ''
  const len = bytes.byteLength
  for (let i = 0; i < len; i++) {
    bin += String.fromCharCode(bytes[i])
  }
  return bin
}


const sendRegistration = async (publicKeyCredential) => {
  const utf8Decoder = new TextDecoder('utf-8');
  const decodedClientData = utf8Decoder.decode(publicKeyCredential.response.clientDataJSON)
  // log("client data json")
  // log(decodedClientData)

  // const decodedAttestationObj = utf8Decoder.decode(publicKeyCredential.response.attestationObject)
  const decodedAttestationObj = new Uint8Array(publicKeyCredential.response.attestationObject)
  log("attestationObject CBOR")
  log(CBOR.decode(publicKeyCredential.response.attestationObject))
  // log(decodedAttestationObj)
  // function buf2hex(buffer) { // buffer is an ArrayBuffer
  //   return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
  // }
  // log(buf2hex(publicKeyCredential.response.attestationObject))

  const dataToSend = {
    id: publicKeyCredential.id,
    rawId: new Uint8Array(publicKeyCredential.rawId),
    type: publicKeyCredential.type,
    clientDataJson: decodedClientData,
    attestationObjectByteArray: new Uint8Array(publicKeyCredential.response.attestationObject),
    // attestationObjectCbor: cborBlob,
  }
  log("will POST dataToSend")
  log(dataToSend)

  const response = await fetch('/verifyRegisterChallenge.php', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
    },
    mode: 'no-cors',
    body: JSON.stringify(dataToSend),
  })

  const respJson = await response.json()

  log(respJson)
  // const clientDataObj = JSON.parse(decodedClientData);
  // log("Client data obj")
  // log(clientDataObj)

}

const register = async () => {
  const publicKeyCredentialCreationOptions = await getCreationOptions()
  log("PK Creation Options")
  log(publicKeyCredentialCreationOptions)

  const credential = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions
  });

  log("Credential")
  log(credential)

  let serverRes = await sendRegistration(credential)

}


register()
