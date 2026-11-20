/**
 * Complete a signature with a passkey, in the page, next to the explanation.
 *
 * The extension's explanation panel and the signing request used to be two
 * separate moments: the panel explained one entry, and the page then asked the
 * authenticator to sign whatever it had built. This module closes that gap.
 * The payload hash shown in the panel is passed in as `expectedPayloadHex` and
 * is compared twice: before the authenticator is asked (so a changed entry is
 * never shown as the thing being signed) and after the assertion returns (so a
 * page cannot substitute bytes while the user is looking at the dialog). A
 * mismatch throws; there is no code path that signs after a mismatch.
 *
 * The signature conversion is not implemented here. `core.passkeySignature`
 * calls the Go library's `Secp256r1SignatureScValFromDER` through wasm, so the
 * DER-to-low-S conversion has one implementation.
 */

/** Hex characters for a byte array. */
export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Decode a base64 or base64url string to bytes. */
export function base64ToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** Encode bytes as unpadded base64url, the WebAuthn challenge encoding. */
export function bytesToBase64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * The encodings a challenge may legitimately carry for one payload. Matching
 * the received string against known encodings avoids the ambiguity of
 * decoding first: a 64-character hexadecimal string is also valid base64url
 * and would decode to the wrong bytes under a fixed decode order.
 */
export function challengeEncodings(payloadHex) {
  const payload = Uint8Array.from(payloadHex.match(/../g) ?? [], (byte) =>
    parseInt(byte, 16),
  );
  const base64 = btoa(String.fromCharCode(...payload));
  return [
    bytesToBase64url(payload),
    base64.replace(/\+/g, "-").replace(/\//g, "_"),
    base64.replace(/=+$/, ""),
    base64,
    payloadHex,
  ];
}

/** Constant-time-ish comparison that does not exit on the first difference. */
function equalStrings(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return difference === 0;
}

/**
 * verifyAssertion checks the properties the extension can check without the
 * account contract: the assertion commits to this payload, and the user was
 * present and verified. It returns the DER signature as hex.
 *
 * It deliberately does not verify the ECDSA signature: that is the account
 * contract's job, on chain, against the key it stored at registration.
 */
export function verifyAssertion(assertion, payloadHex) {
  const response = assertion?.response;
  if (!response || !response.clientDataJSON || !response.authenticatorData || !response.signature) {
    throw new Error("the authenticator returned no assertion");
  }

  let clientData;
  try {
    clientData = JSON.parse(new TextDecoder().decode(response.clientDataJSON));
  } catch {
    throw new Error("clientDataJSON is not valid JSON");
  }
  if (clientData.type !== "webauthn.get") {
    throw new Error(
      `clientDataJSON type is ${JSON.stringify(clientData.type)}, want "webauthn.get"`,
    );
  }
  if (typeof clientData.challenge !== "string" || clientData.challenge === "") {
    throw new Error("clientDataJSON carries no challenge");
  }
  if (!challengeEncodings(payloadHex).some((candidate) => equalStrings(candidate, clientData.challenge))) {
    throw new Error("the assertion does not commit to this payload (challenge binding failed)");
  }

  const authenticatorData = new Uint8Array(response.authenticatorData);
  if (authenticatorData.length < 33) {
    throw new Error("authenticatorData is too short to carry flags");
  }
  const flags = authenticatorData[32];
  if ((flags & 0x01) === 0) {
    throw new Error("the authenticator did not assert user presence");
  }
  if ((flags & 0x04) === 0) {
    throw new Error("the authenticator did not verify the user");
  }

  return bytesToHex(new Uint8Array(response.signature));
}

/**
 * signEntryWithPasskey derives the payload, asks for confirmation with the
 * payload hash, asks the authenticator, and writes the signature onto the
 * entry. It returns `{ entryB64, payloadHex, signatureScvalB64 }`.
 *
 * `expectedPayloadHex` is the hash the user was shown. It is required: a
 * caller that has nothing to compare against is not using the hash-match
 * property, and this function refuses to guess. `confirm` may be supplied to
 * render the decision; anything other than exactly `true` is a refusal.
 *
 * A refusal or timeout from the authenticator rejects the promise and no entry
 * is returned. Nothing is written to the entry until the assertion has passed
 * every check above.
 */
export async function signEntryWithPasskey({
  core,
  entryXdr,
  validUntilLedger,
  networkPassphrase,
  publicKeyHex,
  expectedPayloadHex,
  forAddress = "",
  rpId = globalThis.location?.hostname,
  credentialId,
  allowCredentials,
  credentials = globalThis.navigator?.credentials,
  timeoutMs = 60000,
  confirm,
}) {
  if (typeof expectedPayloadHex !== "string" || expectedPayloadHex === "") {
    throw new Error("refusing to sign without the payload hash the user was shown");
  }
  if (typeof publicKeyHex !== "string" || !/^04[0-9a-fA-F]{128}$/.test(publicKeyHex)) {
    throw new Error("a passkey public key must be the 65-byte uncompressed P-256 key in hex");
  }
  if (!credentials || typeof credentials.get !== "function") {
    throw new Error("this context has no WebAuthn credentials API");
  }

  const { payloadHex } = core.preimage(entryXdr, validUntilLedger, networkPassphrase);
  if (payloadHex !== expectedPayloadHex) {
    throw new Error("the entry's payload changed between explanation and signing");
  }

  if (confirm) {
    const approved = await confirm({ payloadHex, entryXdr });
    if (approved !== true) {
      throw new Error("the signing request was refused");
    }
  }

  // Derive again after the user's decision: a page that swapped the entry while
  // the dialog was open must not have its bytes signed under the old hash.
  const afterConfirmation = core.preimage(entryXdr, validUntilLedger, networkPassphrase);
  if (afterConfirmation.payloadHex !== expectedPayloadHex) {
    throw new Error("the entry's payload changed between explanation and signing");
  }

  const publicKey = {
    challenge: Uint8Array.from(payloadHex.match(/../g) ?? [], (byte) => parseInt(byte, 16)),
    rpId,
    userVerification: "required",
    timeout: timeoutMs,
  };
  if (allowCredentials && allowCredentials.length > 0) {
    publicKey.allowCredentials = allowCredentials;
  } else if (credentialId) {
    publicKey.allowCredentials = [{ type: "public-key", id: base64ToBytes(credentialId) }];
  }

  const assertion = await credentials.get({ publicKey });
  const signatureDerHex = verifyAssertion(assertion, payloadHex);
  const signatureScvalB64 = core.passkeySignature(publicKeyHex, signatureDerHex);
  const signedEntryB64 = core.writeSignature(
    entryXdr,
    validUntilLedger,
    networkPassphrase,
    forAddress,
    signatureScvalB64,
  );
  return { entryB64: signedEntryB64, payloadHex, signatureScvalB64 };
}
