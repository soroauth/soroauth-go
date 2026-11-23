/**
 * Offline passkey signing for a Soroban authorization entry.
 *
 * The page is deliberately dependency-free beyond the locally built
 * `./dist/` assets: the WASM core derives the preimage and payload, builds the
 * passkey signature ScVal, and writes it onto the entry. There is no Stellar
 * SDK import and no fetch after the module loads, which is what makes the
 * no-network test meaningful.
 *
 * What this file verifies before it returns a signature (all local checks):
 *   - the assertion's client data commits to the payload it was asked to sign;
 *   - the user-presence and user-verification flags are set;
 *   - the ES256 signature verifies over authenticatorData || SHA-256(clientDataJSON).
 *
 * What it does not decide: whether the wallet contract accepts the signature,
 * whether the key is a signer of the account, or whether the transaction will
 * succeed. Those belong to the contract and the ledger. See README.md.
 */

import { loadSoroauth } from "./dist/index.js";

const STORAGE_KEY = "soroauth.offline.passkey";
const RP_NAME = "soroauth offline demo";

const $ = (id) => document.getElementById(id);
const log = (message) => {
  const line = `${new Date().toISOString().slice(11, 19)}  ${message}`;
  const target = $("log");
  if (target) target.textContent += `${line}\n`;
  console.log(line);
};

const bytesToBase64 = (bytes) =>
  btoa(String.fromCharCode(...bytes));

const bytesToHex = (bytes) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const base64urlToBytes = (value) =>
  Uint8Array.from(
    atob(value.replace(/-/g, "+").replace(/_/g, "/")),
    (character) => character.charCodeAt(0),
  );

const toBase64url = (bytes) =>
  bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

/** Decode one CBOR item. Attestation objects and COSE keys need nothing more. */
function decodeCBOR(bytes) {
  let offset = 0;
  const readLength = (additional) => {
    if (additional < 24) return additional;
    if (additional === 24) return bytes[offset++];
    if (additional === 25) {
      const value = (bytes[offset++] << 8) | bytes[offset++];
      return value;
    }
    if (additional === 26) {
      const value =
        (bytes[offset++] << 24) |
        (bytes[offset++] << 16) |
        (bytes[offset++] << 8) |
        bytes[offset++];
      return value >>> 0;
    }
    throw new Error("unsupported CBOR length");
  };
  const read = () => {
    const initial = bytes[offset++];
    const major = initial >> 5;
    const additional = initial & 0x1f;
    const length = readLength(additional);
    if (major === 0) return length;
    if (major === 1) return -1 - length;
    if (major === 2) {
      const slice = bytes.slice(offset, offset + length);
      offset += length;
      return slice;
    }
    if (major === 3) {
      const slice = bytes.slice(offset, offset + length);
      offset += length;
      return new TextDecoder().decode(slice);
    }
    if (major === 4) {
      const items = [];
      for (let i = 0; i < length; i++) items.push(read());
      return items;
    }
    if (major === 5) {
      const map = {};
      for (let i = 0; i < length; i++) map[String(read())] = read();
      return map;
    }
    throw new Error(`unsupported CBOR major type ${major}`);
  };
  return read();
}

/** The credential public key in uncompressed SEC1 form, 0x04 || X || Y. */
function uncompressedPublicKey({ x, y }) {
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1 + (32 - x.length));
  out.set(y, 33 + (32 - y.length));
  return out;
}

/** DER ECDSA-Sig-Value to the fixed-width r || s the wallet contract decodes. */
function deriveCompactSignature(der) {
  if (der[0] !== 0x30) {
    throw new Error("the assertion signature is not DER-encoded");
  }
  let offset = 2;
  if (der[1] & 0x80) {
    offset = 2 + (der[1] & 0x7f);
  }
  if (der[offset] !== 0x02) {
    throw new Error("the assertion signature has no r value");
  }
  const rLength = der[offset + 1];
  const r = der.slice(offset + 2, offset + 2 + rLength);
  offset += 2 + rLength;
  if (der[offset] !== 0x02) {
    throw new Error("the assertion signature has no s value");
  }
  const sLength = der[offset + 1];
  const s = der.slice(offset + 2, offset + 2 + sLength);
  const out = new Uint8Array(64);
  out.set(r.slice(-32), 32 - Math.min(32, r.length));
  out.set(s.slice(-32), 64 - Math.min(32, s.length));
  return out;
}

function loadCredential() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    throw new Error("no passkey registered yet: register one first");
  }
  const parsed = JSON.parse(raw);
  return {
    id: parsed.id,
    publicKey: { x: new Uint8Array(parsed.x), y: new Uint8Array(parsed.y) },
  };
}

async function registerPasskey() {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: RP_NAME, id: location.hostname },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "offline@localhost",
        displayName: "soroauth offline demo",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { userVerification: "required" },
    },
  });
  if (!credential) {
    throw new Error("registration was cancelled");
  }
  const attestation = decodeCBOR(
    new Uint8Array(credential.response.attestationObject),
  );
  // WebAuthn §6.5.1: authData is rpIdHash(32) || flags(1) || signCount(4) ||
  // attestedCredentialData, and the COSE key is the tail of that structure
  // after aaguid(16) and the two-byte credential-id length. Decoding authData
  // as one CBOR item would read the first random hash byte as a type tag.
  const authData = new Uint8Array(attestation.authData);
  const credentialIDLength = (authData[53] << 8) | authData[54];
  const cose = decodeCBOR(authData.slice(55 + credentialIDLength));
  const x = new Uint8Array(cose[-2] ?? cose["-2"]);
  const y = new Uint8Array(cose[-3] ?? cose["-3"]);
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      id: toBase64url(new Uint8Array(credential.rawId)),
      x: Array.from(x),
      y: Array.from(y),
    }),
  );
  log(`registered a passkey for ${location.hostname}`);
}

function verifyChallengeBinding(clientDataJSON, payloadBytes) {
  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
  if (clientData.type !== "webauthn.get") {
    throw new Error("the assertion is not a webauthn.get ceremony");
  }
  const expected = toBase64url(payloadBytes);
  if (clientData.challenge !== expected) {
    throw new Error(
      "the assertion does not commit to this payload (challenge binding failed)",
    );
  }
}

/**
 * Sign one payload with the stored passkey and return the uncompressed public
 * key and the fixed-width low-S signature. Every check here is local; nothing
 * is sent anywhere.
 */
async function signPayloadWithPasskey(payloadBytes, credential) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: payloadBytes,
      rpId: location.hostname,
      allowCredentials: [
        {
          id: base64urlToBytes(credential.id),
          type: "public-key",
        },
      ],
      userVerification: "required",
      timeout: 60_000,
    },
  });
  if (!assertion) {
    throw new Error("the assertion was cancelled");
  }

  const authenticatorData = new Uint8Array(
    assertion.response.authenticatorData,
  );
  const clientDataJSON = new Uint8Array(assertion.response.clientDataJSON);
  const derSignature = new Uint8Array(assertion.response.signature);

  verifyChallengeBinding(clientDataJSON, payloadBytes);

  // WebAuthn Level 3 §6.1: the signed bytes are
  // authenticatorData || SHA-256(clientDataJSON).
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", clientDataJSON),
  );
  const flags = authenticatorData[32];
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0) {
    throw new Error("the assertion is missing user presence or verification");
  }
  const signed = new Uint8Array(authenticatorData.length + clientDataHash.length);
  signed.set(authenticatorData, 0);
  signed.set(clientDataHash, authenticatorData.length);

  const key = await crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: toBase64url(credential.publicKey.x),
      y: toBase64url(credential.publicKey.y),
      ext: true,
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  // WebCrypto's ECDSA format is the fixed-width r || s concatenation, while
  // WebAuthn delivers DER. Convert once, verify the same bytes the wallet
  // contract will receive, and return those bytes.
  const rawSignature = deriveCompactSignature(derSignature);
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    rawSignature,
    signed,
  );
  if (!valid) {
    throw new Error("the assertion signature does not verify");
  }

  return {
    publicKey: uncompressedPublicKey(credential.publicKey),
    signature: rawSignature,
  };
}

let soroauth;

async function signEntry() {
  const entry = $("entry").value.trim();
  const wallet = $("wallet").value.trim();
  const network = $("network").value.trim();
  const validUntil = Number($("validUntil").value);

  if (!entry) throw new Error("an unsigned entry is required");
  if (!wallet) throw new Error("the address to sign for is required");
  if (!network) throw new Error("a network passphrase is required");
  if (!Number.isInteger(validUntil) || validUntil <= 0) {
    throw new Error("the expiration must be a positive ledger number");
  }

  const credential = loadCredential();
  const { payloadHex } = soroauth.preimage(entry, validUntil, network);
  log(`derived payload ${payloadHex}`);
  const payloadBytes = Uint8Array.from(payloadHex.match(/../g), (byte) =>
    parseInt(byte, 16),
  );

  const produced = await signPayloadWithPasskey(payloadBytes, credential);
  log("the passkey produced a signature this page verified locally");

  // The ScVal is built by the same Go code the native library uses, so the
  // page does not carry a second XDR encoder that could drift from it.
  const signatureScval = soroauth.passkeySignature(
    bytesToHex(produced.publicKey),
    bytesToHex(produced.signature),
  );
  const signed = soroauth.writeSignature(
    entry,
    validUntil,
    network,
    wallet,
    signatureScval,
  );
  $("signed").value = signed;
  window.__offlineSignedEntry = signed;
  log(`signed entry written for ${wallet}`);
}

async function main() {
  const go = globalThis.Go;
  if (!go) {
    throw new Error("the local wasm_exec.js did not define Go");
  }
  soroauth = await loadSoroauth({
    wasm: new URL("./dist/soroauth.wasm", import.meta.url).href,
    go,
  });

  $("register").addEventListener("click", async () => {
    try {
      await registerPasskey();
    } catch (error) {
      log(`registration failed: ${error.message}`);
    }
  });
  $("sign").addEventListener("click", async () => {
    try {
      await signEntry();
    } catch (error) {
      log(`signing failed: ${error.message}`);
    }
  });

  // The test waits for this flag before it starts failing the run on any
  // request: everything this page needs has loaded by now.
  window.__offlineReady = true;
  log("offline signing core loaded; no network is needed from here");
}

main().catch((error) => {
  log(`startup failed: ${error.message}`);
  window.__offlineStartupError = error.message;
});
