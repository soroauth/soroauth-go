/**
 * A runnable browser demo for issue #55: create a passkey, sign a Soroban
 * authorization entry with it, and write the signature back onto the entry.
 *
 * The signing path is the point of the demo, so it is deliberately local:
 *
 *   1. the unsigned entry (from a record-mode `simulateTransaction`) is loaded;
 *   2. the WASM signing core derives the preimage and the 32-byte payload in the
 *      browser — the server never tells the browser what to sign;
 *   3. the payload is used as the WebAuthn challenge, and the authenticator
 *      returns an assertion over authenticatorData || SHA-256(clientDataJSON);
 *   4. the assertion is verified here (challenge binding, UP/UV, ES256) and
 *      turned into the signature ScVal the wallet contract's `__check_auth`
 *      decodes;
 *   5. the WASM core writes that ScVal onto every credential node whose address
 *      is the wallet, and returns the signed entry.
 *
 * What this demo does NOT do — and why — is stated in README.md: it stops at the
 * signed entry. Submitting requires a deployed wallet contract and the
 * two-pass (record-then-enforce) simulation flow, both of which belong to the
 * caller's application. Claiming otherwise would be the easy lie.
 *
 * Dependencies are loaded from CDNs so the file you are reading is the whole
 * program:
 *   - @stellar/stellar-sdk for XDR and strkey;
 *   - @soroauth/wasm from ../../wasm/dist, built by ../../wasm/build.sh.
 */

import * as StellarSdk from "https://esm.sh/@stellar/stellar-sdk@17.1.0";

const $ = (id) => document.getElementById(id);
const log = (message) => {
  const line = `${new Date().toISOString().slice(11, 19)}  ${message}`;
  ($("log") || { textContent: "" }).textContent += `${line}\n`;
  console.log(line);
};

const base64urlToBytes = (value) =>
  Uint8Array.from(
    atob(value.replace(/-/g, "+").replace(/_/g, "/")),
    (character) => character.charCodeAt(0),
  );

const bytesToHex = (bytes) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const bytesToBase64 = (bytes) => btoa(String.fromCharCode(...bytes));

function passkeySignatureScVal(publicKeyRaw, signatureRaw) {
  const { xdr } = StellarSdk;
  const key = new xdr.ScSymbol("public_key");
  const sig = new xdr.ScSymbol("signature");
  const map = new xdr.ScMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol(key),
      val: xdr.ScVal.scvBytes(publicKeyRaw),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol(sig),
      val: xdr.ScVal.scvBytes(signatureRaw),
    }),
  ]);
  return xdr.ScVal.scvMap(map);
}

function loadCredential() {
  const raw = localStorage.getItem("soroauth.passkey.credential");
  if (!raw) {
    throw new Error("no passkey registered yet: click the button once to register");
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
      rp: { name: "soroauth demo", id: location.hostname },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "demo@localhost",
        displayName: "soroauth demo",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { userVerification: "required" },
    },
  });
  if (!credential) {
    throw new Error("registration was cancelled");
  }
  const response = credential.response;
  const attestation = decodeCBOR(new Uint8Array(response.attestationObject));
  const authData = attestation.authData;
  const credentialData = decodeCBOR(authData);
  const cose = credentialData.publicKey;
  const x = new Uint8Array(cose[-2]);
  const y = new Uint8Array(cose[-3]);

  localStorage.setItem(
    "soroauth.passkey.credential",
    JSON.stringify({ id: bytesToBase64(new Uint8Array(credential.rawId)), x: Array.from(x), y: Array.from(y) }),
  );
  log(`registered a passkey for ${location.hostname}`);
}

async function signPayloadWithPasskey(payloadHex, publicKey) {
  const payload = Uint8Array.from(payloadHex.match(/../g), (byte) => parseInt(byte, 16));
  const credential = loadCredential();

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: payload,
      rpId: location.hostname,
      allowCredentials: [{ id: base64urlToBytes(credential.id.replace(/=+$/, "")), type: "public-key" }],
      userVerification: "required",
      timeout: 60_000,
    },
  });
  if (!assertion) {
    throw new Error("the assertion was cancelled");
  }

  const authenticatorData = new Uint8Array(assertion.response.authenticatorData);
  const clientDataJSON = new Uint8Array(assertion.response.clientDataJSON);
  const derSignature = new Uint8Array(assertion.response.signature);

  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
  if (bytesToHex(clientDataHash) !== payloadHex) {
    throw new Error("the assertion does not commit to this payload (challenge binding failed)");
  }

  const flags = authenticatorData[32];
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0) {
    throw new Error("the assertion is missing user presence or user verification");
  }

  const signed = new Uint8Array(authenticatorData.length + clientDataHash.length);
  signed.set(authenticatorData, 0);
  signed.set(clientDataHash, authenticatorData.length);

  const key = await crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: bytesToBase64(publicKey.x).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
      y: bytesToBase64(publicKey.y).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
      ext: true,
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    derSignature,
    signed,
  );
  if (!valid) {
    throw new Error("the assertion signature does not verify");
  }

  const rawSignature = deriveCompactSignature(derSignature);
  return passkeySignatureScVal(publicKey.x, rawSignature);
}

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
      const value = (bytes[offset++] << 24) | (bytes[offset++] << 16) | (bytes[offset++] << 8) | bytes[offset++];
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
    if (major === 5) {
      const map = {};
      for (let i = 0; i < length; i++) {
        map[read()] = read();
      }
      return map;
    }
    throw new Error(`unsupported CBOR major type ${major}`);
  };
  return read();
}

const readInputs = () => ({
  entry: ($("entry") || { value: "" }).value.trim(),
  wallet: ($("wallet") || { value: "" }).value.trim(),
  validUntil: Number(($("validUntil") || { value: "0" }).value),
  network: ($("network") || { value: "" }).value,
  rpc: ($("rpc") || { value: "" }).value,
});

async function loadCore() {
  if (!globalThis.Go) {
    throw new Error("wasm_exec.js did not load: build it with ./wasm/build.sh and reload");
  }
  const go = new globalThis.Go();
  const wasm = await fetch("../../wasm/dist/soroauth.wasm");
  if (!wasm.ok) {
    throw new Error(`could not fetch the wasm core (HTTP ${wasm.status}); run ./wasm/build.sh first`);
  }
  const { instance } = await WebAssembly.instantiate(await wasm.arrayBuffer(), go.importObject);
  void go.run(instance);

  for (let attempts = 0; attempts < 500; attempts++) {
    if (globalThis.soroauth) {
      const raw = globalThis.soroauth;
      return {
        preimage(entry, validUntil, network) {
          const result = raw.preimage(entry, validUntil, network);
          if (!result || result.ok !== true) {
            throw new Error(`preimage: ${result?.error ?? "the module returned no result"}`);
          }
          return { preimageXdr: result.preimageXdr, payloadHex: result.payloadHex };
        },
        writeSignature(entry, validUntil, network, forAddress, signatureXdr) {
          const result = raw.writeSignature(entry, validUntil, network, forAddress, signatureXdr);
          if (!result || result.ok !== true) {
            throw new Error(`writeSignature: ${result?.error ?? "the module returned no result"}`);
          }
          return result.entryB64;
        },
      };
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("the wasm core did not install its bindings within 5 seconds");
}

async function main() {
  const runBtn = $("run");
  if (runBtn) {
    const soroauth = await loadCore();
    log("loaded the soroauth WASM signing core");
    runBtn.addEventListener("click", async () => {
      try {
        const inputs = readInputs();
        if (!inputs.entry) throw new Error("paste an unsigned entry first");
        if (!inputs.wallet) throw new Error("enter the wallet's C… address");

        let credential;
        try {
          credential = loadCredential();
        } catch {
          await registerPasskey();
          credential = loadCredential();
        }

        const { payloadHex } = soroauth.preimage(inputs.entry, inputs.validUntil, inputs.network);
        log(`derived payload ${payloadHex}`);

        const signature = await signPayloadWithPasskey(payloadHex, credential.publicKey);
        const signatureXdr = signature.toXDR("base64");
        log("the passkey produced a verified signature ScVal");

        const signed = soroauth.writeSignature(
          inputs.entry,
          inputs.validUntil,
          inputs.network,
          inputs.wallet,
          signatureXdr,
        );
        log("signed entry (base64 XDR):");
        log(signed);
      } catch (error) {
        log(`error: ${error.message}`);
        console.error(error);
      }
    });
  }
}

main().catch((error) => {
  log(`failed to start: ${error.message}`);
  console.error(error);
});

export { deriveCompactSignature, passkeySignatureScVal };
