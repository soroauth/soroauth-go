# Browser demo: passkey → signed Soroban authorization entry

A self-contained browser page that signs a Soroban authorization entry with a
WebAuthn passkey, deriving the payload **in the browser** with the
`@soroauth/wasm` signing core.

This exists so the passkey story has something you can actually run, instead of
a guide you have to translate into code yourself.

## What it does

1. You paste an unsigned entry (base64 XDR) from a **record-mode**
   `simulateTransaction`, the wallet's `C…` address, the expiration ledger and
   the network passphrase.
2. The page loads `wasm/dist/soroauth.wasm` (built by `wasm/build.sh`) and calls
   `preimage(...)` to derive the `HashIdPreimage` and its 32-byte payload
   locally. No server is asked what to sign.
3. It registers a passkey if there is not one yet, then runs the assertion
   ceremony with **the payload as the WebAuthn challenge**.
4. It verifies the assertion before using it: challenge binding (hash the
   received `clientDataJSON`, compare to the payload), the UP/UV flags, and the
   ES256 signature over `authenticatorData || SHA-256(clientDataJSON)`.
5. It builds the signature ScVal and calls `writeSignature(...)`, which writes
   the signature only onto credential nodes whose address equals the wallet.

Steps 2–5 are the passkey path end to end. The result printed at the end is the
**signed authorization entry**.

## What it deliberately does not do

Submitting to the network is left to your application, because it needs two
things this demo cannot assume:

- a **deployed wallet contract** whose `__check_auth` decodes the signature
  ScVal this demo builds (the shape is the one in
  [`docs/passkeys.md`](../../docs/passkeys.md); swap `passkeySignatureScVal` in
  `app.js` if your contract differs); and
- the **two-pass simulation flow** — record mode to get the entry, then enforce
  mode with the signed entry to get correct resource fees, then assemble, sign
  the envelope as the fee payer, and submit. Skipping enforce mode fails on
  resource fees after the signature is already attached.

RPC submission is therefore listed as the next step in the page's log rather
than faked. The README's Quickstart and `adapters/walletsdk` cover the full
flow.

## How to run it

The page needs to fetch the WASM file, which a `file://` page usually cannot do,
and WebAuthn requires a secure context (`https://` or `http://localhost`).
Build the core and serve the repository over localhost:

```sh
./wasm/build.sh            # writes wasm/dist/soroauth.wasm + wasm_exec.js
python3 -m http.server 8000
```

Then open `http://localhost:8000/examples/browser-passkey/`.

A passkey created for `localhost` is scoped to `localhost`, so the demo never
touches a real relying party.

## Verification status

**This demo has not been run end to end in CI, and cannot be.** It needs a
browser, a platform authenticator, and a passkey wallet contract on testnet;
none of those exist in the build environment. The code is provided so the
manual run is a few minutes of work, not a research project.

If you run it and it fails, that is a bug report worth filing — the parts that
*are* proven (`preimage` and `writeSignature` against the golden vectors and a
live testnet scenario) live in the rest of this repository, so a failure here
most likely points at the ceremony or the contract, not the core.
