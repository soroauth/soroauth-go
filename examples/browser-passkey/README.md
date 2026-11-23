# Browser passkey example

Two pages, with different jobs:

- `index.html` is the full testnet loop: build a SAC transfer, simulate, sign
  with a passkey, re-simulate in enforce mode, submit, and print the hash. It
  necessarily talks to RPC after load.
- `offline.html` is the offline signing flow: paste an unsigned entry, sign it
  with a passkey, and get the signed entry back. It makes **no request after
  load** and does not submit anything.

## Offline signing page

Build the local assets (the WASM core, the matching Go runtime shim, and the
typed wrapper), then serve this directory:

```sh
./examples/browser-passkey/build-offline.sh
python3 -m http.server 8000
# open http://localhost:8000/examples/browser-passkey/offline.html
```

`offline.html` references only `./dist/`, `./offline.js`, and `offline.html`
itself. There is no CDN, no web font, and no source-map fetch. The `dist/`
directory is a build artifact and is gitignored; the script fails loudly if the
Go or Node toolchain is missing rather than falling back to a remote copy.

The flow, entirely in the page:

1. `soroauth.preimage()` derives the preimage and 32-byte payload from the
   pasted entry, the expiration ledger, and the network passphrase.
2. The payload is the WebAuthn challenge. The assertion is checked locally:
   challenge binding, the UP and UV flags, and ES256 over
   `authenticatorData || SHA-256(clientDataJSON)`.
3. `soroauth.passkeySignature()` builds the `{public_key, signature}` ScVal with
   the same Go code the native library and the golden vectors use.
4. `soroauth.writeSignature()` writes that ScVal onto every node whose address
   matches the address you entered.

### What offline does and does not protect

Offline protects the signing step on this page: the bytes signed are derived
from the entry in the browser, the page needs no server to compute or attach the
signature, and an automated test fails on any request after load.

It does not protect against a compromised host, a malicious browser extension
with access to the page, a passkey provider that exports the key, or ledger
state the entry commits to. The host machine and the authenticator are still in
the trust boundary. Do not read "offline" as "air-gapped": a page cannot prove
what the rest of the machine is doing.

## Test

The offline test drives a real Chromium with a virtual authenticator. After the
page reports that it loaded (all local assets in memory), the test routes every
request to a violation list and aborts it, then registers a passkey and signs
the `v2_single_testnet` vector. It fails if any request is made, including fonts
and source maps.

```sh
cd examples/browser-passkey
npm ci
npx playwright install --with-deps chromium
./build-offline.sh
node offline.test.mjs
```

`app.test.mjs` is the separate Node-only check for the online page's SDK calls,
credential-arm walk, and signature shape. It is not a browser run.
