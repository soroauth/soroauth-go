// Integration test: the TypeScript wrapper against the real wasm module.
//
// These run in Node rather than jsdom because the point here is the signing
// logic, not the browser surface: the wrapper is loaded with the actual Go
// runtime and the actual wasm build, and its output is compared to the golden
// vectors. Skips (loudly) when the module has not been built, so `node --test`
// stays useful on a machine without Go.
//
// Build first with: wasm/build.sh

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { loadSoroauth, SoroauthError } from "../dist/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = resolve(HERE, "..", "..", "dist");
const WASM = join(DIST, "soroauth.wasm");
const SHIM = join(DIST, "wasm_exec.js");
const VECTORS = resolve(HERE, "..", "..", "..", "testdata", "vectors");

const built = existsSync(WASM) && existsSync(SHIM);
const skip = built
  ? false
  : "wasm/dist is missing; run wasm/build.sh before this test";

/** Evaluate Go's wasm_exec.js in this realm so globalThis.Go is defined. */
function installGoRuntime() {
  const require = createRequire(import.meta.url);
  globalThis.require = require;
  globalThis.fs = require("node:fs");
  globalThis.path = require("node:path");
  (0, eval)(readFileSync(SHIM, "utf8"));
}

function sha256Hex(label) {
  return createHash("sha256").update(label).digest("hex");
}

function readVector(name) {
  return JSON.parse(readFileSync(join(VECTORS, name), "utf8"));
}

test("wrapper reproduces a legacy golden vector byte for byte", { skip }, async () => {
  installGoRuntime();
  const soroauth = await loadSoroauth({
    wasm: readFileSync(WASM),
    go: globalThis.Go,
    globalObject: globalThis,
  });

  const vector = readVector("legacy_single_testnet.json");

  const preimage = soroauth.preimage(
    vector.unsigned_entry_xdr,
    vector.valid_until_ledger,
    vector.network_passphrase,
  );
  assert.equal(preimage.preimageXdr, vector.preimage_xdr);
  assert.equal(preimage.payloadHex, vector.payload_hex);
  assert.equal(soroauth.payload(preimage.preimageXdr), vector.payload_hex);

  let signed = vector.unsigned_entry_xdr;
  for (const step of vector.steps) {
    signed = soroauth.authorizeWithSeed(
      signed,
      vector.valid_until_ledger,
      vector.network_passphrase,
      sha256Hex(step.signer_label),
      step.for_address ?? "",
    );
  }
  assert.equal(signed, vector.signed_entry_xdr);
});

test("wrapper reproduces a delegates golden vector byte for byte", { skip }, async () => {
  installGoRuntime();
  const soroauth = await loadSoroauth({
    wasm: readFileSync(WASM),
    go: globalThis.Go,
    globalObject: globalThis,
  });

  const vector = readVector("delegates_unsorted_with_nested.json");
  const preimage = soroauth.preimage(
    vector.unsigned_entry_xdr,
    vector.valid_until_ledger,
    vector.network_passphrase,
  );
  assert.equal(preimage.preimageXdr, vector.preimage_xdr);

  let signed = vector.unsigned_entry_xdr;
  for (const step of vector.steps) {
    signed = soroauth.authorizeWithSeed(
      signed,
      vector.valid_until_ledger,
      vector.network_passphrase,
      sha256Hex(step.signer_label),
      step.for_address ?? "",
    );
  }
  assert.equal(signed, vector.signed_entry_xdr);
});

test("wrapper throws a SoroauthError for a source-account entry", { skip }, async () => {
  installGoRuntime();
  const soroauth = await loadSoroauth({
    wasm: readFileSync(WASM),
    go: globalThis.Go,
    globalObject: globalThis,
  });
  const vector = readVector("source_account_testnet.json");

  assert.throws(
    () =>
      soroauth.preimage(
        vector.unsigned_entry_xdr,
        vector.valid_until_ledger,
        vector.network_passphrase,
      ),
    (err) => {
      assert.ok(err instanceof SoroauthError);
      assert.match(err.message, /source-account/);
      return true;
    },
  );
});
