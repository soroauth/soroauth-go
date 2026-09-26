// WebAssembly parity harness.
//
// Loads the js/wasm build of the signing core and replays every golden vector
// through it, asserting that the preimage, the payload and the final signed
// entry are byte-identical to the recorded values. The vectors are what the
// native Go build and @stellar/stellar-sdk already agree on, so matching them
// here is the evidence that the wasm build did not change the bytes.
//
// The harness talks to the module exactly as a browser would: it passes base64
// XDR strings in and reads base64 XDR strings out. A source-account entry has
// no preimage (the transaction envelope covers it), so it is exercised through
// the pass-through path instead and reported as skipped, loudly, with the
// reason.
//
// Usage: node wasm/parity.mjs [--wasm wasm/dist/soroauth.wasm] [--vectors testdata/vectors]
// Exit status is 0 only when every vector matched and at least one was checked.

import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

// A fixed seed for the source-account pass-through probe. It is never used to
// sign anything -- the pass-through returns the entry before a signer is
// consulted -- it just has to be a valid 32-byte seed.
const PROBE_SEED = "00".repeat(32);

function parseArgs(argv) {
  let wasm = join(HERE, "dist", "soroauth.wasm");
  let vectors = join(ROOT, "testdata", "vectors");
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--wasm") wasm = resolve(argv[++i]);
    else if (argv[i] === "--vectors") vectors = resolve(argv[++i]);
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return { wasm, vectors };
}

// loadRuntime installs the globals wasm_exec.js expects and evaluates it,
// leaving globalThis.Go defined. The shim is copied next to the wasm by
// wasm/build.sh so the two always match.
async function loadRuntime(wasmPath) {
  const require = createRequire(import.meta.url);
  globalThis.require = require;
  globalThis.fs = require("node:fs");
  globalThis.path = require("node:path");

  const shim = join(dirname(wasmPath), "wasm_exec.js");
  let source;
  try {
    source = readFileSync(shim, "utf8");
  } catch {
    throw new Error(
      `missing ${shim}; run wasm/build.sh to produce the module and its runtime shim`,
    );
  }
  // The shim is a plain IIFE that defines globalThis.Go; evaluating it as a
  // script (not as a module) matches how a browser script tag would load it.
  (0, eval)(source);

  const go = new globalThis.Go();
  go.argv = ["soroauth.wasm"];
  go.env = {};

  const bytes = readFileSync(wasmPath);
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);

  // The Go program blocks in select{} after it installs its bindings, so this
  // promise never settles. Do not await it.
  go.run(instance);

  // Wait for main to install the bindings. Bounded so a broken module fails
  // loudly instead of hanging the job.
  for (let i = 0; i < 1000; i++) {
    if (globalThis.soroauth) return globalThis.soroauth;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("timed out waiting for globalThis.soroauth from the wasm module");
}

function sha256Hex(label) {
  return createHash("sha256").update(label).digest("hex");
}

// call invokes a binding and throws on a {ok:false} envelope, the same way the
// TypeScript wrapper does.
function call(api, name, ...args) {
  const fn = api[name];
  if (typeof fn !== "function") throw new Error(`module does not export ${name}`);
  const result = fn(...args);
  if (!result || result.ok !== true) {
    throw new Error(`${name}: ${(result && result.error) || "unknown error"}`);
  }
  return result;
}

function loadVectors(dir) {
  const names = readdirSync(dir)
    .filter((n) => n.endsWith(".json"))
    .sort();
  if (names.length === 0) throw new Error(`no vectors found in ${dir}`);
  return names.map((n) => JSON.parse(readFileSync(join(dir, n), "utf8")));
}

function vectorsMatch(api, vector) {
  // A source-account entry has no preimage. Exercise the pass-through instead:
  // authorizeWithSeed must hand the entry back byte-identical.
  let preimage;
  try {
    preimage = call(api, "preimage", vector.unsigned_entry_xdr, vector.valid_until_ledger, vector.network_passphrase);
  } catch (err) {
    if (!/source.account/i.test(err.message)) throw err;
    const passed = call(
      api, "authorizeWithSeed",
      vector.unsigned_entry_xdr, vector.valid_until_ledger,
      vector.network_passphrase, PROBE_SEED, "",
    ).entryB64;
    if (passed !== vector.unsigned_entry_xdr) {
      return { status: "mismatch", detail: "source-account pass-through changed the entry" };
    }
    return {
      status: "skip",
      detail: `no preimage: credential_type=source_account (pass-through verified): ${err.message}`,
    };
  }

  if (preimage.preimageXdr !== vector.preimage_xdr) {
    return { status: "mismatch", detail: "preimage differs" };
  }
  if (preimage.payloadHex !== vector.payload_hex) {
    return { status: "mismatch", detail: "payload differs" };
  }

  // The standalone payload entry point must agree with the one computed from
  // the entry; a remote signer that only receives the preimage depends on it.
  const standalone = call(api, "payload", preimage.preimageXdr).payloadHex;
  if (standalone !== vector.payload_hex) {
    return { status: "mismatch", detail: "payload(preimage) differs from recorded payload" };
  }

  // Replay every signing step, exactly as golden_test.go does.
  let current = vector.unsigned_entry_xdr;
  for (const step of vector.steps) {
    current = call(
      api, "authorizeWithSeed",
      current, vector.valid_until_ledger, vector.network_passphrase,
      sha256Hex(step.signer_label), step.for_address ?? "",
    ).entryB64;
  }
  if (current !== vector.signed_entry_xdr) {
    return { status: "mismatch", detail: "signed entry differs" };
  }

  return { status: "match", detail: "" };
}

async function main() {
  const { wasm, vectors } = parseArgs(process.argv.slice(2));
  console.log("WebAssembly parity harness");
  console.log(`wasm:    ${wasm}`);
  console.log(`vectors: ${vectors}`);

  const api = await loadRuntime(wasm);
  const cases = loadVectors(vectors);

  let matched = 0;
  let mismatched = 0;
  let skipped = 0;

  for (const vector of cases) {
    const result = vectorsMatch(api, vector);
    if (result.status === "match") {
      matched++;
      console.log(`  ok    ${vector.name}`);
    } else if (result.status === "mismatch") {
      mismatched++;
      console.error(`  FAIL  ${vector.name}: ${result.detail}`);
    } else {
      skipped++;
      console.error(`  skip  ${vector.name}: ${result.detail}`);
    }
  }

  console.log(
    `\nWebAssembly parity: ${matched} matched, ${skipped} skipped, ${mismatched} mismatched (of ${cases.length})`,
  );

  if (mismatched > 0) {
    console.error(
      "\nThe wasm build does not reproduce the native golden vectors. Do not edit a vector; fix the module.",
    );
    return 1;
  }
  if (matched === 0) {
    console.error("nothing was actually checked; refusing to report success");
    return 1;
  }
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
