// WebAssembly System Interface (WASI) parity harness.
//
// Runs the WASI build of the signing core under Node's built-in WASI runtime
// and replays every golden vector through it, asserting that the preimage, the
// payload and the final signed entry are byte-identical to the recorded
// values. The vectors are what the native Go build and @stellar/stellar-sdk
// already agree on, so matching them here is the evidence that the WASI build
// emits the same bytes as the browser build and the library.
//
// The module is exercised as a sandboxed host would use it: one JSON request on
// stdin, one JSON response on stdout, no filesystem, no network, no environment.
//
// Usage: node wasm/wasi-parity.mjs [--wasm wasm/dist/soroauth.wasi.wasm] [--vectors testdata/vectors]
// Exit status is 0 only when every vector matched and at least one was checked.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const RUNNER = join(HERE, "wasi-run.mjs");

// A fixed seed for the source-account pass-through probe. It is never used to
// sign anything -- the pass-through returns the entry before a signer is
// consulted -- it just has to be a valid 32-byte seed.
const PROBE_SEED = "00".repeat(32);

function parseArgs(argv) {
  let wasm = join(HERE, "dist", "soroauth.wasi.wasm");
  let vectors = join(ROOT, "testdata", "vectors");
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--wasm") wasm = resolve(argv[++i]);
    else if (argv[i] === "--vectors") vectors = resolve(argv[++i]);
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return { wasm, vectors };
}

// call runs one request through the module and throws on a {ok:false}
// envelope, matching the TypeScript wrapper's behavior.
function call(wasm, request) {
  const result = spawnSync(
    process.execPath,
    ["--no-warnings", RUNNER, wasm],
    { input: JSON.stringify(request), encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `${request.op}: WASI process exited ${result.status}: ${(result.stderr || "").trim()}`,
    );
  }
  let response;
  try {
    response = JSON.parse(result.stdout);
  } catch (err) {
    throw new Error(`${request.op}: response was not JSON (${err.message}): ${result.stdout}`);
  }
  if (!response || response.ok !== true) {
    throw new Error(`${request.op}: ${(response && response.error) || "unknown error"}`);
  }
  return response;
}

function sha256Hex(label) {
  return createHash("sha256").update(label).digest("hex");
}

function loadVectors(dir) {
  const names = readdirSync(dir)
    .filter((n) => n.endsWith(".json"))
    .sort();
  if (names.length === 0) throw new Error(`no vectors found in ${dir}`);
  return names.map((n) => JSON.parse(readFileSync(join(dir, n), "utf8")));
}

function vectorsMatch(wasm, vector) {
  // A multisig step needs several seeds composed into one signature vector.
  // The binding exposes single-seed signing, exactly as the js/wasm binding
  // does, so this case is skipped loudly rather than replayed with a different
  // API that would prove something else.
  if (vector.steps.some((step) => step.multisig)) {
    return {
      status: "skip",
      detail:
        "multisig signed entry: the WASI binding exposes single-seed signing " +
        "and AccountMultiSigner is proven by its unit tests and e2e scenario C",
    };
  }

  // A source-account entry has no preimage. Exercise the pass-through instead:
  // authorizeWithSeed must hand the entry back byte-identical.
  let preimage;
  try {
    preimage = call(wasm, {
      op: "preimage",
      entry: vector.unsigned_entry_xdr,
      validUntilLedger: vector.valid_until_ledger,
      networkPassphrase: vector.network_passphrase,
    });
  } catch (err) {
    if (!/source.account/i.test(err.message)) throw err;
    const passed = call(wasm, {
      op: "authorizeWithSeed",
      entry: vector.unsigned_entry_xdr,
      validUntilLedger: vector.valid_until_ledger,
      networkPassphrase: vector.network_passphrase,
      seedHex: PROBE_SEED,
      forAddress: "",
    }).entryB64;
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

  // The standalone payload op must agree with the one computed from the entry;
  // a remote signer that only receives the preimage depends on it.
  const standalone = call(wasm, {
    op: "payload",
    preimage: preimage.preimageXdr,
  }).payloadHex;
  if (standalone !== vector.payload_hex) {
    return { status: "mismatch", detail: "payload(preimage) differs from recorded payload" };
  }

  // Replay every signing step, exactly as golden_test.go does.
  let current = vector.unsigned_entry_xdr;
  for (const step of vector.steps) {
    current = call(wasm, {
      op: "authorizeWithSeed",
      entry: current,
      validUntilLedger: vector.valid_until_ledger,
      networkPassphrase: vector.network_passphrase,
      seedHex: sha256Hex(step.signer_label),
      forAddress: step.for_address ?? "",
    }).entryB64;
  }
  if (current !== vector.signed_entry_xdr) {
    return { status: "mismatch", detail: "signed entry differs" };
  }

  return { status: "match", detail: "" };
}

function main() {
  const { wasm, vectors } = parseArgs(process.argv.slice(2));
  console.log("WebAssembly System Interface parity harness (Node WASI)");
  console.log(`wasm:    ${wasm}`);
  console.log(`vectors: ${vectors}`);

  const cases = loadVectors(vectors);

  let matched = 0;
  let mismatched = 0;
  let skipped = 0;

  for (const vector of cases) {
    const result = vectorsMatch(wasm, vector);
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
    `\nWASI parity: ${matched} matched, ${skipped} skipped, ${mismatched} mismatched (of ${cases.length})`,
  );

  if (mismatched > 0) {
    console.error(
      "\nThe WASI build does not reproduce the native golden vectors. Do not edit a vector; fix the module.",
    );
    return 1;
  }
  if (matched === 0) {
    console.error("nothing was actually checked; refusing to report success");
    return 1;
  }
  return 0;
}

process.exit(main());
