#!/usr/bin/env node
// Cross-language conformance runner for the Node binding.
//
// Reads testdata/conformance/cases.json and writes one NDJSON row per case
// to stdout, in the shape testdata/conformance/README.md documents. The CI
// job for this binding diffs this output against the Go oracle's; a
// mismatch fails the job and names the failing case.
//
// Usage:
//   node bindings/node/conformance/run.mjs testdata/conformance/cases.json [vectors-dir]

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { argv, exit, stdout } from "node:process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

let soroauth;
try {
  soroauth = require(path.resolve(path.dirname(new URL(import.meta.url).pathname), "..")).load();
} catch (err) {
  // A failure to load the binding is itself the kind of mismatch the suite
  // wants surfaced. Emit one NDJSON row naming it, then exit non-zero.
  stdout.write(
    JSON.stringify({ id: "_load", ok: false, kind: "ERROR", error: String(err) }) + "\n",
  );
  exit(1);
}

const OP_PREIMAGE = "preimage";
const OP_PAYLOAD = "payload";
const OP_AUTHORIZE_WITH_SEED = "authorize_with_seed";

function seedForLabel(label) {
  return createHash("sha256").update(label, "utf8").digest("hex");
}

function loadVector(vectorsDir, name) {
  const p = path.join(vectorsDir, `${name}.json`);
  return JSON.parse(readFileSync(p, "utf8"));
}

function resolveInputs(c, vectorsDir) {
  const inputs = {};
  if (c.vector) {
    const v = loadVector(vectorsDir, c.vector);
    inputs.entry_xdr_b64 = v.unsigned_entry_xdr;
    inputs.valid_until_ledger = v.valid_until_ledger;
    inputs.network_passphrase = v.network_passphrase;
    inputs.preimage_xdr_b64 = v.preimage_xdr;
    if (v.steps && v.steps.length > 0) {
      inputs.seed_hex = seedForLabel(v.steps[0].signer_label);
    }
  }
  Object.assign(inputs, c.input || {});
  Object.assign(inputs, c.override || {});
  return inputs;
}

function okRow(id, extra) {
  return { id, ok: true, ...extra };
}

function errRow(id, err) {
  // err.kind is set by the ABI envelope; "ERROR" is the sentinel the suite
  // accepts when the binding does not have a more specific one.
  const kind = err.kind || "ERROR";
  return { id, ok: false, kind, error: err.message || String(err) };
}

function runCase(c, vectorsDir) {
  const id = c.id;
  let inputs;
  try {
    inputs = resolveInputs(c, vectorsDir);
  } catch (err) {
    return { id, ok: false, kind: "ERROR", error: err.message || String(err) };
  }
  try {
    switch (c.op) {
      case OP_PREIMAGE: {
        const r = soroauth.preimage(
          inputs.entry_xdr_b64,
          inputs.valid_until_ledger,
          inputs.network_passphrase,
        );
        return okRow(id, { preimage_xdr: r.preimageXdr, payload_hex: r.payloadHex });
      }
      case OP_PAYLOAD: {
        const hex = soroauth.payload(inputs.preimage_xdr_b64);
        return okRow(id, { payload_hex: hex });
      }
      case OP_AUTHORIZE_WITH_SEED: {
        const signed = soroauth.authorizeWithSeed(
          inputs.entry_xdr_b64,
          inputs.valid_until_ledger,
          inputs.network_passphrase,
          inputs.seed_hex,
          inputs.for_address || "",
        );
        return okRow(id, { signed_entry_xdr: signed });
      }
      default:
        return { id, ok: false, kind: "ERROR", error: `unknown op ${c.op}` };
    }
  } catch (err) {
    return errRow(id, err);
  }
}

function main() {
  if (argv.length < 3 || argv.length > 4) {
    process.stderr.write("usage: run.mjs <cases.json> [vectors-dir]\n");
    exit(2);
  }
  const casesPath = argv[2];
  const vectorsDir = argv[3] || path.join(path.dirname(casesPath), "..", "vectors");
  const f = JSON.parse(readFileSync(casesPath, "utf8"));
  if (f.schema_version !== 1) {
    process.stderr.write(`unknown schema_version ${f.schema_version}\n`);
    exit(1);
  }
  for (const c of f.cases || []) {
    const row = runCase(c, vectorsDir);
    stdout.write(JSON.stringify(row) + "\n");
  }
}

main();
