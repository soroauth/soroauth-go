// Run a WASI module once under Node's built-in WASI runtime.
//
// Usage: node wasm/wasi-run.mjs <module.wasm>
//
// The guest reads one JSON request from standard input and writes one JSON
// response to standard output; both are inherited from this process, so a
// caller pipes the request in and reads the response back. This file exists so
// the parity harness does not need a separate WASI runtime installed: Node 22
// and later ship one.
//
// It deliberately provides no arguments and no environment: the wasm core is
// documented to need stdin and stdout only, and this runner gives it nothing
// else.

import { readFileSync } from "node:fs";
import { WASI } from "node:wasi";

const modulePath = process.argv[2];
if (!modulePath) {
  console.error("usage: node wasm/wasi-run.mjs <module.wasm>");
  process.exit(2);
}

const wasi = new WASI({
  version: "preview1",
  args: [],
  env: {},
  // Return an exit code instead of throwing, so the module's status reaches
  // the caller unchanged.
  returnOnExit: true,
  stdin: 0,
  stdout: 1,
  stderr: 2,
});

const { instance } = await WebAssembly.instantiate(
  readFileSync(modulePath),
  wasi.getImportObject(),
);
process.exit(wasi.start(instance));
