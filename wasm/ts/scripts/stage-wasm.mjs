// Stage the wasm module and its Go runtime shim into this package's dist/ so
// the tarball npm publishes is self-contained.
//
// The wasm binary is a build artifact and is not committed. `npm pack` and
// `npm publish` run this automatically through the `prepack` script, so the
// published package always carries the module built from the tagged commit --
// and fails loudly if that build has not happened.

import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const WASM_DIST = resolve(PACKAGE_ROOT, "..", "dist");
const DEST = join(PACKAGE_ROOT, "dist");

// SHA256SUMS is built by wasm/build.sh from the same artifacts and stages with
// them, so a consumer can verify the bytes inside the tarball against the
// digest published on the GitHub release without trusting this build.
const artifacts = ["soroauth.wasm", "wasm_exec.js", "SHA256SUMS"];

mkdirSync(DEST, { recursive: true });

for (const name of artifacts) {
  const source = join(WASM_DIST, name);
  if (!existsSync(source)) {
    console.error(
      `stage-wasm: ${source} is missing; run wasm/build.sh before packing or publishing.`,
    );
    process.exit(1);
  }
  copyFileSync(source, join(DEST, name));
  console.log(`stage-wasm: staged ${name}`);
}
