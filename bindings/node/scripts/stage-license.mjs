// Copy the repository LICENSE into the package root before packing.
//
// npm only looks inside the package directory when it decides what to put in
// the tarball, and bindings/node has no LICENSE of its own. Without this step a
// published @soroauth/node would carry no license file at all. The repository
// LICENSE is the source of truth and is never modified; this writes a build
// artifact that .gitignore excludes.

import { copyFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const REPO_ROOT = resolve(PACKAGE_ROOT, "..", "..");
const SOURCE = join(REPO_ROOT, "LICENSE");
const DESTINATION = join(PACKAGE_ROOT, "LICENSE");

if (!existsSync(SOURCE)) {
  console.error(`prepack: ${SOURCE} is missing; cannot ship a license file`);
  process.exit(1);
}

copyFileSync(SOURCE, DESTINATION);
console.log(`prepack: wrote ${DESTINATION}`);
