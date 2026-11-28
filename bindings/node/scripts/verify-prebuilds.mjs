// Fail closed on an incomplete set of prebuilt bindings.
//
// A published package is only worth shipping if every platform it claims has
// both halves of the pair: the N-API addon and the Go shared library the addon
// dlopens. Checking that here -- before `npm publish` -- turns "one artifact
// failed to upload" into a red release instead of a package that throws for
// everyone on that platform.
//
// With --tarball <pack.json> it additionally checks the file list `npm pack
// --json` reported, so a tarball that dropped prebuilds/ or excluded the
// install script is caught even when the directory on disk is complete.
//
// Usage:
//   node scripts/verify-prebuilds.mjs [prebuildsDir] [--platform NAME]... [--tarball pack.json]
//
// The default is all four platforms, which is what a release must carry.
// --platform narrows the check to the set a caller actually has, for a local
// build that produced only its own machine's pair.
//
// The binary-format check reads the first bytes rather than trusting the file
// name. A wrongly labelled artifact (an x64 binary in the arm64 directory, or a
// Mach-O in a linux directory) installs successfully and then fails to load, so
// the label has to be proved, not assumed.

import { readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");

/** PLATFORMS is the complete set a release must ship, keyed by directory name. */
const PLATFORMS = {
  "linux-x64": { format: "elf", machine: 0x3e, library: "libsoroauth.so" },
  "linux-arm64": { format: "elf", machine: 0xb7, library: "libsoroauth.so" },
  "darwin-x64": { format: "macho", machine: 0x01000007, library: "libsoroauth.dylib" },
  "darwin-arm64": { format: "macho", machine: 0x0100000c, library: "libsoroauth.dylib" },
};

function fail(message) {
  console.error(`verify-prebuilds: ${message}`);
  process.exit(1);
}

/** parseArgs reads the positional directory and the optional --tarball path. */
function parseArgs(argv) {
  let dir = join(PACKAGE_ROOT, "prebuilds");
  let tarball = null;
  const platforms = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--tarball") {
      tarball = argv[index + 1];
      if (!tarball) fail("--tarball needs a path to npm pack --json output");
      index += 1;
      continue;
    }
    if (argv[index] === "--platform") {
      const platform = argv[index + 1];
      if (!platform) fail("--platform needs a directory name");
      platforms.push(platform);
      index += 1;
      continue;
    }
    dir = argv[index];
  }
  const selected = platforms.length === 0 ? Object.keys(PLATFORMS) : platforms;
  for (const platform of selected) {
    if (!PLATFORMS[platform]) fail(`unknown platform ${platform}`);
  }
  return {
    dir: resolve(dir),
    tarball: tarball === null ? null : resolve(tarball),
    platforms: selected,
  };
}

/** inspectBinary reports the format and machine a binary actually is. */
function inspectBinary(path) {
  const header = readFileSync(path).subarray(0, 24);
  if (header.length < 20) fail(`${path} is shorter than any valid binary header`);

  if (header[0] === 0x7f && header[1] === 0x45 && header[2] === 0x4c && header[3] === 0x46) {
    if (header[4] !== 2 || header[5] !== 1) fail(`${path} is not a 64-bit little-endian ELF`);
    return { format: "elf", machine: header.readUInt16LE(18) };
  }

  if (header[0] === 0xcf && header[1] === 0xfa && header[2] === 0xed && header[3] === 0xfe) {
    return { format: "macho", machine: header.readUInt32LE(4) };
  }

  fail(`${path} is neither an ELF nor a 64-bit Mach-O binary`);
  return null;
}

function checkDirectory(dir, platforms) {
  for (const platform of platforms) {
    const expected = PLATFORMS[platform];
    const platformDir = join(dir, platform);
    for (const name of ["soroauth.node", expected.library]) {
      const path = join(platformDir, name);
      let size;
      try {
        size = statSync(path).size;
      } catch {
        fail(`${path} is missing; the release must carry ${platforms.length} platform pairs`);
      }
      if (size === 0) fail(`${path} is empty`);

      const actual = inspectBinary(path);
      if (actual.format !== expected.format) {
        fail(`${path} is ${actual.format}, want ${expected.format}`);
      }
      if (actual.machine !== expected.machine) {
        fail(
          `${path} targets machine 0x${actual.machine.toString(16)}, want 0x${expected.machine.toString(16)}`,
        );
      }
    }
    console.log(`verify-prebuilds: ok ${platform} (${expected.library} + soroauth.node)`);
  }
}

function checkTarball(tarballPath, platforms) {
  let packed;
  try {
    packed = JSON.parse(readFileSync(tarballPath, "utf8"));
  } catch (error) {
    fail(`reading ${tarballPath}: ${error.message}`);
  }
  const files = new Set((packed[0]?.files ?? []).map((file) => file.path));
  const required = [
    "scripts/install.mjs",
    "scripts/build.mjs",
    "binding.gyp",
    "src/addon.c",
    "LICENSE",
  ];
  for (const platform of platforms) {
    required.push(
      `prebuilds/${platform}/soroauth.node`,
      `prebuilds/${platform}/${PLATFORMS[platform].library}`,
    );
  }
  const missing = required.filter((path) => !files.has(path));
  if (missing.length > 0) {
    fail(`the tarball is missing ${missing.join(", ")}`);
  }
  console.log(`verify-prebuilds: tarball carries ${files.size} files including every prebuild`);
}

const options = parseArgs(process.argv.slice(2));
checkDirectory(options.dir, options.platforms);
if (options.tarball !== null) checkTarball(options.tarball, options.platforms);
