#!/usr/bin/env bash
# Build the assets the offline signing page loads.
#
# The offline page has no CDN dependency: it needs the WASM signing core, the Go
# runtime shim that matches the toolchain that built it, and the typed wrapper.
# All three are build artifacts, so they are staged under dist/ (gitignored)
# rather than committed. Run this once, then serve the example directory:
#
#     ./examples/browser-passkey/build-offline.sh
#     python3 -m http.server 8000
#     # open http://localhost:8000/examples/browser-passkey/offline.html
#
# WebAuthn needs a secure context; localhost qualifies, a file:// page does not.
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)

"$root/wasm/build.sh"

# The wrapper is TypeScript, compiled by its own package script. npm ci keeps the
# install pinned to wasm/ts/package-lock.json.
(
	cd "$root/wasm/ts"
	npm ci --silent
	npm run build --silent
)

mkdir -p "$here/dist"
cp "$root/wasm/dist/soroauth.wasm" "$here/dist/soroauth.wasm"
cp "$root/wasm/dist/wasm_exec.js" "$here/dist/wasm_exec.js"
cp "$root"/wasm/ts/dist/*.js "$here/dist/"

echo "offline demo assets staged in $here/dist"
