#!/usr/bin/env sh
# Build the soroauth signing core to WebAssembly.
#
# Produces wasm/dist/soroauth.wasm plus the Go runtime shim that matches the
# toolchain that built it. The shim is copied, never committed: its format is
# tied to the Go version, so committing it would silently break the loader the
# first time the toolchain moved. Both files land in wasm/dist/, which is
# gitignored.
#
# Usage: wasm/build.sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out="$here/dist"

mkdir -p "$out"

echo "building soroauth.wasm with $(go version)"
(cd "$here/.." && GOOS=js GOARCH=wasm go build -o "$out/soroauth.wasm" ./cmd/soroauthwasm)

shim="$(go env GOROOT)/lib/wasm/wasm_exec.js"
if [ ! -f "$shim" ]; then
	# Older toolchains kept the shim under misc/wasm. Fail with a clear message
	# rather than producing a wasm file nothing can load.
	echo "build.sh: could not find wasm_exec.js under $(go env GOROOT)" >&2
	exit 1
fi
cp "$shim" "$out/wasm_exec.js"

echo "wrote $out/soroauth.wasm"
echo "wrote $out/wasm_exec.js"
