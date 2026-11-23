#!/usr/bin/env sh
# Build the soroauth signing core to WebAssembly.
#
# Produces:
#
#   wasm/dist/soroauth.wasm       js/wasm, for a browser or Node with wasm_exec.js
#   wasm/dist/soroauth.wasi.wasm  wasip1, for a sandboxed WASI runtime with no JS host
#   wasm/dist/wasm_exec.js        the Go runtime shim matching the js/wasm artifact
#   wasm/dist/SHA256SUMS          sha256 of the three files above, sorted by name
#
# The shim is copied, never committed: its format is tied to the Go version, so
# committing it would silently break the loader the first time the toolchain
# moved. Every artifact lands in wasm/dist/, which is gitignored.
#
# Reproducibility: both builds pass -trimpath and -buildvcs=false. Absolute build
# paths and the VCS revision are the two pieces of the surrounding checkout that
# Go would otherwise embed, and embedding them would make two builds of the same
# tag differ. With those disabled and the toolchain fixed, repeated builds are
# byte-identical; scripts/reproduce-wasm.sh asserts that and CI re-runs it
# against the published release (docs/reproducibility.md).
#
# Usage: wasm/build.sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
out="$here/dist"

mkdir -p "$out"

echo "building soroauth.wasm with $(go version)"
(cd "$root" && GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false \
	-o "$out/soroauth.wasm" ./cmd/soroauthwasm)

echo "building soroauth.wasi.wasm with $(go version)"
(cd "$root" && GOOS=wasip1 GOARCH=wasm go build -trimpath -buildvcs=false \
	-o "$out/soroauth.wasi.wasm" ./cmd/soroauthwasi)

shim="$(go env GOROOT)/lib/wasm/wasm_exec.js"
if [ ! -f "$shim" ]; then
	# Older toolchains kept the shim under misc/wasm. Fail with a clear message
	# rather than producing a wasm file nothing can load.
	echo "build.sh: could not find wasm_exec.js under $(go env GOROOT)" >&2
	exit 1
fi
cp "$shim" "$out/wasm_exec.js"

# macOS has no sha256sum; shasum -a 256 writes the same "hash  file" line.
if command -v sha256sum >/dev/null 2>&1; then
	checksum() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
	checksum() { shasum -a 256 "$@"; }
else
	echo "build.sh: need sha256sum or shasum to publish the wasm digest" >&2
	exit 1
fi

# Sorted by filename so the file is byte-stable regardless of build order. The
# npm package ships this file (wasm/ts/scripts/stage-wasm.mjs copies it), and
# the release attaches it as soroauth-wasm-checksums.txt.
(
	cd "$out"
	checksum soroauth.wasi.wasm soroauth.wasm wasm_exec.js | sort -k2 >SHA256SUMS
)

echo "wrote $out/soroauth.wasm"
echo "wrote $out/soroauth.wasi.wasm"
echo "wrote $out/wasm_exec.js"
echo "wrote $out/SHA256SUMS"
