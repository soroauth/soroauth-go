#!/usr/bin/env bash
#
# Rebuild the WebAssembly signing core from a git ref and publish its digest.
#
# This is the wasm counterpart to scripts/reproduce.sh. It answers the same
# question for the browser and sandbox artifacts that reproduce.sh answers for
# the CLI binaries: does the tagged source still build the bytes that were
# published? It builds both wasm targets twice from an archive of the ref,
# refuses to report success if the two builds differ, and writes
# soroauth-wasm-checksums.txt beside a copy of the artifacts.
#
# Usage:
#
#	scripts/reproduce-wasm.sh <git-ref> [outdir]
#
# <git-ref> is a tag (e.g. v0.5.0) or any commit-ish. [outdir] defaults to
# ./reproduced-wasm. The build runs from `git archive <ref>`, not from the
# working tree, so a dirty checkout or an untracked file cannot end up in the
# digest.
#
# Toolchain: Go embeds the compiler version in the module. A rebuild must use
# the same Go version the release used, which is the version go.mod's `go`
# directive names and the release workflow installs. A different patch release
# legitimately produces a different digest; that is a property of the
# toolchain, not a reproducibility failure.
#
# Exit status: 0 when both builds agree, 1 on a usage, build or mismatch error.
set -euo pipefail

usage() {
	echo "usage: $(basename "$0") <git-ref> [outdir]" >&2
	exit 1
}

[ "$#" -ge 1 ] || usage
ref="$1"
out="${2:-$(pwd)/reproduced-wasm}"

cd "$(git rev-parse --show-toplevel)"

# Resolve to a commit first: `git archive` accepts a tag object, but every
# message should name exactly what was built.
commit="$(git rev-parse --verify "$ref^{commit}")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The source of the ref and nothing else. Untracked build output in the
# caller's checkout cannot influence the result.
git archive "$commit" | tar -x -C "$work"

build_once() {
	local dest="$1"
	rm -rf "$work/wasm/dist"
	(
		cd "$work"
		./wasm/build.sh
	) >&2
	cp "$work/wasm/dist/SHA256SUMS" "$dest"
}

echo "rebuilding $(git describe --tags --always "$commit") with $(go version)" >&2
build_once "$work/SHA256SUMS.1"
build_once "$work/SHA256SUMS.2"

if ! diff -u "$work/SHA256SUMS.1" "$work/SHA256SUMS.2" >&2; then
	echo >&2
	echo "Two builds of $ref produced different wasm bytes." >&2
	echo "Something non-deterministic is in the build. See docs/reproducibility.md;" >&2
	echo "fix the source of the difference rather than tolerating it." >&2
	exit 1
fi

mkdir -p "$out"
out="$(cd "$out" && pwd)"
cp "$work/SHA256SUMS.1" "$out/soroauth-wasm-checksums.txt"
cp "$work/wasm/dist/soroauth.wasm" "$out/soroauth.wasm"
cp "$work/wasm/dist/soroauth.wasi.wasm" "$out/soroauth.wasi.wasm"
cp "$work/wasm/dist/wasm_exec.js" "$out/wasm_exec.js"

echo "wrote $out/soroauth-wasm-checksums.txt"
cat "$out/soroauth-wasm-checksums.txt"
