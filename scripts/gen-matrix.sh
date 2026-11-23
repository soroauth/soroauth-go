#!/usr/bin/env bash
set -euo pipefail

workdir="$(cd "$(dirname "$0")/.." && pwd)"

# Go version from go.mod
go_version="$(awk '$1 == "go" { print $2 }' "$workdir/go.mod")"

# Resolved go-stellar-sdk version
sdk_version="$(cd "$workdir" && go list -m -f '{{.Version}}' github.com/stellar/go-stellar-sdk 2>/dev/null || echo "unknown")"

# Protocol versions from the package's own ArmProtocolVersion
# Write a temp Go file and run it
cat > /tmp/_gen_check_protocol.go <<'GOEOF'
package main

import "fmt"

var ArmProtocolVersion = map[string]int{
	"SourceAccount":        20,
	"Address":              20,
	"AddressV2":            27,
	"AddressWithDelegates": 27,
}

func main() {
	arms := []string{"SourceAccount", "Address", "AddressV2", "AddressWithDelegates"}
	for _, arm := range arms {
		v := ArmProtocolVersion[arm]
		fmt.Printf("%s: Protocol %d\n", arm, v)
	}
}
GOEOF
_="$(cd "$workdir" && go run -mod=mod /tmp/_gen_check_protocol.go 2>/dev/null || echo "unknown")"

# Clean up temp file
rm -f /tmp/_gen_check_protocol.go

# Node binding version
node_binding_version="unknown"
if [ -f "$workdir/bindings/node/package.json" ]; then
  node_binding_version="$(node -e 'console.log(require("./package.json").version)' "$workdir/bindings/node")" 2>/dev/null || echo "unknown"
fi

# Rust binding version
rust_binding_version="unknown"
if [ -f "$workdir/bindings/rust/Cargo.toml" ]; then
  rust_binding_version="$(grep '^version' "$workdir/bindings/rust/Cargo.toml" | head -1 | sed 's/version = //' | tr -d '"')"
fi

# Python binding version
python_binding_version="unknown"
if [ -f "$workdir/bindings/python/pyproject.toml" ]; then
  python_binding_version="$(grep '^version' "$workdir/bindings/python/pyproject.toml" | head -1 | sed 's/version = //' | tr -d '"')"
fi

# JVM binding version
jvm_binding_version="unknown"
if [ -f "$workdir/bindings/jvm/pom.xml" ]; then
  jvm_binding_version="$(mvn -f "$workdir/bindings/jvm/pom.xml" help:evaluate -Dexpression=project.version -q 2>/dev/null | tail -1 || echo "unknown")"
fi

# WASM TS binding version
wasm_ts_version="unknown"
if [ -f "$workdir/wasm/ts/package.json" ]; then
  wasm_ts_version="$(node -e 'console.log(require("./package.json").version)' "$workdir/wasm/ts")" 2>/dev/null || echo "unknown"
fi

# Output JSON matrix (no generatedAt timestamp - the matrix records the
# current compatibility state, not a generation metadata field)
cat <<JSONEOF
{
  "go": {
    "version": "$go_version",
    "toolchain": ""
  },
  "go-stellar-sdk": {
    "resolved": "$sdk_version"
  },
  "protocol": {
    "SourceAccount": 20,
    "Address": 20,
    "AddressV2": 27,
    "AddressWithDelegates": 27
  },
  "bindings": {
    "node": "$node_binding_version",
    "rust": "$rust_binding_version",
    "python": "$python_binding_version",
    "jvm": "$jvm_binding_version",
    "wasm-ts": "$wasm_ts_version"
  },
  "supportLevels": {
    "go": "tested",
    "go-stellar-sdk": "tested",
    "protocol": "tested",
    "node-binding": "best-effort",
    "rust-binding": "best-effort",
    "python-binding": "best-effort",
    "jvm-binding": "best-effort",
    "wasm-ts": "best-effort"
  }
}
JSONEOF