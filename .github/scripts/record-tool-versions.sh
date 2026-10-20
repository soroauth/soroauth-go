#!/usr/bin/env bash
set -euo pipefail

workspace="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
report=""

while (($#)); do
  tool="$1"
  shift
  case "$tool" in
  go)
    module="${1:-.}"
    if (($#)); then shift; fi
    module_file="$workspace/$module/go.mod"
    go_version="$(go version)"
    go_directive="$(awk '$1 == "go" { print $2 }' "$module_file")"
    go_toolchain="$(awk '$1 == "toolchain" { print $2 }' "$module_file")"
    sdk_version="$(cd "$workspace/$module" && go list -m -f '{{.Version}}' github.com/stellar/go-stellar-sdk)"
    report+=$'\n'"Go: $go_version"
    report+=$'\n'"Module: $module (go $go_directive${go_toolchain:+, toolchain $go_toolchain})"
    if [[ -n "$sdk_version" ]]; then
      report+=$'\n'"github.com/stellar/go-stellar-sdk (resolved): $sdk_version"
    fi
    ;;
  node)
    package_file="${1:?node requires a package-lock.json or package.json path}"
    shift
    node_version="$(node --version)"
    npm_version="$(npm --version)"
    sdk_versions="$(node -e '
      const fs = require("node:fs");
      const file = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      if (file.packages) {
        for (const [path, pkg] of Object.entries(file.packages)) {
          if (path.startsWith("node_modules/@stellar/")) {
            console.log(`${pkg.name || path.slice("node_modules/".length)}: ${pkg.version}`);
          }
        }
      } else {
        for (const [name, version] of Object.entries(file.dependencies || {})) {
          if (name.startsWith("@stellar/")) console.log(`${name}: ${version}`);
        }
      }
    ' "$workspace/$package_file")"
    report+=$'\n'"Node: $node_version; npm: $npm_version"
    report+=$'\n'"Package manifest/lockfile: $package_file"
    if [[ -n "$sdk_versions" ]]; then
      report+=$'\n'"$sdk_versions"
    fi
    ;;
  rust)
    lockfile="${1:?rust requires a Cargo.lock path}"
    shift
    rust_directory="$(dirname "$workspace/$lockfile")"
    rust_version="$(cd "$rust_directory" && rustc --version)"
    cargo_version="$(cd "$rust_directory" && cargo --version)"
    sdk_versions="$(awk '
      /^\[\[package\]\]$/ {
        if (name ~ /^(soroban-sdk|stellar-cli|stellar-xdr|stellar-strkey|stellar-base)$/) {
          print name ": " version
        }
        name = version = ""
      }
      /^name = / { name = $3; gsub(/"/, "", name) }
      /^version = / { version = $3; gsub(/"/, "", version) }
      END {
        if (name ~ /^(soroban-sdk|stellar-cli|stellar-xdr|stellar-strkey|stellar-base)$/) {
          print name ": " version
        }
      }
    ' "$workspace/$lockfile")"
    report+=$'\n'"Rust: $rust_version; $cargo_version"
    report+=$'\n'"Lockfile: $lockfile"
    if [[ -n "$sdk_versions" ]]; then
      report+=$'\n'"$sdk_versions"
    fi
    ;;
  python)
    requirements="${1:?python requires a requirements.txt path}"
    shift
    python_version="$(python3 --version)"
    pip_version="$(python3 -m pip --version)"
    sdk_versions="$(awk '
      /^[[:space:]]*(stellar-sdk|stellar-base|stellar-xdr)([<=>!~].*)?$/ {
        gsub(/[[:space:]]/, "")
        print
      }
    ' "$workspace/$requirements")"
    report+=$'\n'"Python: $python_version; $pip_version"
    report+=$'\n'"Requirements: $requirements"
    if [[ -n "$sdk_versions" ]]; then
      report+=$'\n'"$sdk_versions"
    fi
    ;;
  java)
    java_version="$(java --version)"
    maven_version="$(mvn --version | sed -n '1p')"
    report+=$'\n'"$java_version"
    report+=$'\n'"$maven_version"
    ;;
  stellar)
    stellar_version="$(stellar --version)"
    report+=$'\n'"stellar-cli: $stellar_version"
    ;;
  *)
    printf 'unknown tool-version scope: %s\n' "$tool" >&2
    exit 2
    ;;
  esac
done

report="${report#$'\n'}"
printf '%s\n' "$report"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '### Tool versions (%s)\n' "${GITHUB_JOB:-job}"
    printf '\n```text\n%s\n```\n' "$report"
  } >>"$GITHUB_STEP_SUMMARY"
fi
