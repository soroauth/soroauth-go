#!/usr/bin/env bash
# Build one platform wheel for bindings/python.
#
# Steps:
#   1. Build libsoroauth with cgo for this runner (see bindings/c/build.sh).
#   2. Stage it under bindings/python/soroauth/lib/, which package-data
#      picks up at install time.
#   3. Build the wheel into `dist/` beside the package.
#
# The wheel's platform tag comes from pip's own detection on the runner
# (manylinux repair runs in the release workflow with auditwheel, so the
# tag the file ends up with after that step is what consumers see). On
# macOS the equivalent is `delocate-wheel`, which the release workflow
# also runs.
#
# Usage: bindings/python/scripts/build_wheel.sh [python]
#   python defaults to `python3` on the PATH.
set -euo pipefail

py="${1:-python3}"

here="$(cd "$(dirname "$0")" && pwd)"
pkg="$(cd "$here/.." && pwd)"
repo="$(cd "$pkg/../.." && pwd)"

# Build the native library for the host platform. The build.sh script
# writes libsoroauth.{so,dylib} into its argument directory.
staged_lib_dir="$pkg/soroauth/lib"
rm -rf "$staged_lib_dir"
mkdir -p "$staged_lib_dir"
"$repo/bindings/c/build.sh" "$staged_lib_dir"
# Keep only the shared library — the staged header is build output the
# wheel does not need.
rm -f "$staged_lib_dir/libsoroauth.h"

# Build the wheel. `pip wheel` runs the project's build backend
# (setuptools), which honours the package-data stanza in pyproject.toml.
rm -rf "$pkg/build" "$pkg/dist"
"$py" -m pip wheel --no-deps -w "$pkg/dist" "$pkg"

echo "wheels:"
ls -l "$pkg/dist"
