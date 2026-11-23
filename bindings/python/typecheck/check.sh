#!/usr/bin/env bash
# Run mypy twice: once over a well-typed sample (must succeed) and once
# over a deliberately wrong one (must fail with the expected errors).
#
# The pair is what proves the stubs do the work the issue asks for. A
# one-shot "mypy passes" would succeed against empty stubs too; the
# failing half is the only check that's evidence.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

# ok: must pass; preserve whatever mypy reports and show it on failure.
if ! mypy --strict --no-incremental --config-file mypy.ini sample_ok.py; then
  echo "typecheck: sample_ok.py did not pass under --strict — the stubs are wrong" >&2
  exit 1
fi

# bad: must fail. We capture mypy's output and assert on it: three known
# errors, no fewer. A collapse to zero errors means the stubs stopped
# catching mistakes; a collapse to one error means the stubs stopped
# catching two of the three.
set +e
bad_output="$(mypy --strict --no-incremental --config-file mypy.ini sample_bad.py 2>&1)"
bad_status="$?"
set -e
if [ "$bad_status" -eq 0 ]; then
  echo "typecheck: sample_bad.py passed mypy, which means the stubs are no longer catching the wrong calls. mypy output:" >&2
  echo "$bad_output" >&2
  exit 1
fi

# Assert each expected error shows up. Pin on the error message rather
# than the line number so a cosmetic edit to sample_bad.py doesn't spuriously
# fail the check — what's under test is the stub coverage, not the sample's
# layout.
missing=0
require() {
  local needle="$1"
  if ! printf '%s\n' "$bad_output" | grep -Fq "$needle"; then
    echo "typecheck: sample_bad.py no longer triggers: $needle" >&2
    missing=1
  fi
}
require 'Argument 2 to "preimage" has incompatible type "str"; expected "int"'
require '"PreimageResult" has no attribute "entry_b64"'
require '"SoroauthError" has no attribute "code"'

if [ "$missing" -ne 0 ]; then
  echo "---- mypy output ----" >&2
  echo "$bad_output" >&2
  exit 1
fi

echo "typecheck: ok  — sample_ok.py passes, sample_bad.py fails with the expected errors."
