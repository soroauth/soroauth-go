#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"

if [[ -z "$tag" ]]; then
  echo "error: no tag provided" >&2
  exit 1
fi

# A pre-release tag contains -alpha, -beta, or -rc suffix
# e.g., v0.1.0-alpha.1, v0.1.0-beta.2, v0.1.0-rc.1
if echo "$tag" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-alpha|-beta|-rc)'; then
  echo "prerelease"
  exit 0
fi

echo "release"
exit 0