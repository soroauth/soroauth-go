#!/usr/bin/env bash
#
# Pre-merge supply-chain audit. Run this against a pull request branch BEFORE
# merging it. Exits non-zero on any finding.
#
#   ./scripts/premerge-audit.sh                 # audit the working tree vs main
#   ./scripts/premerge-audit.sh <ref>           # audit a branch/ref vs main
#   ./scripts/premerge-audit.sh --pr 123        # fetch and audit a pull request
#
# Why this exists: the PolinRider campaign (DPRK, first reported March 2026)
# appends an obfuscated JavaScript payload to the END of legitimate config
# files — postcss.config.mjs, tailwind.config.js, vite.config.js, app.js,
# index.js — usually delivered through a compromised npm package that runs on
# install. It has hit repositories in the Stellar Wave program. A reviewer
# reading a diff sees a plausible feature and misses 400 columns of appended
# payload below the fold.
#
# Check 1 is the one that catches that technique directly, and it is
# independent of any indicator list: a JS config file whose legitimate export
# is not the last thing in it is suspicious whatever the payload looks like.
# The indicator checks that follow will go stale; check 1 will not.
#
# A clean run is NOT a guarantee. It is a floor: it means none of the known
# shapes are present. Read the diff.

set -uo pipefail

RED=$'\033[0;31m'; YEL=$'\033[0;33m'; GRN=$'\033[0;32m'; BLD=$'\033[1m'; RST=$'\033[0m'
FINDINGS=0
BASE="${AUDIT_BASE:-main}"

note() { printf '%s==>%s %s\n' "$BLD" "$RST" "$1"; }
pass() { printf '    %sok%s   %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '    %swarn%s %s\n' "$YEL" "$RST" "$1"; }
fail() { printf '    %sFAIL%s %s\n' "$RED" "$RST" "$1"; FINDINGS=$((FINDINGS+1)); }

REF="HEAD"
if [ "${1:-}" = "--pr" ]; then
  [ -n "${2:-}" ] || { echo "usage: $0 --pr <number>" >&2; exit 2; }
  REF="premerge-audit-pr-$2"
  note "fetching pull request #$2"
  git fetch -q origin "refs/pull/$2/head:$REF" || { echo "could not fetch PR #$2" >&2; exit 2; }
elif [ -n "${1:-}" ]; then
  REF="$1"
fi

git rev-parse --verify -q "$REF" >/dev/null || { echo "no such ref: $REF" >&2; exit 2; }
note "auditing ${BLD}${REF}${RST} against ${BLD}${BASE}${RST}"
echo

# Files this ref adds or changes relative to the base. An audit of only the
# changed files is the right scope for a pre-merge check: the base is assumed
# already audited, and scanning everything every time trains people to ignore
# the output.
# Newline-delimited rather than an array: macOS ships bash 3.2, which has no
# mapfile, and `set -u` treats an empty array as unbound there.
CHANGED="$(git diff --name-only "$BASE...$REF" 2>/dev/null || true)"
CHANGED_N="$(printf '%s' "$CHANGED" | grep -c . || true)"
if [ "${CHANGED_N:-0}" -eq 0 ]; then
  warn "no files changed against $BASE — is the branch up to date, or is this the base itself?"
fi
note "${CHANGED_N:-0} changed files"

# ---------------------------------------------------------------------------
note "1. payload appended after a config file's export (PolinRider's technique)"
# Any content after the legitimate export is the signature, whatever it says.
# Checked on every JS-family file in the diff, not only the known filenames,
# because the filename list is the part that changes between variants.
hits=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    *.js|*.mjs|*.cjs|*.ts) ;;
    *) continue ;;
  esac
  git cat-file -e "$REF:$f" 2>/dev/null || continue   # deleted in this ref
  body="$(git show "$REF:$f" 2>/dev/null)" || continue
  last_export="$(printf '%s\n' "$body" | grep -nE '^[[:space:]]*(export default|module\.exports)' | tail -1 | cut -d: -f1)"
  [ -n "$last_export" ] || continue
  total="$(printf '%s\n' "$body" | wc -l | tr -d ' ')"
  trailing="$(printf '%s\n' "$body" | tail -n +$((last_export+1)) | grep -vE '^[[:space:]]*$|^[[:space:]]*(//|\*|/\*|\*/|\}|\);|\})' | head -3)"
  if [ -n "$trailing" ]; then
    fail "$f: code after the export at line $last_export (file is $total lines)"
    printf '         %s\n' "$(printf '%s' "$trailing" | head -2 | cut -c1-120)"
    hits=$((hits+1))
  fi
done <<EOF
$CHANGED
EOF
[ "$hits" -eq 0 ] && pass "no JS/TS file in the diff has code after its export"

# ---------------------------------------------------------------------------
note "2. obfuscation and dynamic execution in changed files"
hits=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    *.js|*.mjs|*.cjs|*.ts|*.json|*.sh|*.yml|*.yaml) ;;
    *) continue ;;
  esac
  git cat-file -e "$REF:$f" 2>/dev/null || continue
  m="$(git show "$REF:$f" 2>/dev/null | grep -nEo "eval\(|new Function\(|_0x[0-9a-f]{4}|atob\([\"'\`][A-Za-z0-9+/]{40,}|Buffer\.from\([\"'][A-Za-z0-9+/]{40,}[\"'],[[:space:]]*[\"']base64|\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}" | head -2)"
  [ -n "$m" ] && { fail "$f: $(printf '%s' "$m" | tr '\n' ' ')"; hits=$((hits+1)); }
  # A very long line in a source file is how a minified payload hides.
  l="$(git show "$REF:$f" 2>/dev/null | awk 'length($0)>400 {print NR": "length($0)" cols"; exit}')"
  case "$f" in
    testdata/*|*.json) ;;   # vectors, corpora and lockfiles are legitimately long
    *) [ -n "$l" ] && { fail "$f: very long line ($l) — minified payload?"; hits=$((hits+1)); } ;;
  esac
done <<EOF
$CHANGED
EOF
[ "$hits" -eq 0 ] && pass "no obfuscation or dynamic-execution markers"

# ---------------------------------------------------------------------------
note "3. npm lifecycle hooks (PolinRider's delivery vector)"
hits=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in */package.json|package.json) ;; *) continue ;; esac
  git cat-file -e "$REF:$f" 2>/dev/null || continue
  h="$(git show "$REF:$f" 2>/dev/null | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print('UNPARSEABLE'); raise SystemExit
s=d.get('scripts') or {}
bad={k:v for k,v in s.items() if k in ('preinstall','install','postinstall','prepare','prepublish','prepack')}
print(json.dumps(bad) if bad else '')
" 2>/dev/null)"
  if [ -n "$h" ]; then
    warn "$f introduces or changes a lifecycle hook: $h"
    printf '         %sreview it by hand: a hook that fetches anything is the attack%s\n' "$YEL" "$RST"
    hits=$((hits+1))
  fi
done <<EOF
$CHANGED
EOF
[ "$hits" -eq 0 ] && pass "no npm lifecycle hooks added or changed"

# ---------------------------------------------------------------------------
note "4. known PolinRider indicators"
IOC=$(mktemp)
cat > "$IOC" <<'EOF'
rmcej%otb%
Cot%3t=shtP
_$_1e42
function MDy(
global['!']
global['_V']
global['r'] = require
LAST_COMMIT_DATE LAST_COMMIT_TIME
260120.vercel.app
default-configuration.vercel.app
vscode-settings-bootstrap.vercel.app
vscode-settings-config.vercel.app
vscode-bootstrapper.vercel.app
vscode-load-config.vercel.app
api.trongrid.io
fullnode.mainnet.aptoslabs.com
bsc-dataseed.binance.org
bsc-rpc.publicnode.com
TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP
TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG
2[gWfGj;<:-93Z^C
m6:tTh^D)cBz?NM]
e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9
tailwindcss-style-animate
tailwind-mainanimation
tailwind-autoanimation
tailwind-animationbased
tailwindcss-typography-style
tailwindcss-style-modify
tailwindcss-animate-style
EOF
# Scoped to the files this ref changes, like every other check, and with this
# script excluded. Scanning the whole ref would match the indicator list below
# against itself the moment this script is on the base branch, and an audit
# that always fails is an audit everyone learns to ignore.
m=""
if [ -n "$CHANGED" ]; then
  SCAN="$(printf '%s\n' "$CHANGED" | grep -v '^scripts/premerge-audit\.sh$' || true)"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    git cat-file -e "$REF:$f" 2>/dev/null || continue
    h="$(git show "$REF:$f" 2>/dev/null | grep -nFf "$IOC" | head -2)"
    [ -n "$h" ] && m="$m$f: $h
"
  done <<EOF
$SCAN
EOF
fi
rm -f "$IOC"
if [ -n "$m" ]; then fail "PolinRider indicator present:"; printf '         %s\n' "$m"; else pass "no known indicator strings"; fi

# Drop files the campaign leaves behind.
d="$(git diff --name-only "$BASE...$REF" 2>/dev/null | grep -iE '(^|/)(temp_auto_push\.bat|config\.bat|\.vscode/tasks\.json)$|\.bat$')"
if [ -n "$d" ]; then fail "campaign drop-file added: $(printf '%s' "$d" | tr '\n' ' ')"; else pass "no campaign drop files"; fi

# ---------------------------------------------------------------------------
note "5. workflow attack surface"
wf="$(printf '%s\n' "$CHANGED" | grep '^\.github/workflows/' || true)"
if [ -z "$wf" ]; then
  pass "no workflow files changed"
else
  for f in $wf; do
    git cat-file -e "$REF:$f" 2>/dev/null || continue
    c="$(git show "$REF:$f")"
    printf '%s' "$c" | grep -q 'pull_request_target' && fail "$f uses pull_request_target — a fork PR would get secrets"
    printf '%s' "$c" | grep -qE '\$\{\{ *github\.event\.(pull_request|issue|comment|head_ref)' && fail "$f interpolates untrusted event data into a script (injection)"
    printf '%s' "$c" | grep -qE '(echo|printf|curl)[^|]*secrets\.|secrets\.[A-Z_]+[^}]*\|[[:space:]]*(curl|nc|wget)' && fail "$f may exfiltrate a secret"
    printf '%s' "$c" | grep -qE 'curl[^|]*\|[[:space:]]*(ba)?sh|wget[^|]*\|[[:space:]]*(ba)?sh' && warn "$f pipes a download straight to a shell — pin and checksum it"
    printf '%s' "$c" | grep -qE 'uses: *[^@]+@(v?[0-9]+|main|master)[^0-9a-f]*$' && warn "$f uses an action pinned to a mutable ref, not a commit SHA"
  done
  pass "workflow checks complete (see any FAIL/warn above)"
fi

# ---------------------------------------------------------------------------
note "6. dependency changes"
dep="$(git diff "$BASE...$REF" -- go.mod '**/go.mod' '**/package.json' 2>/dev/null | grep -E '^\+' | grep -vE '^\+\+\+' | grep -E '"[^"]+": *"|^\+[[:space:]]+[a-z0-9.-]+/' | head -8)"
if [ -n "$dep" ]; then
  warn "dependencies added or changed — verify each is the real package, not a typosquat:"
  printf '         %s\n' "$dep"
else
  pass "no dependency changes"
fi

# ---------------------------------------------------------------------------
note "7. correctness gate (the signing path)"
if [ "$REF" = "HEAD" ] && git diff --quiet 2>/dev/null; then
  if command -v node >/dev/null 2>&1 && [ -d testdata/gen/node_modules ]; then
    (cd testdata/gen && node gen.mjs >/dev/null 2>&1)
    if git diff --quiet -- testdata/vectors 2>/dev/null; then
      pass "golden vectors reproduce byte-for-byte"
    else
      fail "GOLDEN VECTOR DRIFT — the signing path or a vector changed"
      git checkout -q -- testdata/vectors 2>/dev/null
    fi
  else
    warn "skipped: run 'cd testdata/gen && npm ci' to enable the vector check"
  fi
else
  warn "skipped on a non-checked-out ref — run 'make vectors-check' after checking the branch out"
fi

v="$(git diff --name-only "$BASE...$REF" -- testdata/vectors 2>/dev/null)"
g="$(git diff --name-only "$BASE...$REF" -- testdata/gen 2>/dev/null)"
if [ -n "$v" ] && [ -z "$g" ]; then
  fail "vectors changed with no change to testdata/gen — a hand-edited vector is never acceptable"
elif [ -n "$v" ]; then
  warn "vectors changed alongside the generator — confirm they were regenerated, not edited"
else
  pass "no golden vectors touched"
fi

# ---------------------------------------------------------------------------
echo
if [ "$FINDINGS" -eq 0 ]; then
  printf '%s==> audit clean: %d findings%s\n' "$GRN" "$FINDINGS" "$RST"
  printf '    A clean run means no known shape is present. It is a floor, not a guarantee — read the diff.\n'
  exit 0
else
  printf '%s==> audit FAILED: %d finding(s) — do not merge%s\n' "$RED" "$FINDINGS" "$RST"
  exit 1
fi
