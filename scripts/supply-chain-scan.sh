#!/usr/bin/env bash
#
# Supply-chain scan over a pull request's changed files.
#
#   scripts/supply-chain-scan.sh                 # HEAD vs origin/main
#   scripts/supply-chain-scan.sh <base> <head>   # explicit range
#   scripts/supply-chain-scan.sh --sarif <out> <base> <head>
#
# Runs in CI on every pull request. Exits non-zero when any BLOCK finding is
# present; WARN findings are reported and do not fail the build.
#
# SARIF: --sarif <path> writes a SARIF 2.1.0 report with stable rule IDs
# (SCS001..SCS012) and levels mapped from severities: BLOCK -> error,
# WARN -> warning. Human-readable output is still printed to stdout. The SARIF
# file is an addition, not a replacement.
#
# Why two severities: a check that cries wolf is one people learn to click
# past, and that is how the real thing gets through. BLOCK is for patterns with
# no legitimate use in this repository. Anything with honest uses that a
# maintainer should still look at is a WARN.
#
# Scope is the pull request's changed files. The base branch is assumed already
# scanned, and re-scanning the whole tree every time produces a wall of output
# nobody reads.
#
# Coverage:
#   1  payload appended after a JS config file's export   (PolinRider)
#   2  obfuscation and dynamic code execution
#   3  npm lifecycle hooks
#   4  credential and wallet harvesting
#   5  exfiltration channels and dead-drop C2
#   6  reverse shells and pipe-to-interpreter
#   7  persistence and auto-run mechanisms
#   8  workflow attack surface
#   9  dependency changes and known-malicious packages
#  10  new binary and executable files
#  11  Go-specific risks in library code
#  12  known campaign indicator strings
#
# Checks 1 and 4 through 7 describe malware *behaviour* and carry no indicator
# list, so they keep working against variants nobody has published yet. Check
# 12 is the opposite: fast, exact, and stale the moment the campaign rotates.
# Both are worth having; neither is sufficient alone.
#
# A clean run is a floor, not a guarantee. It means none of the known shapes is
# present in this diff. Read the diff.

set -uo pipefail

BLOCKS=0
WARNS=0
HERE="$(cd "$(dirname "$0")" && pwd)"
SARIF_OUT=""

if [ -n "${GITHUB_ACTIONS:-}" ]; then
  R=""; G=""; Y=""; B=""; N=""
else
  R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[0;33m'; B=$'\033[1m'; N=$'\033[0m'
fi

# --sarif <path> writes SARIF 2.1.0 in addition to human-readable output.
if [ "${1:-}" = "--sarif" ]; then
  [ -n "${2:-}" ] || { echo "usage: $0 --sarif <out> [base] [head]" >&2; exit 2; }
  SARIF_OUT="$2"
  shift 2
fi

# --pr <n> fetches a pull request and scans it, replacing the separate
# premerge-audit.sh that used to provide this. Two scanners doing one job is
# how their fixes diverge: the old one still carried the crude injection check
# this one replaced, and it self-matched on this file's indicator list.
if [ "${1:-}" = "--pr" ]; then
  [ -n "${2:-}" ] || { echo "usage: $0 --pr <number>" >&2; exit 2; }
  PRREF="supply-chain-scan-pr-$2"
  git fetch -q origin "refs/pull/$2/head:$PRREF" || { echo "could not fetch PR #$2" >&2; exit 2; }
  set -- "$(git rev-parse --verify -q origin/main 2>/dev/null || git rev-parse main)" "$PRREF"
fi

BASE="${1:-}"
HEAD="${2:-HEAD}"
if [ -z "$BASE" ]; then
  BASE="$(git rev-parse --verify -q origin/main 2>/dev/null || git rev-parse --verify -q main 2>/dev/null || true)"
  [ -z "$BASE" ] && { echo "cannot determine a base revision; pass one explicitly" >&2; exit 2; }
fi

CURRENT_RULE=""
CURRENT_RULE_ID=""
FINDINGS_TSV="$(mktemp)"
RULES_TSV="$(mktemp)"
trap 'rm -f "$FINDINGS_TSV" "$RULES_TSV"' EXIT

record_rule() {
  local id="$1" name="$2" desc="$3" level="$4"
  printf '%s\t%s\t%s\t%s\n' "$id" "$name" "$desc" "$level" >> "$RULES_TSV"
}

record_finding() {
  local level="$1" rule="$2" msg="$3"
  local file="" line="1"
  if [[ "$msg" == *:* ]]; then
    file="${msg%%:*}"
    # only treat as file path if it looks like a repo path
    if [[ "$file" == *"/"* || "$file" == *.* ]]; then
      local rest="${msg#*: }"
      local lineno
      lineno="$(printf '%s' "$rest" | grep -oE '^[0-9]+' | head -1 || true)"
      if [ -n "$lineno" ]; then line="$lineno"; fi
    else
      file=""
    fi
  fi
  # escape tabs/newlines for TSV
  msg="${msg//$'\t'/ }"
  msg="${msg//$'\n'/ }"
  printf '%s\t%s\t%s\t%s\t%s\n' "$level" "$rule" "$file" "$line" "$msg" >> "$FINDINGS_TSV"
}

section() {
  CURRENT_RULE="$1"
  case "$CURRENT_RULE" in
    "1. payload appended after a config file's export") CURRENT_RULE_ID="SCS001" ;;
    "2. obfuscation and dynamic code execution") CURRENT_RULE_ID="SCS002" ;;
    "3. npm lifecycle hooks") CURRENT_RULE_ID="SCS003" ;;
    "4. credential and wallet harvesting") CURRENT_RULE_ID="SCS004" ;;
    "5. exfiltration channels and dead-drop C2") CURRENT_RULE_ID="SCS005" ;;
    "6. reverse shells and pipe-to-interpreter") CURRENT_RULE_ID="SCS006" ;;
    "7. persistence and auto-run mechanisms") CURRENT_RULE_ID="SCS007" ;;
    "8. workflow attack surface") CURRENT_RULE_ID="SCS008" ;;
    "9. dependency changes and known-malicious packages") CURRENT_RULE_ID="SCS009" ;;
    "10. new binary and executable files") CURRENT_RULE_ID="SCS010" ;;
    "11. Go-specific risks in library code") CURRENT_RULE_ID="SCS011" ;;
    "12. known campaign indicator strings") CURRENT_RULE_ID="SCS012" ;;
    *) CURRENT_RULE_ID="SCS000" ;;
  esac
  printf '\n%s==>%s %s\n' "$B" "$N" "$1"
}
ok()      { printf '    %sok%s     %s\n' "$G" "$N" "$1"; }
warn()    { printf '    %sWARN%s   %s\n' "$Y" "$N" "$1"; WARNS=$((WARNS+1)); record_finding warning "$CURRENT_RULE_ID" "$1"; }
block()   { printf '    %sBLOCK%s  %s\n' "$R" "$N" "$1"; BLOCKS=$((BLOCKS+1)); record_finding error "$CURRENT_RULE_ID" "$1"; }
detail()  { printf '           %s\n' "$1"; }

# Stable rule registry: ID, name, description, default SARIF level.
record_rule SCS001 "trailing-code-after-export" "Code appended after a JS/TS module export" error
record_rule SCS002 "obfuscation-or-dynamic-exec" "Obfuscation or dynamic code execution markers" error
record_rule SCS003 "npm-lifecycle-hook" "npm lifecycle hook that may execute during install" warning
record_rule SCS004 "credential-harvesting" "Credential or wallet material access" error
record_rule SCS005 "exfiltration-or-deaddrop" "Exfiltration channel or blockchain dead-drop endpoint" error
record_rule SCS006 "reverse-shell-or-pipe-exec" "Reverse shell or download piped to interpreter" error
record_rule SCS007 "persistence-mechanism" "Persistence or auto-run mechanism" error
record_rule SCS008 "workflow-attack-surface" "GitHub Actions workflow attack surface" error
record_rule SCS009 "dependency-risk" "Dependency change or known-malicious package" warning
record_rule SCS010 "binary-or-executable-added" "Executable or binary file added to repository" error
record_rule SCS011 "go-library-risk" "Process spawning or embedded binary in library Go code" error
record_rule SCS012 "known-campaign-indicator" "Known campaign indicator string" error

# Newline-delimited rather than an array: macOS ships bash 3.2, which has no
# mapfile and treats an empty array as unbound under `set -u`.
CHANGED="$(git diff --name-only --diff-filter=d "$BASE...$HEAD" 2>/dev/null || true)"
N_CHANGED="$(printf '%s' "$CHANGED" | grep -c . || true)"

printf '%ssupply-chain scan%s  base=%s head=%s  %s changed files\n' \
  "$B" "$N" "$(git rev-parse --short "$BASE" 2>/dev/null || echo "$BASE")" \
  "$(git rev-parse --short "$HEAD" 2>/dev/null || echo "$HEAD")" "${N_CHANGED:-0}"

if [ "${N_CHANGED:-0}" -eq 0 ]; then
  echo "nothing to scan"
  if [ -n "$SARIF_OUT" ]; then
    python3 - "$SARIF_OUT" "$RULES_TSV" "$FINDINGS_TSV" <<'PY'
import json,sys
out, rules_tsv, findings_tsv = sys.argv[1], sys.argv[2], sys.argv[3]
rules=[]
for line in open(rules_tsv):
    line=line.rstrip('\n')
    if not line: continue
    i,n,d,l=line.split('\t')
    rules.append({"id":i,"name":n,"shortDescription":{"text":n},"fullDescription":{"text":d},"defaultConfiguration":{"level":l}})
sarif={"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"soroauth-supply-chain-scan","informationUri":"https://github.com/soroauth/soroauth-go","rules":rules}},"results":[]}]}
json.dump(sarif, open(out,'w'), indent=2)
open(out,'a').write('\n')
PY
  fi
  exit 0
fi

show() { git show "$HEAD:$1" 2>/dev/null; }

changed_matching() {
  printf '%s\n' "$CHANGED" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    # shellcheck disable=SC2254
    case "$f" in $1) echo "$f";; esac
  done
}

# The scanners themselves carry indicator strings, campaign domains and
# reverse-shell patterns as data. Without this they match themselves the moment
# they are part of a diff, which is exactly the false positive that teaches
# people to ignore the check.
is_scanner() {
  case "$1" in
    scripts/supply-chain-scan.sh|scripts/lib/*.py) return 0;;
    *) return 1;;
  esac
}

# Machine-generated or legitimately opaque content, excluded from the
# content-shape checks but never from the indicator check.
is_generated() {
  case "$1" in
    testdata/*|*/testdata/*|*.lock|*lock.json|go.sum|flake.lock|*.min.js|*.min.css) return 0;;
    *) return 1;;
  esac
}

# ---------------------------------------------------------------------------
section "1. payload appended after a config file's export"
hits=0
for f in $(changed_matching '*.js'; changed_matching '*.mjs'; changed_matching '*.cjs'; changed_matching '*.ts'); do
  is_generated "$f" && continue
  is_scanner "$f" && continue
  res="$(show "$f" | python3 "$HERE/lib/trailing_code.py" 2>/dev/null)"
  [ -n "$res" ] || continue
  sline="${res%%|*}"; rest="${res#*|}"; total="${rest%%|*}"; first="${rest#*|}"
  block "$f: code after the export ends (export begins line $sline, file is $total lines)"
  detail "$first"
  hits=$((hits+1))
done
[ "$hits" -eq 0 ] && ok "no JS/TS file has code after its export"

# ---------------------------------------------------------------------------
section "2. obfuscation and dynamic code execution"
hits=0
for f in $CHANGED; do
  is_generated "$f" && continue
  is_scanner "$f" && continue
  case "$f" in
    *.js|*.mjs|*.cjs|*.ts|*.jsx|*.tsx|*.py|*.sh|*.bash) ;;
    *) continue ;;
  esac
  c="$(show "$f")" || continue
  m="$(printf '%s' "$c" | grep -nEo "eval\(|new Function\(|_0x[0-9a-f]{4,}|String\.fromCharCode\([0-9]+,[0-9]+,[0-9]+,[0-9]+" | head -2)"
  [ -n "$m" ] && { block "$f: dynamic execution or obfuscation — $(printf '%s' "$m" | tr '\n' ' ')"; hits=$((hits+1)); }
  b="$(printf '%s' "$c" | grep -nEo "[\"'][A-Za-z0-9+/]{220,}={0,2}[\"']" | head -1)"
  [ -n "$b" ] && { warn "$f: long encoded literal — confirm it is data, not code"; hits=$((hits+1)); }
  l="$(printf '%s' "$c" | awk 'length($0)>500 {print NR" ("length($0)" cols)"; exit}')"
  [ -n "$l" ] && { warn "$f: very long line $l — minified payload?"; hits=$((hits+1)); }
done
[ "$hits" -eq 0 ] && ok "no obfuscation or dynamic-execution markers"

# ---------------------------------------------------------------------------
section "3. npm lifecycle hooks"
hits=0
for f in $(changed_matching '*package.json'); do
  h="$(show "$f" | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print('UNPARSEABLE'); raise SystemExit
s=d.get('scripts') or {}
bad={k:v for k,v in s.items() if k in ('preinstall','install','postinstall','prepare','prepublish','prepack','postpack')}
print(json.dumps(bad) if bad else '')
" 2>/dev/null)"
  if [ "$h" = "UNPARSEABLE" ]; then
    block "$f: not valid JSON"; hits=$((hits+1))
  elif [ -n "$h" ]; then
    warn "$f: lifecycle hook — $h"
    detail "a hook that downloads or executes anything from the network is the attack"
    hits=$((hits+1))
  fi
done
[ "$hits" -eq 0 ] && ok "no npm lifecycle hooks added or changed"

# ---------------------------------------------------------------------------
section "4. credential and wallet harvesting"
hits=0
for f in $CHANGED; do
  is_generated "$f" && continue
  is_scanner "$f" && continue
  case "$f" in *.md|*.txt) continue;; esac
  m="$(show "$f" | grep -nEo '\.ssh/id_[a-z0-9]+|\.aws/credentials|\.config/gcloud|\.docker/config\.json|\.npmrc|\.pypirc|\.netrc|Login Data|Local State|key3\.db|logins\.json|wallet\.dat|\.kube/config|find-generic-password|login\.keychain' | head -2)"
  [ -n "$m" ] && { block "$f: reads credential or wallet material — $(printf '%s' "$m" | tr '\n' ' ')"; hits=$((hits+1)); }
done
[ "$hits" -eq 0 ] && ok "no credential or wallet paths referenced"

# ---------------------------------------------------------------------------
section "5. exfiltration channels and dead-drop C2"
hits=0
for f in $CHANGED; do
  is_generated "$f" && continue
  is_scanner "$f" && continue
  case "$f" in *.md) continue;; esac
  c="$(show "$f")" || continue
  m="$(printf '%s' "$c" | grep -nEo 'discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|api\.telegram\.org/bot|pastebin\.com/raw|hastebin|transfer\.sh|file\.io|requestbin|pipedream\.net|\.ngrok\.(io|app)|burpcollaborator|interact\.sh|oast\.(fun|live|pro|site)' | head -2)"
  [ -n "$m" ] && { block "$f: exfiltration channel — $(printf '%s' "$m" | tr '\n' ' ')"; hits=$((hits+1)); }
  d="$(printf '%s' "$c" | grep -nEo 'trongrid\.io|aptoslabs\.com/v1/accounts|bsc-dataseed|bsc-rpc\.publicnode' | head -2)"
  [ -n "$d" ] && { block "$f: blockchain dead-drop endpoint — $(printf '%s' "$d" | tr '\n' ' ')"; hits=$((hits+1)); }
  i="$(printf '%s' "$c" | grep -nEoi 'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?' | grep -vE '127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.[0-9]|172\.(1[6-9]|2[0-9]|3[01])\.' | head -1)"
  [ -n "$i" ] && { warn "$f: hard-coded public IP endpoint — $i"; hits=$((hits+1)); }
done
[ "$hits" -eq 0 ] && ok "no exfiltration channels or dead-drop endpoints"

# ---------------------------------------------------------------------------
section "6. reverse shells and pipe-to-interpreter"
hits=0
for f in $CHANGED; do
  is_generated "$f" && continue
  is_scanner "$f" && continue
  case "$f" in *.md) continue;; esac
  c="$(show "$f")" || continue
  m="$(printf '%s' "$c" | grep -nEo '/dev/tcp/|nc +-[a-z]*e[a-z]* |bash +-i +>&|sh +-i +>&|socat +TCP|mkfifo +/tmp' | head -2)"
  [ -n "$m" ] && { block "$f: reverse-shell pattern — $(printf '%s' "$m" | tr '\n' ' ')"; hits=$((hits+1)); }
  p="$(printf '%s' "$c" | grep -nEo '(curl|wget)[^|;]{0,120}\|[[:space:]]*(ba)?sh|(curl|wget)[^|;]{0,120}\|[[:space:]]*(python[0-9.]*|node|perl|ruby)|iwr[^|]{0,80}\|[[:space:]]*iex' | head -1)"
  [ -n "$p" ] && { warn "$f: download piped to an interpreter"; detail "pin to a tag or commit and verify a checksum"; hits=$((hits+1)); }
done
[ "$hits" -eq 0 ] && ok "no reverse-shell or pipe-to-interpreter patterns"

# ---------------------------------------------------------------------------
section "7. persistence and auto-run mechanisms"
hits=0
for f in $CHANGED; do
  is_generated "$f" && continue
  is_scanner "$f" && continue
  case "$f" in *.md) continue;; esac
  m="$(show "$f" | grep -nEo 'crontab +-|/etc/cron\.|systemctl +enable|LaunchAgents|launchctl +load|>> *~?/?\.(bashrc|zshrc|profile|bash_profile)' | head -2)"
  [ -n "$m" ] && { block "$f: persistence mechanism — $(printf '%s' "$m" | tr '\n' ' ')"; hits=$((hits+1)); }
done
d="$(printf '%s\n' "$CHANGED" | grep -iE '(^|/)(temp_auto_push\.bat|config\.bat)$|\.vscode/tasks\.json$|(^|/)\.git/hooks/' || true)"
[ -n "$d" ] && { block "auto-run or campaign drop file added: $(printf '%s' "$d" | tr '\n' ' ')"; hits=$((hits+1)); }
[ "$hits" -eq 0 ] && ok "no persistence or auto-run mechanisms"

# ---------------------------------------------------------------------------
section "8. workflow attack surface"
wf="$(changed_matching '.github/workflows/*')"
if [ -z "$wf" ]; then
  ok "no workflow files changed"
else
  hits=0
  for f in $wf; do
    c="$(show "$f")" || continue
    printf '%s' "$c" | grep -q 'pull_request_target' && { block "$f: pull_request_target gives a fork PR access to secrets"; hits=$((hits+1)); }
    # Only an expression that lands in a `run:` block is an injection.
    # Routing the same value through `env:` is the documented mitigation, so
    # flagging that too would flag the fix alongside the bug.
    inj="$(printf '%s' "$c" | python3 "$HERE/lib/workflow_injection.py" 2>/dev/null)"
    case "$inj" in
      UNAVAILABLE*) warn "$f: injection check skipped — $inj"; hits=$((hits+1));;
      ?*) block "$f: untrusted event data interpolated into a run: block (injection)"
          printf '%s\n' "$inj" | while IFS= read -r l; do [ -n "$l" ] && detail "$l"; done
          hits=$((hits+1));;
    esac
    printf '%s' "$c" | grep -qE '(echo|printf|curl)[^|]*secrets\.|secrets\.[A-Z_]+[^}]*\|[[:space:]]*(curl|nc|wget)' && { block "$f: a secret may be printed or sent off-box"; hits=$((hits+1)); }
    printf '%s' "$c" | grep -qE 'uses: *[^@#]+@(v?[0-9]+(\.[0-9]+)*|main|master|HEAD)[[:space:]]*(#.*)?$' && { warn "$f: an action is pinned to a mutable ref, not a commit SHA"; hits=$((hits+1)); }
  done
  [ "$hits" -eq 0 ] && ok "no workflow attack patterns"
fi

# ---------------------------------------------------------------------------
section "9. dependency changes and known-malicious packages"
dep="$(git diff "$BASE...$HEAD" -- go.mod '**/go.mod' '*package.json' '**/package.json' 2>/dev/null \
  | grep -E '^\+' | grep -vE '^\+\+\+' | grep -E '"[^"]+" *: *"|^\+[[:space:]]+[a-z0-9._-]+(\.[a-z]+)?/' | head -8 || true)"
if [ -n "$dep" ]; then
  warn "dependencies added or changed — confirm each is the real package, not a typosquat:"
  printf '%s\n' "$dep" | while IFS= read -r l; do [ -n "$l" ] && detail "$(printf '%s' "$l" | cut -c1-110)"; done
else
  ok "no dependency changes"
fi
BAD='tailwindcss-style-animate|tailwind-mainanimation|tailwind-autoanimation|tailwind-animationbased|tailwindcss-typography-style|tailwindcss-style-modify|tailwindcss-animate-style'
badhit="$(git diff "$BASE...$HEAD" -- '*package.json' '**/package.json' '*lock.json' '**/*lock.json' 2>/dev/null | grep -E '^\+' | grep -oE "$BAD" | head -2 || true)"
if [ -n "$badhit" ]; then
  block "known-malicious package introduced: $(printf '%s' "$badhit" | tr '\n' ' ')"
else
  ok "no known-malicious package names"
fi

# ---------------------------------------------------------------------------
section "10. new binary and executable files"
hits=0
for f in $CHANGED; do
  case "$f" in
    *.wasm|*.so|*.dylib|*.dll|*.exe|*.bin|*.node|*.a|*.o|*.class|*.jar)
      block "$f: executable or object file added to the repository"; hits=$((hits+1));;
    *.woff|*.woff2|*.ttf|*.otf)
      # The campaign hid a payload in a font file, so new ones are surfaced.
      warn "$f: font binary added — confirm its provenance"; hits=$((hits+1));;
  esac
done
[ "$hits" -eq 0 ] && ok "no binary or executable files added"

# ---------------------------------------------------------------------------
section "11. Go-specific risks in library code"
# Scoped to packages a consumer imports. The CLI, adapters, examples, e2e,
# scripts, server, remote and rpcflow legitimately exec processes and open
# sockets, so flagging them there would be noise.
hits=0
for f in $(changed_matching '*.go'); do
  case "$f" in
    *_test.go) continue;;
    cmd/*|adapters/*|examples/*|e2e/*|scripts/*|server/*|remote/*|rpcflow/*|bindings/*|internal/*) continue;;
  esac
  c="$(show "$f")" || continue
  m="$(printf '%s' "$c" | grep -nEo 'exec\.Command|syscall\.Exec|os\.StartProcess|plugin\.Open' | head -2)"
  [ -n "$m" ] && { block "$f: library code spawns a process — $(printf '%s' "$m" | tr '\n' ' ')"; hits=$((hits+1)); }
  e="$(printf '%s' "$c" | grep -nEo '//go:embed [^ ]*\.(so|dll|dylib|exe|bin|wasm)' | head -1)"
  [ -n "$e" ] && { block "$f: embeds a binary — $e"; hits=$((hits+1)); }
  u="$(printf '%s' "$c" | grep -nEo '"unsafe"' | head -1)"
  [ -n "$u" ] && { warn "$f: imports unsafe — justify it in review"; hits=$((hits+1)); }
done
[ "$hits" -eq 0 ] && ok "no process spawning or embedded binaries in library code"

# ---------------------------------------------------------------------------
section "12. known campaign indicator strings"
IOC="$(mktemp)"
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
TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP
TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG
2[gWfGj;<:-93Z^C
m6:tTh^D)cBz?NM]
e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9
EOF
iochit=""
for f in $CHANGED; do
  is_scanner "$f" && continue
  h="$(show "$f" | grep -nFf "$IOC" | head -1)"
  [ -n "$h" ] && iochit="$iochit$f: $h
"
done
rm -f "$IOC"
if [ -n "$iochit" ]; then
  block "known campaign indicator present:"
  printf '%s' "$iochit" | while IFS= read -r l; do [ -n "$l" ] && detail "$(printf '%s' "$l" | cut -c1-130)"; done
else
  ok "no known indicator strings"
fi

write_sarif() {
  [ -n "$SARIF_OUT" ] || return 0
  python3 - "$SARIF_OUT" "$RULES_TSV" "$FINDINGS_TSV" <<'PY'
import json,sys
out, rules_tsv, findings_tsv = sys.argv[1], sys.argv[2], sys.argv[3]
rules=[]
for line in open(rules_tsv):
    line=line.rstrip('\n')
    if not line: continue
    i,n,d,l=line.split('\t')
    rules.append({"id":i,"name":n,"shortDescription":{"text":n},"fullDescription":{"text":d},"defaultConfiguration":{"level":l}})
results=[]
for line in open(findings_tsv):
    line=line.rstrip('\n')
    if not line: continue
    level, rule, file, line_no, msg = line.split('\t',4)
    loc={}
    if file:
        loc={"physicalLocation":{"artifactLocation":{"uri":file},"region":{"startLine":int(line_no) if line_no.isdigit() else 1}}}
    result={"ruleId":rule,"level":level,"message":{"text":msg}}
    if loc:
        result["locations"]=[loc]
    results.append(result)
sarif={"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"soroauth-supply-chain-scan","informationUri":"https://github.com/soroauth/soroauth-go","rules":rules}},"results":results}]}
json.dump(sarif, open(out,'w'), indent=2)
open(out,'a').write('\n')
PY
  if [ $? -ne 0 ]; then
    echo "::error title=SARIF generation failed::could not write SARIF report to $SARIF_OUT" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
echo
if [ "$BLOCKS" -gt 0 ]; then
  printf '\n%s==> BLOCKED: %d blocking finding(s), %d warning(s)%s\n' "$R" "$BLOCKS" "$WARNS" "$N"
  echo "    Do not merge until each blocking finding is explained or removed."
  write_sarif || true
  exit 1
fi
printf '\n%s==> clean: 0 blocking findings, %d warning(s)%s\n' "$G" "$WARNS" "$N"
echo "    A clean run means no known shape is present in this diff. It is a floor,"
echo "    not a guarantee — read the diff."
write_sarif || exit 1
exit 0
