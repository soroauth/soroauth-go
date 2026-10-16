#!/usr/bin/env bash
#
# verify.sh runs `soroauth inspect` and `soroauth verify` from the published CLI
# image over every entry it is given, and turns each finding into a GitHub
# workflow annotation. It is the body of the composite action; the inputs are
# the action's inputs, passed as SOROAUTH_INPUT_* environment variables.
#
# It accepts no secret: entries are public data, and the action has no input
# that could hold a seed. The CLI is asked only to inspect and verify, never to
# sign.
set -euo pipefail

image="${SOROAUTH_INPUT_IMAGE:?the image input is required}"
network="${SOROAUTH_INPUT_NETWORK:?the network input is required}"
expected_arm="${SOROAUTH_INPUT_EXPECTED_ARM:-}"
allow_unsigned="${SOROAUTH_INPUT_ALLOW_UNSIGNED:-false}"

case "${allow_unsigned,,}" in
  1 | true | yes) allow_bool=true ;;
  *) allow_bool=false ;;
esac

run_cli() {
  docker run --rm -i "$image" "$@"
}

# emit_error prints a workflow error annotation. The properties (file, line,
# title) come before "::"; the message follows and has its newlines encoded so
# a multi-line reason stays one annotation.
emit_error() {
  local msg="$1" file="${2:-}" line="${3:-}"
  msg="${msg//%/%25}"
  msg="${msg//$'\r'/%0D}"
  msg="${msg//$'\n'/%0A}"
  if [[ -n "$file" && -n "$line" ]]; then
    echo "::error file=${file},line=${line},title=soroauth verify::${msg}"
  else
    echo "::error title=soroauth verify::${msg}"
  fi
}

entry_values=()
entry_files=()
entry_lines=()

add_entry() {
  entry_values+=("$1")
  entry_files+=("$2")
  entry_lines+=("$3")
}

if [[ -n "${SOROAUTH_INPUT_ENTRY:-}" && -n "${SOROAUTH_INPUT_ENTRY_FILE:-}" ]]; then
  echo "::error title=soroauth verify::entry and entry-file are mutually exclusive"
  exit 1
fi

if [[ -n "${SOROAUTH_INPUT_ENTRY:-}" ]]; then
  add_entry "$SOROAUTH_INPUT_ENTRY" "" "1"
elif [[ -n "${SOROAUTH_INPUT_ENTRY_FILE:-}" ]]; then
  shopt -s nullglob
  matched=0
  # Deliberately unquoted: entry-file may be a glob, which is how a repository
  # checks every committed entry with one action.
  for f in $SOROAUTH_INPUT_ENTRY_FILE; do
    matched=1
    if [[ ! -f "$f" ]]; then
      echo "::error title=soroauth verify::${f} is not a file"
      exit 1
    fi
    lineno=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      lineno=$((lineno + 1))
      line="${line%$'\r'}"
      if [[ -z "${line//[[:space:]]/}" ]]; then
        continue
      fi
      add_entry "$line" "$f" "$lineno"
    done <"$f"
  done
  shopt -u nullglob

  if [[ "$matched" -eq 0 ]]; then
    echo "::error title=soroauth verify::entry-file matched no files: ${SOROAUTH_INPUT_ENTRY_FILE}"
    exit 1
  fi
  if [[ "${#entry_values[@]}" -eq 0 ]]; then
    echo "::error title=soroauth verify::entry-file carried no entries: ${SOROAUTH_INPUT_ENTRY_FILE}"
    exit 1
  fi
else
  echo "::error title=soroauth verify::one of entry or entry-file is required"
  exit 1
fi

failures=0
for i in "${!entry_values[@]}"; do
  entry="${entry_values[$i]}"
  file="${entry_files[$i]}"
  line="${entry_lines[$i]}"

  # --- inspect: report the structure and check the expected arm ---
  inspect_err="$(mktemp)"
  if ! inspect_json="$(printf '%s' "$entry" | run_cli inspect --entry - 2>"$inspect_err")"; then
    emit_error "inspect failed: $(tr '\n' ' ' <"$inspect_err")" "$file" "$line"
    failures=$((failures + 1))
    rm -f "$inspect_err"
    continue
  fi
  rm -f "$inspect_err"

  credential_type="$(printf '%s' "$inspect_json" | jq -r '
    if type == "array" then (map(.credential_type) | join(", ")) else .credential_type end')"
  if [[ -n "$expected_arm" && "$credential_type" != "$expected_arm" ]]; then
    emit_error "credential arm is ${credential_type}, expected ${expected_arm}" "$file" "$line"
    failures=$((failures + 1))
  fi

  # --- verify: every node, with its verdict and reason ---
  verify_err="$(mktemp)"
  set +e
  verify_json="$(printf '%s' "$entry" | run_cli verify --entry - --network "$network" --json 2>"$verify_err")"
  verify_code=$?
  set -e

  # Exit 0 is a full pass; exit 4 is a completed verification whose verdicts
  # say "not verified" and is still a report to parse. Anything else is an
  # error with no report.
  if [[ "$verify_code" -ne 0 && "$verify_code" -ne 4 ]]; then
    emit_error "verify failed (exit ${verify_code}): $(tr '\n' ' ' <"$verify_err")" "$file" "$line"
    failures=$((failures + 1))
    rm -f "$verify_err"
    continue
  fi
  rm -f "$verify_err"

  findings="$(printf '%s' "$verify_json" | jq -r --argjson allow "$allow_bool" '
    (if type == "array" then .[] else . end) as $entry
    | ($entry.nodes // [])[]
    | select(.verdict != "verified")
    | select((($allow) and (.verdict == "unsigned")) | not)
    | "\($entry.credential_type): \(.address) \(.verdict)\(if .reason then " — " + .reason else "" end)"')"

  if [[ -n "$findings" ]]; then
    while IFS= read -r finding; do
      emit_error "$finding" "$file" "$line"
    done <<<"$findings"
    failures=$((failures + 1))
  else
    echo "soroauth: ${file:-<inline>}${line:+:$line} no findings (${credential_type})"
  fi
done

if [[ "$failures" -gt 0 ]]; then
  echo "::error title=soroauth verify::${failures} of ${#entry_values[@]} entries did not verify"
  exit 1
fi

echo "soroauth: checked ${#entry_values[@]} entries, no findings"
