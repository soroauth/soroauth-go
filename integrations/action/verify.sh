#!/usr/bin/env bash
#
# verify.sh runs `soroauth inspect` and `soroauth verify` from the published CLI
# image over every input it is given, and turns each finding into a GitHub
# workflow annotation. It is the body of the composite action; the inputs are
# the action's inputs, passed as SOROAUTH_INPUT_* environment variables.
#
# Inputs are one of four, mutually exclusive channels:
#
#   entry          one base64 authorization entry or envelope
#   entry-file     a path or glob to a file of base64 entries, one per line
#   envelope       one base64 transaction envelope
#   envelope-file  a path or glob to a file of base64 envelopes, one per line
#
# The envelope channels exist because a reviewer's unit is the transaction, not
# an entry: an envelope carries every entry the host will check, and splitting
# it by hand is how one gets dropped. The CLI already understands envelopes;
# this script adds the per-entry reporting and the envelope-wide conditions.
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

# fail-on selects which verdicts are findings. "any" is the default and is the
# fail-closed reading: anything the verifier cannot confirm fails, except
# unsigned when allow-unsigned was given. Named values allow a caller to gate
# an envelope on one property, e.g. "unsigned" to reject any unsigned address
# entry while still accepting a cannot_check custom-account signature that the
# action cannot decide offline.
fail_on="${SOROAUTH_INPUT_FAIL_ON:-any}"
fail_on="${fail_on,,}"
fail_on="${fail_on// /}"
fail_on="${fail_on//cannot-check/cannot_check}"
if [[ -z "$fail_on" ]]; then
  fail_on="any"
fi
IFS=',' read -r -a fail_conditions <<<"$fail_on"
for condition in "${fail_conditions[@]}"; do
  case "$condition" in
    any | invalid | unsigned | cannot_check | unknown | verified) ;;
    *)
      echo "::error title=soroauth verify::unknown fail-on condition '${condition}' (expected any, invalid, unsigned, cannot-check, unknown, or verified)"
      exit 1
      ;;
  esac
done

run_cli() {
  if [[ -n "${SOROAUTH_CLI_OVERRIDE:-}" ]]; then
    $SOROAUTH_CLI_OVERRIDE "$@"
  else
    docker run --rm -i "$image" "$@"
  fi
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

envelope_values=()
envelope_files=()
envelope_lines=()

add_entry() {
  entry_values+=("$1")
  entry_files+=("$2")
  entry_lines+=("$3")
}

add_envelope() {
  envelope_values+=("$1")
  envelope_files+=("$2")
  envelope_lines+=("$3")
}

channels=0
for channel in "${SOROAUTH_INPUT_ENTRY:-}" "${SOROAUTH_INPUT_ENTRY_FILE:-}" \
  "${SOROAUTH_INPUT_ENVELOPE:-}" "${SOROAUTH_INPUT_ENVELOPE_FILE:-}"; do
  [[ -n "$channel" ]] && channels=$((channels + 1))
done
if [[ "$channels" -eq 0 ]]; then
  emit_error "one of entry, entry-file, envelope or envelope-file is required"
  exit 1
fi
if [[ "$channels" -gt 1 ]]; then
  emit_error "entry, entry-file, envelope and envelope-file are mutually exclusive"
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
      emit_error "${f} is not a file"
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
    emit_error "entry-file matched no files: ${SOROAUTH_INPUT_ENTRY_FILE}"
    exit 1
  fi
  if [[ "${#entry_values[@]}" -eq 0 ]]; then
    emit_error "entry-file carried no entries: ${SOROAUTH_INPUT_ENTRY_FILE}"
    exit 1
  fi
elif [[ -n "${SOROAUTH_INPUT_ENVELOPE:-}" ]]; then
  add_envelope "$SOROAUTH_INPUT_ENVELOPE" "" "1"
else
  shopt -s nullglob
  matched=0
  for f in $SOROAUTH_INPUT_ENVELOPE_FILE; do
    matched=1
    if [[ ! -f "$f" ]]; then
      emit_error "${f} is not a file"
      exit 1
    fi
    lineno=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      lineno=$((lineno + 1))
      line="${line%$'\r'}"
      if [[ -z "${line//[[:space:]]/}" ]]; then
        continue
      fi
      add_envelope "$line" "$f" "$lineno"
    done <"$f"
  done
  shopt -u nullglob

  if [[ "$matched" -eq 0 ]]; then
    emit_error "envelope-file matched no files: ${SOROAUTH_INPUT_ENVELOPE_FILE}"
    exit 1
  fi
  if [[ "${#envelope_values[@]}" -eq 0 ]]; then
    emit_error "envelope-file carried no envelopes: ${SOROAUTH_INPUT_ENVELOPE_FILE}"
    exit 1
  fi
fi

# Report the exact soroauth CLI build identity used for verification.
cli_version_raw="$(run_cli --version 2>/dev/null || echo "soroauth dev (commit: unknown, built: unknown)")"
tag="$(printf '%s\n' "$cli_version_raw" | sed -n '1p')"
commit="$(printf '%s\n' "$cli_version_raw" | grep '^commit:' | sed 's/^commit:[[:space:]]*//' || true)"
built="$(printf '%s\n' "$cli_version_raw" | grep '^built:' | sed 's/^built:[[:space:]]*//' || true)"
go_ver="$(printf '%s\n' "$cli_version_raw" | grep '^go:' | sed 's/^go:[[:space:]]*//' || true)"

meta=()
[[ -n "$commit" ]] && meta+=("commit: $commit")
[[ -n "$built" ]] && meta+=("built: $built")
[[ -n "$go_ver" ]] && meta+=("go: $go_ver")

if [[ ${#meta[@]} -gt 0 ]]; then
  meta_joined="$(printf '%s, ' "${meta[@]}")"
  meta_joined="${meta_joined%, }"
  cli_version_line="${tag} (${meta_joined})"
else
  cli_version_line="${tag}"
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "version=${cli_version_line}" >>"$GITHUB_OUTPUT"
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### soroauth verify"
    echo ""
    echo "Verified with **soroauth** \`${cli_version_line}\`"
    echo ""
    echo '```text'
    echo "$cli_version_raw"
    echo '```'
    echo ""
  } >>"$GITHUB_STEP_SUMMARY"
fi

# fails_expression is the jq predicate over one node verdict. It is shared by
# the entry and envelope paths so a condition means the same thing in both.
fails_expression='def fails($v):
  if $v == "verified" then false
  elif ($v == "unsigned") and $allow then false
  elif ($conditions | index("any")) != null then true
  else ($conditions | index($v)) != null end;'

failures=0
checked_entries=0
summary_rows=()

# verify_envelope inspects and verifies one whole envelope, annotates every
# failing node by the position of its entry, and appends a row per entry for the
# job summary. It mutates the counters shared with the caller.
verify_envelope() {
  local envelope="$1" file="$2" line="$3"

  local inspect_err inspect_json verify_err verify_json verify_code
  inspect_err="$(mktemp)"
  if ! inspect_json="$(printf '%s' "$envelope" | run_cli inspect --entry - 2>"$inspect_err")"; then
    emit_error "inspect failed: $(tr '\n' ' ' <"$inspect_err")" "$file" "$line"
    failures=$((failures + 1))
    rm -f "$inspect_err"
    return
  fi
  rm -f "$inspect_err"

  verify_err="$(mktemp)"
  set +e
  verify_json="$(printf '%s' "$envelope" | run_cli verify --entry - --network "$network" --json 2>"$verify_err")"
  verify_code=$?
  set -e
  if [[ "$verify_code" -ne 0 && "$verify_code" -ne 4 ]]; then
    emit_error "verify failed (exit ${verify_code}): $(tr '\n' ' ' <"$verify_err")" "$file" "$line"
    failures=$((failures + 1))
    rm -f "$verify_err"
    return
  fi
  rm -f "$verify_err"

  if ! printf '%s' "$inspect_json" | jq -e 'type == "array"' >/dev/null 2>&1; then
    emit_error "inspect did not report the envelope as an array of entries" "$file" "$line"
    failures=$((failures + 1))
    return
  fi
  if ! printf '%s' "$verify_json" | jq -e 'type == "array"' >/dev/null 2>&1; then
    emit_error "verify did not report the envelope as an array of entries" "$file" "$line"
    failures=$((failures + 1))
    return
  fi

  local entries_in_envelope
  entries_in_envelope="$(printf '%s' "$inspect_json" | jq 'length')"
  checked_entries=$((checked_entries + entries_in_envelope))

  # expected-arm is checked entry by entry. A source-account entry is a real
  # arm and must match if named; it is not skipped.
  if [[ -n "$expected_arm" ]]; then
    while IFS=$'\t' read -r op en arm; do
      if [[ "$arm" != "$expected_arm" ]]; then
        emit_error "operation ${op} entry ${en}: credential arm is ${arm}, expected ${expected_arm}" "$file" "$line"
        failures=$((failures + 1))
      fi
    done < <(printf '%s' "$inspect_json" | jq -r '.[] | [.operation_index + 1, .entry_index + 1, .credential_type] | @tsv')
  fi

  # Findings: one annotation per failing node, named by the position of its
  # entry in the envelope. A source-account entry has no nodes, so it can never
  # be a finding here — that is the point: its authorizer is the envelope's own
  # signature.
  local conditions_json findings
  conditions_json="$(printf '%s\n' "${fail_conditions[@]}" | jq -R . | jq -s .)"
  findings="$(printf '%s' "$verify_json" | jq -r \
    --argjson allow "$allow_bool" \
    --argjson conditions "$conditions_json" \
    "$fails_expression"'
    (if type == "array" then . else [.] end) as $entries
    | $entries
    | to_entries[]
    | .key as $i
    | .value as $entry
    | ($entry.nodes // [])[]
    | select(fails(.verdict))
    | (
        if $entry.operation_index != null and $entry.entry_index != null
        then "operation \($entry.operation_index) entry \($entry.entry_index): "
        else "" end
      )
      + "\(.address) \(.verdict)\(if .reason then " — " + .reason else "" end)"')"

  if [[ -n "$findings" ]]; then
    while IFS= read -r finding; do
      emit_error "$finding" "$file" "$line"
    done <<<"$findings"
    failures=$((failures + 1))
  else
    echo "soroauth: ${file:-<inline>}${line:+:$line} no findings (${entries_in_envelope} entries)"
  fi

  # A row per entry, with its index and address, for the job summary. Every
  # entry is named, including a source-account one and one with no nodes.
  while IFS= read -r row; do
    summary_rows+=("$row")
  done < <(jq -nr \
    --argjson infos "$inspect_json" \
    --argjson reports "$verify_json" \
    '
    def verdicts($nodes):
      if ($nodes | length) == 0 then "—"
      else ($nodes | map("\(.address) \(.verdict)") | join("<br>")) end;
    $infos | to_entries[] | .key as $i
    | .value as $info
    | ($reports[$i] // {nodes: []}) as $report
    | "| \($info.operation_index + 1) | \($info.entry_index + 1) | \($info.credential_type) | "
      + (if ($info.address // "") == "" then "—" else $info.address end)
      + " | \(verdicts($report.nodes // [])) |"')
}

# --- Envelope path ---------------------------------------------------------
if [[ "${#envelope_values[@]}" -gt 0 ]]; then
  for i in "${!envelope_values[@]}"; do
    verify_envelope "${envelope_values[$i]}" "${envelope_files[$i]}" "${envelope_lines[$i]}"
  done

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" && "${#summary_rows[@]}" -gt 0 ]]; then
    {
      echo "| Operation | Entry | Arm | Address | Verdicts |"
      echo "| --------- | ----- | --- | ------- | -------- |"
      printf '%s\n' "${summary_rows[@]}"
      echo ""
    } >>"$GITHUB_STEP_SUMMARY"
  fi

  if [[ "$failures" -gt 0 ]]; then
    emit_error "${failures} of ${#envelope_values[@]} envelopes did not verify"
    exit 1
  fi
  echo "soroauth: checked ${checked_entries} entries across ${#envelope_values[@]} envelopes, no findings"
  exit 0
fi

# --- Entry path ------------------------------------------------------------
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

  # `entry` has always accepted an envelope as well as a single entry. Keep that
  # working, and route it through the envelope path so it gets the per-entry
  # reporting and the same expected-arm semantics.
  if printf '%s' "$inspect_json" | jq -e 'type == "array"' >/dev/null 2>&1; then
    verify_envelope "$entry" "$file" "$line"
    continue
  fi

  checked_entries=$((checked_entries + 1))
  credential_type="$(printf '%s' "$inspect_json" | jq -r '.credential_type')"
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

  conditions_json="$(printf '%s\n' "${fail_conditions[@]}" | jq -R . | jq -s .)"
  findings="$(printf '%s' "$verify_json" | jq -r \
    --argjson allow "$allow_bool" \
    --argjson conditions "$conditions_json" \
    "$fails_expression"'
    (if type == "array" then .[] else . end) as $entry
    | ($entry.nodes // [])[]
    | select(fails(.verdict))
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

if [[ -n "${GITHUB_STEP_SUMMARY:-}" && "${#summary_rows[@]}" -gt 0 ]]; then
  {
    echo "| Operation | Entry | Arm | Address | Verdicts |"
    echo "| --------- | ----- | --- | ------- | -------- |"
    printf '%s\n' "${summary_rows[@]}"
    echo ""
  } >>"$GITHUB_STEP_SUMMARY"
fi

if [[ "$failures" -gt 0 ]]; then
  echo "::error title=soroauth verify::${failures} of ${#entry_values[@]} inputs did not verify"
  exit 1
fi

echo "soroauth: checked ${checked_entries} entries, no findings"
