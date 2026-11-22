#!/usr/bin/env python3
# Cross-language conformance runner for the Python binding.
#
# Reads testdata/conformance/cases.json and writes one NDJSON row per case
# to stdout, in the shape testdata/conformance/README.md documents. The CI
# job for this binding diffs this output against the Go oracle's; a
# mismatch fails the job and names the failing case.
#
# Usage:
#   python -m conformance.run testdata/conformance/cases.json [vectors-dir]
"""Python runner for the cross-language conformance suite (issue #545)."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

try:
    import soroauth
except Exception as exc:  # noqa: BLE001 — the runner reports any import failure
    print(
        json.dumps({"id": "_import", "ok": False, "kind": "ERROR", "error": str(exc)}),
        flush=True,
    )
    sys.exit(1)


_OP_PREIMAGE = "preimage"
_OP_PAYLOAD = "payload"
_OP_AUTHORIZE_WITH_SEED = "authorize_with_seed"


def _vector_path(vectors_dir: Path, name: str) -> Path:
    return vectors_dir / f"{name}.json"


def _load_vector(vectors_dir: Path, name: str) -> dict:
    with open(_vector_path(vectors_dir, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _seed_for_label(label: str) -> str:
    """Derive the deterministic ed25519 seed each vector signer_label signs with.

    The derivation is SHA-256(label); the vectors were generated this way,
    and the Go oracle uses the same derivation, so the two produce the same
    seed byte-for-byte.
    """
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _resolve_inputs(case: dict, vectors_dir: Path) -> dict:
    inputs: dict = {}
    vector_name = case.get("vector")
    if vector_name:
        v = _load_vector(vectors_dir, vector_name)
        inputs["entry_xdr_b64"] = v["unsigned_entry_xdr"]
        inputs["valid_until_ledger"] = v["valid_until_ledger"]
        inputs["network_passphrase"] = v["network_passphrase"]
        inputs["preimage_xdr_b64"] = v["preimage_xdr"]
        steps = v.get("steps", [])
        if steps:
            inputs["seed_hex"] = _seed_for_label(steps[0]["signer_label"])
    inputs.update(case.get("input", {}))
    inputs.update(case.get("override", {}))
    return inputs


def _ok_result(case_id: str, **fields: str) -> dict:
    out = {"id": case_id, "ok": True}
    out.update(fields)
    return out


def _err_result(case_id: str, exc: Exception) -> dict:
    kind = getattr(exc, "kind", None) or type(exc).__name__.upper().replace("ERROR", "") or "ERROR"
    # Normalise to the stable "ERROR" sentinel when the binding does not map
    # the kind. The suite's kind_in lists accept either, so a binding that
    # knows the specific sentinel is more precise than one that does not.
    if kind in {"", "SOROAUTH"}:
        kind = "ERROR"
    return {"id": case_id, "ok": False, "kind": kind, "error": str(exc)}


def _run_preimage(case_id: str, inputs: dict) -> dict:
    try:
        r = soroauth.preimage(
            inputs["entry_xdr_b64"],
            int(inputs["valid_until_ledger"]),
            inputs["network_passphrase"],
        )
        return _ok_result(case_id, preimage_xdr=r.preimage_xdr, payload_hex=r.payload_hex)
    except Exception as exc:  # noqa: BLE001
        return _err_result(case_id, exc)


def _run_payload(case_id: str, inputs: dict) -> dict:
    try:
        r = soroauth.payload(inputs["preimage_xdr_b64"])
        return _ok_result(case_id, payload_hex=r.payload_hex)
    except Exception as exc:  # noqa: BLE001
        return _err_result(case_id, exc)


def _run_authorize(case_id: str, inputs: dict) -> dict:
    try:
        r = soroauth.authorize_with_seed(
            inputs["entry_xdr_b64"],
            int(inputs["valid_until_ledger"]),
            inputs["network_passphrase"],
            inputs["seed_hex"],
            inputs.get("for_address"),
        )
        return _ok_result(case_id, signed_entry_xdr=r.entry_b64)
    except Exception as exc:  # noqa: BLE001
        return _err_result(case_id, exc)


def _run_case(case: dict, vectors_dir: Path) -> dict:
    case_id = case["id"]
    try:
        inputs = _resolve_inputs(case, vectors_dir)
    except Exception as exc:  # noqa: BLE001
        return {"id": case_id, "ok": False, "kind": "ERROR", "error": str(exc)}
    op = case["op"]
    if op == _OP_PREIMAGE:
        return _run_preimage(case_id, inputs)
    if op == _OP_PAYLOAD:
        return _run_payload(case_id, inputs)
    if op == _OP_AUTHORIZE_WITH_SEED:
        return _run_authorize(case_id, inputs)
    return {"id": case_id, "ok": False, "kind": "ERROR", "error": f"unknown op {op}"}


def main() -> int:
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("usage: run.py <cases.json> [vectors-dir]", file=sys.stderr)
        return 2
    cases_path = Path(sys.argv[1])
    if len(sys.argv) == 3:
        vectors_dir = Path(sys.argv[2])
    else:
        vectors_dir = cases_path.parent.parent / "vectors"
    with open(cases_path, "r", encoding="utf-8") as fh:
        f = json.load(fh)
    if f.get("schema_version") != 1:
        print(f"unknown schema_version {f.get('schema_version')}", file=sys.stderr)
        return 1
    for case in f.get("cases", []):
        row = _run_case(case, vectors_dir)
        print(json.dumps(row, separators=(",", ":"), ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
