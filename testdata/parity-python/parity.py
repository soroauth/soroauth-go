#!/usr/bin/env python3
"""Python stellar-sdk parity harness for the soroauth golden vectors.

The golden vectors prove soroauth agrees with ``@stellar/stellar-sdk`` byte for
byte. They cannot prove that agreement is *correct*: a bug committed by both the
Go library and the JS reference would be baked into the vectors and every test
would keep passing. Recomputing the preimage and the payload with a third,
independently maintained implementation is the cheapest way to catch that class
of bug.

This harness reads every ``testdata/vectors/*.json`` the JS generator wrote,
rebuilds the ``HashIDPreimage`` from the recorded ``unsigned_entry_xdr``,
``valid_until_ledger`` and ``network_passphrase`` with the Python
``stellar-sdk``, and asserts that:

* the marshalled preimage equals the recorded ``preimage_xdr``;
* ``sha256(preimage)`` equals the recorded ``payload_hex``.

It never writes to a vector. A disagreement is a failure to investigate, not a
value to update: see the accompanying README.

Cases the Python SDK cannot express are skipped **loudly** -- named on stderr
and counted in the summary -- and a run that checked nothing is a failure, so
the harness cannot pass by doing nothing.

Pinned reference: ``stellar-sdk==16.1.0`` (see ``requirements.txt``). The
harness reads the version that is actually installed and refuses to run against
anything else, the same way ``testdata/gen/gen.mjs`` does for its JS SDK.

Run it with:

    python3 testdata/parity-python/parity.py

Exit status is 0 only when every non-skipped vector matched and at least one
vector was checked.
"""

from __future__ import annotations

import argparse
import dataclasses
import glob
import json
import os
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as installed_version
from pathlib import Path

# The exact Python SDK this harness is pinned to. Vectors are only meaningful
# when they are compared against a known reference build, so an installed
# version other than this one is refused rather than compared.
REQUIRED_SDK_VERSION = "16.1.0"

# Repository layout: this file lives in testdata/parity-python/, next to
# testdata/vectors/.
HERE = Path(__file__).resolve().parent
DEFAULT_VECTORS_DIR = HERE.parent / "vectors"

# SorobanCredentialsType discriminants, named for readable output.
_CREDENTIAL_TYPES = {
    0: "source_account",
    1: "address",
    2: "address_v2",
    3: "address_with_delegates",
}


def credential_type_name(value: int) -> str:
    """Name a Soroban credential arm for human-readable output."""
    return _CREDENTIAL_TYPES.get(value, f"unknown({value})")


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class CaseResult:
    """The outcome of checking one vector."""

    name: str
    status: str  # "match", "mismatch" or "skip"
    detail: str = ""

    @property
    def matched(self) -> bool:
        return self.status == "match"

    @property
    def mismatched(self) -> bool:
        return self.status == "mismatch"

    @property
    def skipped(self) -> bool:
        return self.status == "skip"


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------


def require_pinned_sdk() -> str:
    """Return the pinned SDK version, or exit if the installed one differs.

    Reading the version from the installed distribution -- rather than trusting
    a constant -- is what makes the pin meaningful: a stale virtualenv with a
    different SDK is detected here instead of silently producing a second
    opinion nobody can attribute to a version.
    """
    try:
        found = installed_version("stellar-sdk")
    except PackageNotFoundError:
        sys.stderr.write(
            "parity harness: the Python 'stellar-sdk' package is not installed.\n"
            "Install the pinned reference with:\n"
            f"  pip install -r {HERE / 'requirements.txt'}\n"
        )
        raise SystemExit(2)

    if found != REQUIRED_SDK_VERSION:
        sys.stderr.write(
            f"parity harness: installed stellar-sdk is {found}, this harness is "
            f"pinned to {REQUIRED_SDK_VERSION}.\n"
            f"Install the pinned reference with:\n"
            f"  pip install -r {HERE / 'requirements.txt'}\n"
        )
        raise SystemExit(2)

    return found


# ---------------------------------------------------------------------------
# Per-vector verification
# ---------------------------------------------------------------------------


def check_vector(path: Path) -> CaseResult:
    """Recompute one vector's preimage and payload and compare to the record.

    ``path`` is the JSON file. An unrepresentable case comes back as a ``skip``
    result, and a genuine disagreement as a ``mismatch``; neither raises.
    """
    # Imported here so ``require_pinned_sdk`` can print its friendly message
    # before a missing install would raise ImportError.
    import stellar_sdk.xdr as xdr
    from stellar_sdk.auth import (
        authorization_payload_hash,
        build_authorization_preimage,
    )

    with path.open(encoding="utf-8") as handle:
        vector = json.load(handle)

    name = vector.get("name") or path.name
    entry = xdr.SorobanAuthorizationEntry.from_xdr(vector["unsigned_entry_xdr"])
    cred_type = int(entry.credentials.type)

    if not vector.get("preimage_xdr"):
        # A vector with an empty recorded preimage is one the recording side
        # decided has no preimage at all -- a source-account entry, which the
        # transaction envelope authenticates instead. There is nothing to
        # recompute, so this is skipped, loudly, by name and reason.
        return CaseResult(
            name=name,
            status="skip",
            detail=(
                "no recorded preimage: "
                f"credential_type={credential_type_name(cred_type)}; cases with "
                "no preimage cannot be recomputed"
            ),
        )

    try:
        preimage = build_authorization_preimage(
            entry,
            vector["valid_until_ledger"],
            vector["network_passphrase"],
        )
    except ValueError as exc:
        # The Python SDK actively refuses an arm it cannot express. That is a
        # skip, not a pass, and the SDK's own message is the reason.
        return CaseResult(
            name=name,
            status="skip",
            detail=(
                f"credential_type={credential_type_name(cred_type)}: Python "
                f"stellar-sdk cannot express this case: {exc}"
            ),
        )

    got_preimage = preimage.to_xdr()
    got_payload = authorization_payload_hash(preimage).hex()
    want_preimage = vector.get("preimage_xdr", "")
    want_payload = vector.get("payload_hex", "")

    problems: list[str] = []
    if got_preimage != want_preimage:
        problems.append(
            f"preimage differs\n    want {want_preimage}\n     got {got_preimage}"
        )
    if got_payload != want_payload:
        problems.append(f"payload differs\n    want {want_payload}\n     got {got_payload}")

    if problems:
        return CaseResult(name=name, status="mismatch", detail="; ".join(problems))

    return CaseResult(name=name, status="match")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run(vectors_dir: Path) -> list[CaseResult]:
    """Check every vector in ``vectors_dir`` and return the per-vector results."""
    paths = sorted(Path(p) for p in glob.glob(os.fspath(vectors_dir / "*.json")))
    if not paths:
        raise SystemExit(
            f"parity harness: no vectors found in {vectors_dir}; "
            "run `cd testdata/gen && npm ci && node gen.mjs` to generate them"
        )
    return [check_vector(path) for path in paths]


def report(results: list[CaseResult], out=sys.stdout, err=sys.stderr) -> int:
    """Print a human-readable report and return the process exit code."""
    matched = [r for r in results if r.matched]
    mismatched = [r for r in results if r.mismatched]
    skipped = [r for r in results if r.skipped]

    for result in results:
        if result.matched:
            print(f"  ok    {result.name}", file=out)
        elif result.skipped:
            # Skips go to stderr so they cannot be mistaken for the "ok" lines,
            # and they name the case and the reason.
            print(f"  skip  {result.name}: {result.detail}", file=err)

    for result in mismatched:
        print(f"  FAIL  {result.name}: {result.detail}", file=err)

    print(
        f"\nparity harness: {len(matched)} matched, {len(skipped)} skipped, "
        f"{len(mismatched)} mismatched (of {len(results)})",
        file=out,
    )

    if mismatched:
        print(
            "\nDo not edit a vector to make this pass. A disagreement here means "
            "one of the two implementations is wrong; open an issue with the "
            "protocol reference (CAP-71-01) and investigate.",
            file=err,
        )
        return 1

    # A run that checked nothing is not a pass. This is the guard against the
    # harness silently degrading to a no-op if every vector becomes skippable.
    if not matched:
        print(
            "parity harness: nothing was actually checked; refusing to report success",
            file=err,
        )
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Recompute the golden vectors' preimages and payloads with the "
            "Python stellar-sdk and compare them against the recorded values."
        )
    )
    parser.add_argument(
        "--vectors",
        type=Path,
        default=DEFAULT_VECTORS_DIR,
        help=(
            "directory holding the golden vector JSON files "
            f"(default: {DEFAULT_VECTORS_DIR})"
        ),
    )
    args = parser.parse_args(argv)

    sdk_version = require_pinned_sdk()
    print(f"Python stellar-sdk {sdk_version} parity harness")
    print(f"vectors: {args.vectors}")

    results = run(args.vectors)
    return report(results)


if __name__ == "__main__":
    raise SystemExit(main())
