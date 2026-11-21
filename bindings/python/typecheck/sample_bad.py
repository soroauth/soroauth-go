"""A deliberately wrong program.

Running `mypy --strict sample_bad.py` must FAIL. The function bodies
below each contain one type error the stubs catch; `check.sh` asserts
that mypy still reports them, so a regression in the stubs fails CI.
"""

from __future__ import annotations

import soroauth


def wrong_argument_type(entry: str) -> None:
    # valid_until_ledger is LedgerSeq (int). Passing a str is the kind of
    # mix-up the stubs exist to catch, and the thing a library of base64
    # strings, hex strings and ledger numbers is most likely to be bitten
    # by at a call site.
    soroauth.preimage(entry, "not-a-ledger", "Test SDF Network ; September 2015")


def wrong_result_attribute(entry: str, ledger: int) -> None:
    # PreimageResult has preimage_xdr and payload_hex; .entry_b64 is on
    # SignResult, not PreimageResult.
    pre = soroauth.preimage(entry, ledger, "Test SDF Network ; September 2015")
    _ = pre.entry_b64


def wrong_exception_attribute() -> None:
    # SoroauthError has `kind: str`; a call site that reaches for a
    # nonexistent `.code` should fail here.
    try:
        soroauth.preimage("x", 1, "")
    except soroauth.SoroauthError as exc:
        _ = exc.code
