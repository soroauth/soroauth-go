"""A small, correctly typed program.

Running `mypy --strict sample_ok.py` must succeed. Running it against
`sample_bad.py` must fail. The pair is what proves the stubs do work: a
single always-passing sample would succeed even if the stubs were empty.
"""

from __future__ import annotations

import soroauth
from soroauth import Base64Xdr, HexStr, LedgerSeq


def build_and_inspect(
    entry: Base64Xdr,
    valid_until: LedgerSeq,
    passphrase: str,
    seed: HexStr,
) -> Base64Xdr:
    """Walk the whole public surface once with correct types."""
    pre: soroauth.PreimageResult = soroauth.preimage(entry, valid_until, passphrase)
    _ = soroauth.payload(pre.preimage_xdr)

    signed: soroauth.SignResult = soroauth.authorize_with_seed(
        entry, valid_until, passphrase, seed
    )
    multi: soroauth.SignResult = soroauth.authorize_with_seeds(
        entry, valid_until, passphrase, [seed, seed]
    )
    _ = multi

    info: dict[str, object] = soroauth.inspect(signed.entry_b64)
    _ = info

    findings: list[dict[str, object]] = soroauth.analyze(
        signed.entry_b64, current_ledger=valid_until
    )
    _ = findings

    tree: str = soroauth.render_tree(signed.entry_b64)
    inv: str = soroauth.render_invocations(signed.entry_b64)
    _ = tree
    _ = inv

    return signed.entry_b64


def catches_typed_exception(entry: Base64Xdr, valid_until: LedgerSeq) -> str:
    """The `kind` attribute is typed, so this reads under strict mypy."""
    try:
        soroauth.preimage(entry, valid_until, "")
    except soroauth.SourceAccountCredentialsError as exc:
        return exc.kind
    except soroauth.SoroauthError as exc:
        return exc.kind
    return "ok"
