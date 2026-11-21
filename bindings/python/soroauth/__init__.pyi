"""Type stubs for the public soroauth API.

The three string kinds this library handles are named rather than left as
`str`: `Base64Xdr` is base64-encoded XDR, `HexStr` is lowercase hex, and
`LedgerSeq` is a ledger sequence number. They are aliases, not `NewType`s,
so existing call sites keep working; the aliases exist so a reader can tell
at a glance which of the three a parameter wants.

Only the public surface declared in `__init__.py`'s `__all__` is covered
here. The `_ffi` and `ffi` modules are private and carry no stubs.
"""

from __future__ import annotations

from typing import Any, Dict, Final, List, Mapping, Optional, Sequence, Union

# ---------------------------------------------------------------------------
# Precise aliases for the three string kinds the library handles.
#
# These are aliases, not NewType: a reader learns what the parameter means
# without every call site needing a cast. A stricter contract would be a
# NewType, which the library can tighten later without breaking the public
# names.
# ---------------------------------------------------------------------------

Base64Xdr = str
"""Base64-encoded XDR, as emitted by the Stellar SDKs."""

HexStr = str
"""Lowercase hex, without any `0x` prefix. 64 chars for a 32-byte payload."""

LedgerSeq = int
"""A Stellar ledger sequence number (uint32 on the wire)."""

__version__: Final[str]
__all__: list[str]

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SoroauthError(Exception):
    """Base exception for every failure the library reports.

    The `kind` attribute names the underlying Go sentinel so a caller can
    switch on it; the subclasses below are the typed form of the same
    information.
    """

    kind: str
    message: str

    def __init__(self, message: str, kind: str = ...) -> None: ...
    def __repr__(self) -> str: ...

class SourceAccountCredentialsError(SoroauthError):
    """The entry uses source-account credentials; the ABI refuses to sign."""

class UnsupportedCredentialsError(SoroauthError):
    """The credential arm is not one the library builds a preimage for."""

class NoMatchingCredentialNodeError(SoroauthError):
    """No credential node in the entry matches the requested address."""

class DuplicateDelegateError(SoroauthError):
    """A delegate address appears twice at the same tier."""

class SignatureMismatchError(SoroauthError):
    """The signer returned a signature that does not verify against the payload."""

class MissingSignerError(SoroauthError):
    """The multisig tree asked for a signer the caller did not supply."""

class AlreadySignedError(SoroauthError):
    """A credential node already carries a signature for this address."""

class InvalidExpirationError(SoroauthError):
    """The valid-until ledger is zero or before the signing ledger."""

class TooManySignaturesError(SoroauthError):
    """More than the 20-key cap AccountMultiSigner enforces."""

class DecodeLimitError(SoroauthError):
    """The entry hit the library's bounded decoder limits."""

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class PreimageResult:
    preimage_xdr: Base64Xdr
    payload_hex: HexStr

    def __init__(self, preimage_xdr: Base64Xdr, payload_hex: HexStr) -> None: ...
    def __repr__(self) -> str: ...

class PayloadResult:
    payload_hex: HexStr

    def __init__(self, payload_hex: HexStr) -> None: ...
    def __repr__(self) -> str: ...

class SignResult:
    entry_b64: Base64Xdr

    def __init__(self, entry_b64: Base64Xdr) -> None: ...
    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def version() -> str: ...
def preimage(
    entry_b64: Base64Xdr,
    valid_until_ledger: LedgerSeq,
    network_passphrase: str,
) -> PreimageResult: ...
def payload(preimage_xdr_b64: Base64Xdr) -> PayloadResult: ...
def authorize_with_seed(
    entry_b64: Base64Xdr,
    valid_until_ledger: LedgerSeq,
    network_passphrase: str,
    seed_hex: HexStr,
    for_address: Optional[str] = ...,
) -> SignResult: ...
def authorize_with_seeds(
    entry_b64: Base64Xdr,
    valid_until_ledger: LedgerSeq,
    network_passphrase: str,
    seeds_hex: Union[HexStr, Sequence[HexStr]],
    for_address: Optional[str] = ...,
) -> SignResult: ...
def write_signature(
    entry_b64: Base64Xdr,
    valid_until_ledger: LedgerSeq,
    network_passphrase: str,
    for_address: str,
    signature_scval_b64: Base64Xdr,
) -> SignResult: ...
def inspect(entry_b64: Base64Xdr) -> Dict[str, Any]: ...
def analyze(
    entry_b64: Base64Xdr,
    current_ledger: Optional[LedgerSeq] = ...,
    max_delegate_depth: Optional[int] = ...,
    max_total_delegates: Optional[int] = ...,
    max_valid_until_ledger_delta: Optional[int] = ...,
    known_contracts: Optional[Mapping[str, bool]] = ...,
    max_sub_invocations: Optional[int] = ...,
) -> List[Dict[str, Any]]: ...
def render_invocations(entry_b64: Base64Xdr) -> str: ...
def render_tree(entry_b64: Base64Xdr) -> str: ...
