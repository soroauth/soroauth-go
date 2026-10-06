# FAQ

Most of these are questions about _why_ soroauth behaves a certain way, and
every answer is already in a doc comment, the README or a CAP. They are
collected here because a doc comment is hard to find before you know which
function to look at.

Each answer links its authoritative source. Where the source is the protocol or
the host, that is cited rather than paraphrased — soroauth's rule is that a
claim about host behaviour carries the CAP, the `rs-soroban-env` function, or
the SDK file and line, never memory.

## Signing

### Why doesn't it sign the top-level node by default?

Because a signature on the wrong node produces a transaction that pays fees and
then fails during application.

soroauth writes a signature only onto a node whose address equals the target —
`ForAddress`, or the signer's own `Address()`. If nothing matches, it returns
`ErrNoMatchingCredentialNode` rather than falling back. The JS reference does
fall back to the top-level node when no target is given, even if the key belongs
to someone else, and that difference is deliberate.

See [Differences from the JS SDK](../README.md#differences-from-the-js-sdk).

### Why is my signer never called when nothing matches?

The zero-match check and the already-signed check both run _before_ signing, so
a hardware wallet or remote signer is never asked to approve something that is
about to be discarded. That is the third of the four
[documented differences](../README.md#differences-from-the-js-sdk).

### Why does re-signing a node need `AllowResign`?

Under CAP-71-01 every signature-bearing node in a delegates entry commits to the
_same_ payload, and that payload includes the expiration ledger. Re-signing one
node at a different expiration therefore silently invalidates every other node's
signature. The entry still looks complete and fails only on-chain.

`AllowResign` can be scoped to named addresses, which matters when you are
replacing one party's signature: an unscoped `AllowResign()` shared across a
batch would also permit overwriting every _other_ delegate's signature.

See the `AllowResign` doc comment in [authorize.go](../authorize.go).

### Why can't `AllowResign` change the expiration too?

Because that guard protects the _other_ nodes, not the one you named. In the
delegates arm, if any node is already signed and the stored top-level expiration
disagrees with the one you are passing, the call fails with
`ErrInvalidExpiration` — and no address list lifts it, by design.

The practical consequence for a multi-party flow is in
[multi-party-signing.md](multi-party-signing.md): the expiration has to be
agreed before the first party signs.

### Why does wrapping or upgrading a _signed_ entry fail instead of replacing the signature?

Both operations change the signing payload, so the old signature would no longer
verify — and an entry that looks complete while being rejected on-chain is the
worst possible outcome. soroauth returns `ErrAlreadySigned`. The JS SDK silently
discards the old signature instead.

The `ScvVoid` and empty-`ScvVec` placeholders that simulation emits are not
signatures and are wrapped or upgraded normally.

See the `UpgradeToV2` doc comment in [upgrade.go](../upgrade.go).

## Batches and delegates

### Why does `AuthorizeAll` succeed with a delegate node left unsigned?

Because it cannot know whether that delegate's signature was required. A 2-of-3
delegate policy is legitimate, and so is a tree where only one branch needs to
sign.

Under CAP-71-01 ("Semantics", `delegate_account_auth`), a delegate node is only
exercised if the account's own `__check_auth` calls `delegate_account_auth` for
that address. An unsigned node that is never delegated to costs nothing; an
unsigned node that _is_ delegated to hands the delegate an empty signature,
which a G-account delegate cannot authenticate with.

In practice, expect the second case. So unless you know your account's policy,
treat an unsigned node as one that will fail: check the per-node `Signed` flags
`Inspect` reports, or pass `RequireAllSigned()`, rather than reading a nil error
as "fully signed".

The full reasoning, including why requiring a top-level signature would make the
delegates arm unusable in the case it was designed for, is in the `AuthorizeAll`
doc comment in [batch.go](../batch.go).

### Then why doesn't it require a top-level signature at least?

CAP-71-01 permits a `Void` top-level signature when an account authenticates
purely through its delegates, and an entry built that way is complete without
the account signing anything. Requiring one would break the arm's main use.

`RequireAllSigned()` is the opt-in for a caller who _does_ know their policy
requires every node signed. It checks every node literally, which also means a
delegates-only account that deliberately leaves its top-level node `Void` must
not use it — the option cannot tell "intentionally Void" from "forgotten".

### Why does it sort my delegate list for me?

CAP-71-01 requires delegates in strictly ascending order of the XDR encoding of
their address, at every level, and the host rejects a mis-ordered or duplicated
array before the account contract runs. Sorting is therefore not a convenience
that could differ from the protocol; there is one correct order.

Duplicates within one level are rejected with `ErrDuplicateDelegate`. The same
address at two _different_ levels is allowed — see
[glossary.md](glossary.md#delegates).

### Why do I need _two_ simulation passes?

Signing changes what the transaction costs: a signature `ScVal` is real memory
the host has to hold and check. A transaction assembled from the recording pass
carries a resource fee that is too small once the signatures are on, and is
rejected on-chain for exceeding its budget — after fees, and after your signers
have approved.

The enforcing pass is also a free pre-flight check: it executes `__check_auth`
with your real signatures, so a wrong signature shape or a mis-targeted address
is caught locally.

See
[The two-pass simulation requirement](../README.md#the-two-pass-simulation-requirement),
and `rpcflow.SignAndSubmit` if you want the flow rather than the explanation.

## Expiration

### Is the expiration ledger inclusive or exclusive?

Inclusive. `verify_and_consume_nonce` in `rs-soroban-env` rejects only when
`ledger_seq > live_until_ledger`, so the expiration ledger itself is still
valid. The JS SDK's doc comment describes the bound as exclusive; the host is
the authority.

`ExpirationAfter(1000, 1)` returns 1001, which is accepted in ledger 1001 and
rejected from ledger 1002.

### Why is there no maximum expiration check?

The host also rejects anything above the network's `max_live_until_ledger`, but
that is a network setting, so a baked-in constant here would silently become
wrong. Read it from the network if you need the real ceiling.

### Why is `ExpirationAfter(latest, 0)` refused?

Because by the inclusive rule above, `latest` has already closed — a transaction
built now lands in `latest + 1` at the earliest. Zero is already expired, not
permissive, so it fails closed with `ErrInvalidExpiration`.

Both answers are in [Expiration](../README.md#expiration) and the
`ExpirationAfter` doc comment.

## Credential arms

### Is `SOROBAN_CREDENTIALS_ADDRESS` deprecated?

No. CAP-71-02 has a section titled "No deprecation of
`SOROBAN_CREDENTIALS_ADDRESS`" and says deprecation _may_ be considered in
protocol 28 or later. The Protocol 28 upgrade guide lists no such removal, and
`rs-soroban-env` `main` still handles the arm.

What V2 actually does is bind the signer's address into the signed payload,
which closes a narrow replay case: a key shared across accounts, plus a contract
that does not bind the address in its own arguments. See
[glossary.md](glossary.md#the-four-credential-arms).

### Which arm will simulation give me?

Either. The RPC field that asks for V2,
`SimulateTransactionRequest.UseUpgradedAuth`, is explicitly best-effort: its own
documentation says it affects only the recording auth modes and is silently
ignored by protocol versions whose host cannot emit `AddressV2`
(`protocols/rpc/simulate_transaction.go:24-32` in `go-stellar-sdk`). It is also
described there as transitional, to become a no-op once the RPC returns
`AddressV2` by default — so you cannot rely on _omitting_ it to keep receiving
the legacy format either.

A caller who requires V2 must check what came back and upgrade it. `UpgradeToV2`
returns an already-V2 entry as an unaliased copy with a nil error, so you can
call it unconditionally.

### Can a nonce really be negative?

Yes. It is an `int64` in the credentials, so negative values are legal, and the
golden vector `testdata/vectors/legacy_negative_nonce.json` exists to prove
soroauth handles one byte-for-byte. It is also not a counter: the host consumes
it so an entry cannot be replayed, but there is no ordering requirement.

See [glossary.md](glossary.md#the-entry).

## Verification

### Why is a signature an `ScVal` rather than 64 bytes?

Because its shape is whatever the address's account logic expects, not something
the protocol fixes. For a classic account the host expects a vector of maps with
`public_key` and `signature` keys, in that order. A custom account defines its
own.

That is why `Signer.Sign` returns an `ScVal` and why `SignerFunc` exists: a
smart wallet owns its own signature shape, and soroauth writes what the signer
returns verbatim.

### Why does `soroauth verify` say `cannot_check` for my smart wallet?

Because only the contract's `__check_auth` can decide, and that requires the
host. A signature on a `C…` address is reported as `cannot_check` and never as
`verified` — reporting it as valid would be a claim soroauth cannot support.

What `verify` can and cannot establish offline is set out in
[verification-limits.md](verification-limits.md).

### Does a nil error from signing mean the transaction will succeed?

No. It means the bytes are what the protocol asks for. Whether the account's
policy is satisfied is decided by `__check_auth` on-chain — which is exactly
what the enforcing simulation pass lets you check locally first.

## Scope

### Why is there no key management in the library?

The root module depends only on `go-stellar-sdk` (plus the CLI's TUI
dependencies), so adding soroauth to a backend does not pull in a cloud SDK.
`Signer` is an interface for that reason.

KMS and wallet integrations therefore live in separate Go modules under
[adapters/](../adapters) — `awskms`, `gcpkms` and `walletsdk` — each with its
own `go.mod`, so you depend on one only if you use it. [signers.md](signers.md)
covers which signer suits which threat model.

### Will it tell me what an entry authorizes in plain language?

Not here. `Inspect` reports structure — arm, address, nonce, expiration,
delegate tree, which nodes are signed — and deliberately stops there.
Interpreting an invocation tree is a different problem with a different honesty
boundary, and it lives in
[soroauth-explain](https://github.com/soroauth/soroauth-explain).

### Is soroauth audited?

No. It is proven byte-for-byte against `@stellar/stellar-sdk@17.1.0` and run
live on testnet, and neither of those is an audit. See
[Status](../README.md#status) and [SECURITY.md](../SECURITY.md).
