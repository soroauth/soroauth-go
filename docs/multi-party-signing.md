# Multi-party signing walkthrough

This walkthrough has three delegates sign one Soroban authorization entry in
sequence. Each person receives the current base64 XDR entry, signs only their
own node, and returns the updated entry to the next person. Under CAP-71-01,
every delegate signature is over the same payload, bound to the top-level
account; the signatures do not authorize separate parts of the invocation.

## Before starting

- Install the `soroauth` CLI and `jq`.
- Start with an **unsigned** simulated authorization entry for an account that
  supports delegated authentication. Keep the invocation and top-level account
  address unchanged throughout this process.
- Agree out of band on the three delegate addresses, their order of handoff, the
  network, and the exact invocation being approved. `soroauth inspect` reports
  structure; it does not explain what the invocation does.
- Each delegate must confirm that the address they are asked to sign is theirs
  and is accepted by the top-level account's authentication policy.

The example uses one nested delegate and one sibling:

```text
top-level account
├── Party A
│   └── Party B
└── Party C
```

Replace the example addresses below with the real addresses from your account
policy. The CLI sorts delegate arrays by their XDR address encoding as required
by CAP-71-01; the sort order does not determine who signs first.

## Prepare the entry once

The coordinator wraps the unsigned entry, setting one expiration for the whole
round. `--valid-for` resolves a lifetime against the RPC's latest ledger. The
coordinator then reads the resulting absolute expiration so it can be sent
unchanged to all three signers.

```bash
set -euo pipefail
export SOROAUTH_RPC_URL='https://soroban-testnet.stellar.org'
UNSIGNED_ENTRY_B64='paste-the-unsigned-simulated-entry-base64-here'
PARTY_A_ADDRESS='G...'
PARTY_B_ADDRESS='G...'
PARTY_C_ADDRESS='G...'
DELEGATE_TREE="[{\"Address\":\"$PARTY_A_ADDRESS\",\"Nested\":[{\"Address\":\"$PARTY_B_ADDRESS\"}]},{\"Address\":\"$PARTY_C_ADDRESS\"}]"

WRAPPED_ENTRY_B64=$(printf '%s' "$UNSIGNED_ENTRY_B64" |
  soroauth delegates --entry - --valid-for 100 \
    --rpc-url "$SOROAUTH_RPC_URL" --nested-json "$DELEGATE_TREE")
VALID_UNTIL=$(printf '%s' "$WRAPPED_ENTRY_B64" |
  soroauth inspect --entry - | jq -r '.valid_until_ledger')

printf 'Expiration ledger: %s\n' "$VALID_UNTIL"
printf '%s\n' "$WRAPPED_ENTRY_B64"
```

Send the wrapped entry, `VALID_UNTIL`, network name (`testnet` here), and the
expected delegate address to Party A through your normal handoff channel. The
base64 entry is not a secret, but it is an authorization artifact: distribute it
only to the intended participants.

If the entry starts with legacy `ADDRESS` credentials, wrapping converts it to
the address-bound delegates arm. Do not wrap after anyone has signed: changing
the credential arm changes the payload and invalidates any earlier signature.

## Party A signs

Party A checks the invocation and address out of band, stores the received XDR
in `ENTRY_B64`, and confirms the expiration is the agreed ledger. The seed is
read silently into the environment; it is never a CLI argument.

```bash
set -euo pipefail
ENTRY_B64='paste-the-wrapped-entry-base64-here'
VALID_UNTIL='paste-the-agreed-ledger-here'
PARTY_A_ADDRESS='G...'

read -r -s -p 'Party A Stellar seed: ' PARTY_A_SEED
printf '\n'
export PARTY_A_SEED
SIGNED_BY_A=$(printf '%s' "$ENTRY_B64" |
  soroauth sign --entry - --valid-until "$VALID_UNTIL" \
    --network testnet --secret-env PARTY_A_SEED --for "$PARTY_A_ADDRESS")
unset PARTY_A_SEED
printf '%s\n' "$SIGNED_BY_A"
```

Party A returns the complete `SIGNED_BY_A` base64 value and the unchanged
expiration ledger to Party B. The signature is added to Party A's matching node;
the other nodes remain as they were.

## Party B signs

Party B receives Party A's **updated** entry, not the original wrapped entry.
Party B verifies the same invocation, network, expiration, and their own address
before signing:

```bash
set -euo pipefail
ENTRY_B64='paste-the-complete-entry-returned-by-party-A-here'
VALID_UNTIL='paste-the-same-agreed-ledger-here'
PARTY_B_ADDRESS='G...'

read -r -s -p 'Party B Stellar seed: ' PARTY_B_SEED
printf '\n'
export PARTY_B_SEED
SIGNED_BY_B=$(printf '%s' "$ENTRY_B64" |
  soroauth sign --entry - --valid-until "$VALID_UNTIL" \
    --network testnet --secret-env PARTY_B_SEED --for "$PARTY_B_ADDRESS")
unset PARTY_B_SEED
printf '%s\n' "$SIGNED_BY_B"
```

Party B returns the full updated entry to Party C. Party A's signature remains
in the entry; Party B's signature is written to the nested Party B node.

## Party C signs

Party C repeats the same checks and signs the sibling node. Use the entry from
Party B and exactly the same absolute ledger expiration:

```bash
set -euo pipefail
ENTRY_B64='paste-the-complete-entry-returned-by-party-B-here'
VALID_UNTIL='paste-the-same-agreed-ledger-here'
PARTY_C_ADDRESS='G...'

read -r -s -p 'Party C Stellar seed: ' PARTY_C_SEED
printf '\n'
export PARTY_C_SEED
SIGNED_BY_C=$(printf '%s' "$ENTRY_B64" |
  soroauth sign --entry - --valid-until "$VALID_UNTIL" \
    --network testnet --secret-env PARTY_C_SEED --for "$PARTY_C_ADDRESS")
unset PARTY_C_SEED
printf '%s\n' "$SIGNED_BY_C"
```

Party C returns the final entry to the coordinator. The coordinator can inspect
and verify the classic-account signatures locally:

```bash
set -euo pipefail
printf '%s' "$SIGNED_BY_C" | soroauth inspect --entry -
printf '%s' "$SIGNED_BY_C" |
  soroauth verify --entry - --network testnet --allow-unsigned
```

`--allow-unsigned` permits the top-level account's `Void` signature, which
CAP-71-01 allows when delegates authenticate. It does not make an unsigned
delegate acceptable to the account's policy. The account contract still decides
which delegates it calls `delegate_auth` for.

## Keep expiration fixed

All delegate nodes sign the same payload, and for the delegates arm that payload
includes the top-level account and signature expiration (CAP-71-01). The host
accepts the expiration ledger itself; it rejects the entry once the current
ledger is greater than the expiration. It also rejects an expiration above the
network's `max_live_until_ledger`, which the CLI cannot determine offline.

Do not have each participant run `--valid-for`: each invocation can resolve to a
different absolute ledger. Pass the coordinator's exact `VALID_UNTIL` value to
every signer. If a signature already exists and a later signer supplies a
different expiration, `soroauth sign` refuses with an invalid-expiration error.
Do not bypass that guard: changing the expiration would invalidate the
signatures already collected. Choose a ledger that leaves time for all handoffs
while remaining within the network's allowed maximum.

After collecting signatures, the transaction coordinator must run an enforce
simulation with the signed entry, then assemble and submit the transaction using
that simulation's result. Signing changes the resources required; the
record-mode simulation is not ready to submit.

## Distributed key generation (FROST)

`frost.TrustedDealerKeygen` is for tests: one process holds the whole key while
it splits it. For a real group, use the DKG ceremony, where no participant and
no coordinator ever holds the full private key.

```go
cfg := frost.DKGConfig{Threshold: 2, MaxSigners: 3}
participant, err := frost.NewDKGParticipant(cfg, 1) // 1-indexed
round1, err := participant.Start()                  // broadcast this
// Every participant broadcasts its round-one package. Then:
round2, err := participant.Continue(allRound1)      // deliver round2[recipient]
// Each recipient collects the packages addressed to it. Then:
share, err := participant.Finalize(allRound1, sharesAddressedToMe)
```

Every package is verified before it is accepted. A participant that aborts, or
sends a commitment or share that does not verify, is named in a
`*frost.DKGError` and no usable share is produced. `Finalize` checks the
participant's public key share against the commitments and the group
verification key against every other participant's derivation before returning
anything.

`frost.NewDKGTranscript(cfg, allRound1)` returns the public transcript: every
commitment, every proof of knowledge, and the group verification key. It carries
no secret and `Verify()` re-checks it without participant state, which is what
lets a third party confirm the ceremony completed correctly. The verification
rules are RFC 9591 Appendix C.2 (commitments and `vss_verify`, with a failure
requiring the participant to abort); RFC 9591 Section 4 leaves the DKG
construction itself out of scope, and the Schnorr proof of knowledge is the one
the `bytemare/dkg` protocol defines.

The returned `frost.DKGShare` is the representation the FROST signer already
uses, so it goes straight into `frost.NewFROSTCoordinator` and
`frost.NewFROSTParticipant`.

## Refreshing shares

A group public key is the Stellar account address, so it cannot change. When
shares must stop being useful to an attacker who took one, refresh them instead
of re-keying:

```go
cfg := frost.RefreshConfig{Threshold: 2, MaxSigners: 3, Epoch: 1}
participant, err := frost.NewRefreshParticipant(cfg, 1)
commitment := participant.Commitment()      // public; broadcast
shares, err := participant.Shares(allCommitments) // private; one per recipient
next, err := participant.Apply(currentShare, sharesAddressedToMe, allCommitments)
```

Each participant contributes a random polynomial whose constant term is the
identity, so the sum of the contributions changes every share without changing
the group secret. `Apply` refuses a contribution with a non-zero constant term,
a share that fails `vss_verify`, a missing participant, or an epoch that is not
exactly one more than the current share's. The group verification key and the
account address are unchanged; the secret shares, public key shares and epoch
all move forward. A stale share combined with a refreshed share fails FROST
signature-share verification rather than producing a signature, and a
participant that misses the ceremony is named.

## Session transcripts

A coordinator can record a signed transcript of a delegates signing session:

```go
coord, err := soroauth.NewCoordinator(entry, validUntil, networkPassphrase,
    soroauth.WithSessionTranscript(coordinatorKey))
// ... coord.Record(ctx, address, signer) for each node ...
transcript, ok := coord.FinalizedTranscript()
err = soroauth.VerifyTranscript(transcript) // needs only the transcript
```

The transcript records the participants, the payload hash, each round, the
outcome (`complete`, `failed` or `aborted`), the audit records for the signing
calls, and the failure reason when the session did not complete. A failed
`Record` closes it as failed; `AbortTranscript` closes it deliberately; both
produce a verifiable transcript. It carries no seed, key share, nonce or
signature share, and only the payload hash rather than the payload. The
coordinator signs it once with Ed25519, and the public key travels inside it, so
verification needs no coordinator cooperation.
