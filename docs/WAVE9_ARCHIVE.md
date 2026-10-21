# Wave 9 archive

**Date:** 2026-10-18

Wave 9 contained 154 issues spanning signers, testing, API, documentation,
tooling, integrations, and protocol work. This document records which items
shipped and which did not, so the backlog serves as a honest historical record
rather than a to-do list.

## Shipped (implemented in the library)

The core library functionality from Wave 9 has been fully implemented and is
part of the `v0.1.0` release. The following categories are covered:

### Signer infrastructure

- `Signer` interface with `Address()` and `Sign(ctx, preimage, payload)` methods
- `NewEd25519Signer` for classic Ed25519 account signatures, with
  self-verification and the exact ScVal map shape
  (`{public_key: 32-byte-pubkey, signature: 64-byte-sig}`) matching the JS
  reference and the Soroban host
- `NewAccountMultiSigner` for multisig accounts, with keys strictly sorted by
  32-byte public key, capped at 20, and duplicate/zero-key rejection
- `SignerFunc` adapter for custom signers (passkey, KMS, remote)
- Context cancellation and deadline semantics documented and tested

### Preimage and authorization entry building

- `Preimage()` building for all four credential arms (source-account, legacy
  address/V1, V2 address-bound, address-with-delegates)
- `Payload()`: SHA-256 of the marshalled preimage
- `AuthorizeEntry()`: signs entries with the fail-closed target-address rule
- `UpgradeToV2()`: converts unsigned legacy entries to V2
- `Inspect()`: reports `EntryInfo` structure per entry
- `AuthorizeAll()`: all-or-nothing batch signing, delegate-aware
- `ExpirationAfter()`: computes expiration ledger with overflow check
- `ForAddress` option: target-address rule (only write signature to nodes whose
  address matches the target)

### Delegates

- `Delegate` type with `Address`, `Signature`, and `Nested` fields
- `WithDelegates()`: wraps entries with ordered delegate trees, sorting by XDR
  bytes at every level, rejecting duplicates within a level, allowing the same
  address at different levels
- `ValidateDelegateOrder()`: validates existing delegates-arm entries against
  sorting and duplicate rules
- Delegates arm nodes signed by address via `ForAddress`

### Address handling

- `ParseAddress()`: accepts `G…` (account) and `C…` (contract) strkeys, rejects
  `M…` muxed
- `FormatAddress()`: inverse round-trip
- `ArmProtocolVersion()`: protocol version per credential arm (CAP-46-11,
  CAP-71-01, CAP-71-02)

### Invocation and nonce

- `AuthorizeInvocation()`: builds entries from scratch with deterministic nonce
  from `crypto/rand`
- Nonce: 8 bytes big-endian `int64` from `crypto/rand`

### Errors

- 25+ sentinel errors with `errors.Is` support, each tested as a producing test
- `ErrSourceAccountCredentials`, `ErrUnsupportedCredentials`,
  `ErrNoMatchingCredentialNode`, `ErrDuplicateDelegate`, `ErrSignatureMismatch`,
  `ErrMissingSigner`, `ErrAlreadySigned`, `ErrInvalidExpiration`,
  `ErrTooManySignatures`

### CLI

- `soroauth payload`, `sign`, `delegates`, `inspect` subcommands
- `--secret-env` reads seed from environment only (no flag value)
- `--for <addr>` targets a specific address when signing

### Documentation and tooling

- All exported identifiers have doc comments (enforced by `internal/doccheck`)
- `make` targets: `fmt`, `vet`, `test`, `vectors`, `vectors-check`, `e2e`,
  `fuzz`, `soak`
- CI workflows: `ci.yml`, `ci-go.yml`, `fuzz.yml`, `parity.yml`, `sdk-main.yml`,
  `wasm.yml`, and others
- Golden vector generation and drift check (`make vectors-check`)
- Coverage floors per package
- Property-based fuzz targets: `FuzzValidateDelegateOrder`, `FuzzInspect`,
  `FuzzPreimage`, `FuzzPayload`, `FuzzDecodeAuthorizationEntry`,
  `FuzzVerifyEntry`, `FuzzDiffEntries`, `FuzzCopyRoundTrip`
- Soak test: `TestSoakBatchSigning`
- Continuous fuzzing infrastructure

### e2e test infrastructure

- Modular account contract for delegate testing
- Scenarios A-E: legacy signing, V2 signing, multisig, delegates, rejection
  scenarios
- `e2e/RESULTS.md` records real testnet transaction hashes
- fixture contracts built with `stellar contract build` and `cargo test`

### Benchmarks

- `bench_signing_test.go`: `Preimage`, `Payload`, `AuthorizeEntry` on all three
  arms, `AuthorizeAll`, `BenchmarkXDRCopy`
- `bench_arms_test.go`: `BenchmarkVerifyEntry`, `BenchmarkDiffEntries`,
  `BenchmarkDelegateTree` (nodes_1, nodes_4, nodes_16, nodes_63)
- Budget files in `testdata/bench/budgets.json` with ~40% headroom
- `scripts/checkbench` validates budgets on CI

### Protocol and SDK support

- Pinned `go-stellar-sdk` v0.7.3 with `go 1.26.3` toolchain
- Protocol version matrix citing CAP preambles
- CAP-85 audit: no wire-format change required against SDK v0.7.3
- SDK main nightly job checks compatibility against `go-stellar-sdk@main`

## Not shipped (outstanding items from Wave 9)

The following categories from Wave 9 remain outstanding. These are not part of
the `v0.1.0` release:

### Passkey / WebAuthn signers (high complexity, area:signers)

- secp256r1 signature verification primitives
- WebAuthn assertion parsing
- `PasskeySigner` implementing the `Signer` interface
- User presence and timeout handling for passkey signers
- CLI `--assertion` flag for passkey signatures
- Browser demo: passkey to submitted transaction

### Remote signer protocol and reference server (high, area:signers)

- Documented request/response schema carrying preimage and payload
- Reference server decoding and logging what it approves
- Client `Signer` with context cancellation

### KMS adapter modules (multiple, high, area:signers)

- AWS KMS signer
- Google Cloud KMS signer
- HashiCorp Vault signer
- Azure Key Vault / Managed HSM signer
- Ledger hardware wallet signer
- PKCS#11 signer for HSMs and smartcards
- Trezor hardware wallet signer
- Turnkey signer
- Fireblocks signer

### Threshold / MPC signing (high, area:signers)

- Conformance test suite every signer must pass
- Threshold signing with real key shares
- Policy-enforcing signer wrapper
- Rate-limited and quota-aware signer wrapper
- Cancellation and deadline semantics audit

### Advanced API features (multiple, high, area:api)

- Offline verification engine
- `soroauth verify` subcommand
- HTTP verification service
- Batch verification API
- Canonical JSON representation of an entry
- Templating entries for repeated authorizations
- Typed accessors for the credentials union
- Structured audit record for every signing decision
- Entry expiry and freshness policy helpers
- Merge independently signed copies of one entry
- Pluggable signature-shape registry
- Deterministic test-entry builders for downstream test suites

### Contract fixtures (multiple, high, area:integrations)

- Policy account with spending limits
- Social recovery account
- Session keys with time-bound delegates
- Threshold multi-sig smart account
- Wallet SDK adapter package

### Advanced tooling (multiple, high, area:tooling)

- Nested delegate syntax for the CLI
- JSON output mode on all subcommands
- Container image publishing
- Release automation
- CAP-85 support once the Go SDK ships P28 helpers
- Multi-party signing coordination library
- High-throughput batch signing
- Soroban RPC integration helpers
- Semantic diff between two authorization entries
- Delegate tree planner
- Metrics and tracing hooks
- Upstream auth-entry signing helper to go-stellar-sdk
- `RequireAllSigned` option for `AuthorizeAll`
- Delegate plan input for `AuthorizeAll`
- Typed errors carrying the offending address
- Audit context propagation across the API
- Protocol version compatibility matrix

### Documentation (multiple, medium/trivial, area:docs)

- Many doc examples, guides, and overviews
- CAP-85 note and support policy
- Two-pass simulation requirement guide
- Badges in the README header
- FAQ and glossary
- Contributor onboarding checklist
- Deprecation and support policy
- Package example in doc.go
- Table of contents in the README
- Table of contents in the docs directory
- Architecture diagrams as images
- Label taxonomy

### CI and release tooling (multiple, trivial/medium, area:tooling)

- Dependabot for Go modules, GitHub Actions, vector generator
- CODEOWNERS
- Security issue template
- `.editorconfig`
- SUPPORT.md and CITATION.cff
- `.gitattributes`
- Codeowners and other repo metadata chores
- Spell-check and link-check CI jobs
- GolangCI-lint adoption
- Normalise Markdown formatting
- Pin GitHub Actions to commit SHAs
- Makefile for common tasks

## Summary

Of 154 Wave 9 items, the core library shipping with `v0.1.0` implements the
majority of the signing path, address handling, delegate model, authorization
entry building, inspection, batching, expiration, error handling, CLI,
benchmarking, e2e testing, and CI infrastructure. The remaining items are
primarily passkey/WebAuthn signers, KMS/HSM adapters, threshold/MPC signing,
advanced API features, contract fixtures, and documentation/tooling additions
that are outside the scope of the `v0.1.0` release.

The Wave 9 backlog (`docs/WAVE9_BACKLOG.json`) is retained as an archive. The
old issue-creation script `scripts/wave9_issues.py` has been superseded by
`scripts/wave_issues.py`, which reads a backlog JSON and skips issues whose
titles already exist on GitHub, preventing duplicates.

## References

- `docs/WAVE9_BACKLOG.json` — the original Wave 9 issue backlog (source of truth
  for what was planned)
- `docs/WAVE10_BACKLOG.json` — the Wave 10 issue backlog (successor to Wave 9)
- `scripts/wave_issues.py` — the current issue-creation script
- `docs/labels.md` — issue label definitions
- `CONTRIBUTING.md` — contribution guidelines
