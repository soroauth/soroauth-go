# Wave 10 issue backlog

<!-- Generated from docs/WAVE10_BACKLOG.json by scripts/wave_issues.py --markdown. Do not edit by hand. -->

150 issues, 25000 points. `docs/WAVE10_BACKLOG.json` is the source of truth;
this document exists so the backlog can be read and reviewed before any issue is
created.

| Complexity |  Issues | Points each |    Points |
| ---------- | ------: | ----------: | --------: |
| High       |      80 |         200 |     16000 |
| Medium     |      40 |         150 |      6000 |
| Trivial    |      30 |         100 |      3000 |
| **Total**  | **150** |             | **25000** |

| Area                | Issues |
| ------------------- | -----: |
| `area:api`          |     16 |
| `area:docs`         |     28 |
| `area:integrations` |     18 |
| `area:protocol`     |     10 |
| `area:signers`      |     18 |
| `area:testing`      |     28 |
| `area:tooling`      |     32 |

## High — 200 points each (80 issues)

### `area:api`

#### feat(api): simulate an account contract's policy offline

Given an entry and a description of an account's policy — required signers,
thresholds, which delegates must sign — report whether the entry as it stands
satisfies it.

**Why this matters:** `AuthorizeAll` deliberately cannot know an account's
policy, so it enforces only that nothing is wholly unsigned, and the docs tell
callers to check the per-node `Signed` flags themselves. Everyone writes that
check, and the delegates arm makes it non-obvious enough to get wrong.

_Acceptance criteria_

- A policy type expressive enough for the shipped fixture contracts:
  threshold-of-N delegates, a required signer, and nested requirements.
- Reports which requirement is unmet and at which node, not a bare boolean.
- Tests drive it from the fixture contracts' actual rules, so the model is
  checked against something real rather than invented.
- The doc comment states plainly that this evaluates a policy the caller
  supplied and is not evidence about the deployed contract.

_Implementation guidance_

- The honesty boundary is the whole value: a pass here must never read as a
  promise the transaction will succeed.
- `threshold.go` and the fixture contracts in `e2e/contracts/` are the source
  for what policies look like in practice.
- Fail closed on a policy the evaluator cannot express, rather than
  approximating it.

#### feat(api): streaming signer for very large delegate trees

Sign a delegate tree without materialising every node, so memory stays flat as
the tree grows, and allow a caller to supply signatures lazily as they arrive.

**Why this matters:** `credentialNodes` walks the whole tree into a slice and
`batch_sign.go` works from that. For the trees shipped today that is fine; for a
tree assembled from many parties over time it means holding everything, and it
forces every signature to exist before any is written.

_Acceptance criteria_

- A callback or iterator API that visits each node once, in a documented order,
  and writes a signature as it is produced.
- A benchmark showing allocations flat as node count grows, compared against the
  current path.
- Identical output bytes to the existing API for every golden vector — proven by
  test, not by inspection.
- Cancellation is honoured mid-walk, with the entry left untouched rather than
  partly written.

_Implementation guidance_

- The existing API stays; this is an addition for callers who need it, not a
  replacement.
- `internal/xdrcopy` pools buffers — reuse that rather than adding a second
  pooling scheme.
- The partial-write failure mode is the risk: a cancelled walk must not return a
  half-signed entry with a non-nil error.

#### feat(api): canonical JSON representation of an entry

A documented, stable JSON encoding of a `SorobanAuthorizationEntry` that
round-trips to identical XDR bytes.

**Why this matters:** Entries move between tools as base64, which is exact and
unreadable. `Inspect` is readable and lossy. There is nothing in between, so
anything that needs to diff, review, store or template an entry invents its own
lossy JSON.

_Acceptance criteria_

- Round-trips every golden vector to byte-identical XDR, asserted for all of
  them.
- A schema document, and a version field so a later change is detectable rather
  than silent.
- Rejects input it cannot represent exactly, rather than dropping a field.
- Fuzz target asserting XDR → JSON → XDR is the identity.

_Implementation guidance_

- Exactness is the whole point; a convenient encoding that loses a field is
  worse than none.
- Reuse the decode-depth bound — this is another untrusted-input surface.
- Coordinate with the differential harness: a canonical JSON would make
  cross-implementation cases easier to write.

#### feat(api): templating entries for repeated authorizations

Build an entry from a template plus the fields that change per submission —
nonce, expiration, and chosen arguments — with validation that nothing else
moved.

**Why this matters:** A backend authorizing the same call repeatedly rebuilds
the whole entry each time, and the risk is a field drifting unnoticed between
submissions. A template makes the invariant part explicit and checkable.

_Acceptance criteria_

- A template type that pins the invocation tree and address, and requires nonce
  and expiration per instantiation.
- A checker that, given a template and an entry, reports whether the entry is an
  instance of it and what differs if not.
- Reuses `DiffEntries` for the comparison rather than reimplementing structural
  equality.
- A test proving two instantiations differing only in nonce produce different
  payloads.

_Implementation guidance_

- `DiffEntries` already separates payload-affecting fields from the rest; a
  template is the same distinction applied forward.
- Nonce generation stays in `invocation.go` — do not add a second source of
  randomness.
- Never let a template carry a signature: the payload changes per instance, so a
  stored signature would be invalid by construction.

#### feat(api): typed accessors for the credentials union

Replace the repeated `switch entry.Credentials.Type` blocks with one typed
accessor layer that makes an unhandled arm a compile-time or single-point
failure instead of a copy of the same switch.

**Why this matters:** `arm.go` introduced an arm abstraction, but the switch on
`Credentials.Type` still appears across `inspect.go`, `verify.go`, `diff.go`,
`batch.go` and `upgrade.go`. Adding a fifth credential arm means finding every
one of them, and the cost of missing one is a silent wrong answer rather than an
error.

_Acceptance criteria_

- One place that maps a credentials value to its arm behaviour, with every
  caller going through it.
- A test that fails if a new `SorobanCredentialsType` is handled in fewer places
  than it should be — a registry check, not a comment asking people to remember.
- No change to any exported signature, and no change to any golden vector's
  bytes.
- `go test -race ./...` and every parity suite stay green, proving the refactor
  is behaviour-preserving.

_Implementation guidance_

- `arm.go` is the existing seam; extend it rather than introducing a parallel
  abstraction.
- Behaviour-preserving means byte-identical: the vectors are the proof, so run
  them before and after.
- `refactor: scaffolding for future credential arms` from Wave 9 is the
  groundwork — read what it did first.

#### feat(api): structured audit record for every signing decision

An optional recorder that captures, per signing call, what was signed: arm,
address, nonce, expiration, payload hash, target node, and the decision taken —
in a form suitable for an append-only log.

**Why this matters:** `hooks.go` emits events for metrics and tracing, which is
the right shape for observability and the wrong shape for an audit trail: events
are sampled, unordered and droppable. An operator asked to prove which payloads
their service signed has nothing to hand over.

_Acceptance criteria_

- A record type carrying the payload hash and every preimage-derived field, with
  a stable serialisation.
- Records are produced for refusals too — a refused signature is the most
  interesting line in an audit log.
- No secret, seed or signature value is ever recorded; a test asserts the record
  contains none.
- Documented ordering and delivery guarantees, including what happens when the
  sink fails.

_Implementation guidance_

- Build on `hooks.go` only if its guarantees can be stated honestly; otherwise
  keep audit separate and say why in the doc comment.
- The library does no logging — this hands records to a caller-supplied sink, it
  does not write files.
- A sink that errors must not silently drop a record; decide and document
  whether that fails the signing call.

#### feat(api): entry expiry and freshness policy helpers

Helpers that answer, for an entry and a current ledger, whether it is still
valid, how many ledgers remain, and whether it is inside a caller-chosen safety
margin.

**Why this matters:** `ExpirationAfter` computes an expiration going in. Nothing
reads one back out. A service holding pre-signed entries has to re-derive the
inclusive-bound rule itself every time, and that rule is exactly the one the JS
SDK documents the other way round.

_Acceptance criteria_

- A validity check implementing the host's inclusive bound, cited to
  `verify_and_consume_nonce`.
- Remaining-ledger count, and a margin check for a caller-supplied threshold.
- Handles the delegates arm, where the top-level expiration governs every node.
- A table test covering the boundary ledgers either side, since off-by-one is
  the whole risk.

_Implementation guidance_

- `expiration.go` is the home; keep the existing doc-comment table as the single
  statement of the rule.
- The network's `max_live_until_ledger` is not knowable offline — do not cap,
  and say so.
- A source-account entry has no expiration; return an error rather than a
  misleading `true`.

#### feat(api): merge independently signed copies of one entry

Combine several copies of the same entry, each signed by a different party, into
one fully signed entry — refusing any pair that does not agree on the payload.

**Why this matters:** `coordinator.go` sequences multi-party signing, which
assumes the parties take turns. Parties who sign in parallel each hold a copy,
and merging them by hand is where a mismatched expiration silently invalidates
the others' signatures.

_Acceptance criteria_

- Refuses to merge copies whose payload-affecting fields differ, naming the
  field and the two values.
- Refuses two different signatures for the same node unless the caller
  explicitly chooses one.
- The merged entry is byte-identical to the same signatures applied
  sequentially, asserted against a golden vector.
- Reuses `DiffEntries` for the agreement check rather than reimplementing it.

_Implementation guidance_

- The refusal is the feature. A merge that quietly picks a winner produces an
  entry that looks complete and fails on-chain.
- `docs/multi-party-signing.md` states why the expiration must be fixed before
  anyone signs — this is the parallel case of that rule.
- All-or-nothing: on any disagreement return no entry, not a partial merge.

#### feat(api): pluggable signature-shape registry

Let a caller register a custom account's signature shape so `DescribeSignature`,
`VerifyEntry` and the risk analyzer can recognise and check it instead of
reporting `cannot_check`.

**Why this matters:** `cannot_check` is the honest answer for a shape the
library does not know, and it is also a dead end: a wallet vendor who knows
their own shape has no way to teach it to the library, so their users get no
verification at all.

_Acceptance criteria_

- A registry taking a shape matcher and a verifier, with the built-in ed25519
  and passkey shapes registered through the same mechanism.
- A registered verifier that fails reports `invalid`, never `cannot_check` — the
  distinction `VerifyVerdict` exists for.
- A registered shape cannot cause a false `verified`: a test asserts a verifier
  returning success on wrong bytes is still reported honestly, or that this is
  impossible by construction.
- Registration is explicit and per-caller; no global mutable default, and a test
  proving concurrent use is safe.

_Implementation guidance_

- `verify.go`'s four verdicts already carry the right distinctions — extend
  their sources, not the verdict set.
- The trust boundary needs stating: a registered verifier is the caller's claim,
  not the library's, and the report should make that legible.
- `SignerFunc` is the existing escape hatch on the signing side; this is its
  counterpart on the reading side.

#### feat(api): deterministic test-entry builders for downstream test suites

An exported, documented builder package producing entries of every arm with
fixed addresses, nonces and invocation trees, for use in other projects' tests.

**Why this matters:** The in-repo fixtures (`entryForArm`, `delegatesFixture`)
are unexported test helpers, so every downstream project writing tests against
soroauth hand-builds XDR structs — and a wrong fixture makes their tests pass
for the wrong reason.

_Acceptance criteria_

- Builders for all four arms plus a nested delegate tree, deterministic across
  runs and platforms.
- Keys derived by the repo's documented label scheme, with the package stating
  plainly that they are public test keys and must never be funded on mainnet.
- The repo's own tests are refactored onto it, so it cannot drift from what is
  actually used.
- Importing it pulls in no test-only dependency and no `testing` import in
  non-test files.

_Implementation guidance_

- A separate importable package, not the root — a test helper in the root
  package surface invites production use.
- `docs` already documents the deterministic key scheme; cite it rather than
  restating the derivation.
- If exporting the existing helpers verbatim would freeze an awkward signature,
  design the API first and migrate the tests onto it.

### `area:integrations`

#### feat(bindings): Python package wrapping the signing core

A published Python package exposing preimage construction, signing and
inspection, built on the existing wasm core or a C shared library.

**Why this matters:** The Python `stellar-sdk` has the same gap the Go SDK had:
no auth-entry signing helper. `testdata/parity-python` already proves the Python
SDK can be driven to the same bytes, so the correctness groundwork exists and
only packaging is missing.

_Acceptance criteria_

- Installable from a wheel with no Go toolchain required at install time.
- Every golden vector replayed through the Python API in its CI, asserting byte
  equality.
- The published API is documented, and its honesty boundaries match the Go
  library's — no verdict the Go library would call `cannot_check`.
- Wheels built for Linux and macOS in CI, with the build reproducible from the
  repo.

_Implementation guidance_

- `wasm/` and `cmd/soroauthwasm` already compile the core; reuse rather than
  starting a third surface.
- `testdata/parity-python` has the pinned SDK and venv machinery — build on it.
- A binding that can disagree with the Go library is worse than none, so the
  vector replay is the gate, not a nice-to-have.

#### feat(bindings): C shared library and header

A stable C ABI over the signing core, with a generated header, as the foundation
other language bindings build on.

**Why this matters:** Each new binding currently needs its own path to the core.
One reviewed C ABI makes Python, Ruby, PHP, Java and Swift bindings thin
wrappers instead of separate reimplementations.

_Acceptance criteria_

- A documented ABI with explicit memory ownership rules and no Go pointers
  escaping into C.
- Every error returned as a code plus a retrievable message; no path aborts the
  process.
- Built for Linux, macOS and Windows in CI, with the golden vectors replayed
  through the C API on each platform.
- An ASan or Valgrind run over the test harness, reported in the PR.

_Implementation guidance_

- `c-shared` build mode plus `cgo` export comments is the mechanism; the hard
  part is ownership, so document it before writing it.
- Secrets must not cross the boundary carelessly — define who zeroes what, and
  test it.
- Keep the surface minimal: preimage, payload, sign, inspect, verify. Breadth
  can come later; a published ABI is hard to change.

#### feat(bindings): Java/JVM binding

A JVM library over the C ABI or the wasm core, published to a Maven repository.

**Why this matters:** Java is the dominant language in the custody and exchange
systems that hold Stellar assets, and it is the ecosystem furthest from an
auth-entry signing helper today.

_Acceptance criteria_

- Published artifact installable without a local Go or Rust toolchain.
- Golden vectors replayed through the JVM API in CI with byte equality asserted.
- Native libraries bundled for Linux and macOS, with the selection mechanism
  documented and tested.
- Idiomatic exceptions carrying the same distinctions as the Go sentinels, so a
  caller can tell a refusal from a fault.

_Implementation guidance_

- Depends on the C ABI issue; check its state before starting and say so on the
  issue.
- Prefer the Foreign Function and Memory API over JNI if the baseline JDK allows
  it, and state the minimum version.
- Mirror the Go library's honesty boundaries exactly; a JVM `verify` that
  returns a boolean would erase the `cannot_check` distinction.

#### feat(bindings): Rust crate over the signing core

A Rust crate exposing the same operations, for tooling that already depends on
`stellar-xdr` and `soroban-sdk`.

**Why this matters:** The Soroban contract and tooling ecosystem is Rust, so
Rust is where the consumers of these entries live. `testdata/parity-rust`
already recomputes the vectors with the crate the host itself uses, which makes
a native crate the shortest path from this library to that ecosystem.

_Acceptance criteria_

- Replays every golden vector with byte equality in CI.
- Uses the same `stellar-xdr` version the parity harness pins, with the pin
  policy documented.
- No `unsafe` outside a clearly justified and commented boundary.
- Error types carry the same distinctions as the Go sentinels.

_Implementation guidance_

- A native Rust implementation and a binding over the C ABI are different
  projects with different risks — pick one deliberately and say which on the
  issue.
- If native: the parity harness becomes the correctness gate, so wire it in from
  the start.
- `docs/parity.md` states what agreement across implementations does and does
  not establish; inherit that framing.

#### feat(integrations): Stellar Wallets Kit / Freighter integration

Wire the wasm package into Stellar Wallets Kit and Freighter so a browser dapp
can sign an authorization entry through an installed wallet.

**Why this matters:** `examples/browser-passkey` proves the wasm core signs in a
browser with a passkey. The far more common browser case is a user with
Freighter installed, and that path does not exist, so dapps fall back to
hand-rolled signing.

_Acceptance criteria_

- A working example signing an entry through a real wallet extension, with the
  flow documented end to end.
- The signed entry is verified against the golden-vector path, so the wallet's
  output is checked and not assumed.
- Wallet rejection, locked wallet and wrong-network are distinct, handled states
  in the example.
- `docs/browser.md` gains the flow alongside the passkey one.

_Implementation guidance_

- `adapters/walletsdk` and `wasm/ts` are the existing pieces; this connects them
  rather than adding a third.
- A wallet that returns a signature for a different network must be caught —
  check the passphrase, do not trust the wallet to.
- Say plainly in the docs which wallet versions were actually tested.

#### feat(integrations): gRPC signing and verification service

A gRPC surface over the operations the HTTP service already exposes, with a
published protobuf schema.

**Why this matters:** `server/` and `remote/` speak HTTP/JSON. A backend fleet
that standardises on gRPC either proxies or reimplements, and the protobuf
schema is also the clearest machine-readable statement of the service contract.

_Acceptance criteria_

- A committed `.proto` with the schema, and generated code checked by CI to be
  in sync with it.
- Parity tests asserting the gRPC and HTTP surfaces return equivalent results
  for the same inputs.
- Deadlines and cancellation propagate to the signer, with a test.
- The honesty boundaries of `verify` are preserved in the schema —
  `cannot_check` is a distinct value, not a false.

_Implementation guidance_

- `remote/protocol.go` defines the existing contract; the proto should express
  the same thing, not a looser version.
- This adds dependencies: keep it in its own module so the root module stays
  thin.
- A service that signs needs its authentication story stated, not deferred —
  coordinate with the service-auth issue.

#### feat(integrations): GitHub Action to verify entries in a workflow

A published composite action wrapping `soroauth verify` and `soroauth inspect`,
so a repository can gate on an entry's structure and signatures in CI.

**Why this matters:** Teams that commit or generate authorization entries have
no way to check them in review. The CLI already does the work and exits with
meaningful codes; what is missing is the packaging that makes it one line in a
workflow.

_Acceptance criteria_

- Published and usable by SHA from another repository, with inputs for entry
  source, network and expected arm.
- Findings surface as workflow annotations, not only as log text.
- Its own integration test workflow in this repo, proving it fails on a bad
  entry and passes on a good one.
- No secret is ever accepted as an action input, consistent with the CLI's rule.

_Implementation guidance_

- Pin everything by commit SHA, as `CONTRIBUTING.md` requires of this repo's own
  workflows.
- The container image from Wave 9 is the natural runtime — reuse it rather than
  installing Go in the action.
- Add the action's own path to its workflow's `paths:` filter, or an edit to it
  will not run its own test.

#### feat(integrations): OpenAPI specification for the verification service

A committed OpenAPI document for the HTTP service, with CI asserting the
implementation matches it.

**Why this matters:** `docs/verification-service.md` describes the service in
prose. A client generator cannot read prose, and prose drifts from the handler
without anything failing.

_Acceptance criteria_

- The spec covers every endpoint, status code and error shape the service
  actually returns.
- A CI check that fails when the implementation and the spec disagree — a real
  conformance test, not a linter on the YAML.
- A generated client is exercised against the running service in that check.
- `docs/verification-service.md` links the spec rather than restating it.

_Implementation guidance_

- Generate the check from the spec so drift is caught automatically; a
  hand-written parallel test will itself drift.
- The `cannot_check` verdict must be representable — do not let the schema
  flatten it to a boolean.
- Add the spec's path to the relevant workflow's `paths:` filter so editing it
  re-runs the check.

#### feat(integrations): harden the HTTP service for untrusted exposure

Add authentication, request size limits, timeouts, concurrency bounds and
structured request logging to `server/`, and document the threat model it is
then fit for.

**Why this matters:** `server/main.go` is a single file that accepts entries
from anyone who can reach it and decodes them. The decode depth is bounded,
which is the sharpest edge, but there is no auth, no body limit and no timeout —
so it is only safe on a trusted network, and nothing says so.

_Acceptance criteria_

- Body size limit, read and write timeouts, and a bounded concurrent-request
  count, each configurable with a documented default.
- An authentication mechanism, off by default only if the service refuses to
  bind a non-loopback address without it.
- Request logs carry no entry bytes and no secret; a test asserts it.
- `docs/verification-service.md` states the threat model, what is now safe, and
  what is still not.

_Implementation guidance_

- The service verifies rather than signs today — if signing is ever added, the
  auth story becomes mandatory, so design for that now.
- Refusing to start insecurely is better than a warning nobody reads; prefer
  fail-closed defaults.
- An unbounded decode is the classic denial of service here; `MaxDecodeDepth`
  covers depth, so check size and count too.

#### feat(integrations): Prometheus metrics and a reference dashboard

Expose the hook events as Prometheus metrics from the service, and ship a
Grafana dashboard definition for them.

**Why this matters:** `hooks.go` emits the events and `examples/opentelemetry`
shows one consumer, but an operator running the service has nothing to look at.
The signals that matter — refusal rate, signer latency, stale-signature findings
— are exactly the ones that indicate something is wrong.

_Acceptance criteria_

- Metrics for request rate, verdict distribution, refusal reasons and signer
  latency, with documented names and labels.
- No label carries an address, a nonce or anything else unbounded in
  cardinality; a test asserts the label sets are closed.
- A committed dashboard JSON, with a screenshot or export proving it renders
  against real data.
- The metrics endpoint is separable from the API port, so it need not be
  publicly exposed.

_Implementation guidance_

- Build on `hooks.go` rather than instrumenting the handlers separately, so
  there is one event source.
- High-cardinality labels are the usual way a metrics change takes down a
  Prometheus — hence the closed-label-set test.
- The library itself does no logging and should gain no metrics dependency; this
  belongs in the service.

#### feat(integrations): multi-architecture signed container images

Publish the container image for `linux/amd64` and `linux/arm64`, signed and with
an attached SBOM and provenance attestation.

**Why this matters:** Wave 9 publishes a single-architecture image. A consumer
on arm64 — most recent laptops and much of current cloud capacity — cannot run
it, and nothing about the published image is verifiable.

_Acceptance criteria_

- A manifest list covering both architectures, with both actually tested by
  running the CLI in CI.
- Images signed, with the verification command documented so a consumer can
  check rather than trust.
- An SBOM and a build provenance attestation attached to the published image.
- The release workflow does all of this; no step is a documented manual ritual.

_Implementation guidance_

- Reuse the existing release workflow and image build; this extends them rather
  than replacing them.
- Keyless signing avoids a long-lived key in CI — if you choose otherwise, say
  why.
- Document the verification command in the README; a signature nobody can check
  adds nothing.

#### feat(integrations): Homebrew tap and Nix flake for the CLI

Publish the CLI through a Homebrew tap and a Nix flake, both updated by the
release workflow.

**Why this matters:** Installing the CLI means `go install` or downloading a
release binary. The two package managers its likely users already have are the
ones missing, and a hand-updated formula goes stale the first time nobody
remembers.

_Acceptance criteria_

- Both install a working `soroauth` whose `--version` reports the released
  version, verified in CI on macOS and Linux.
- The release workflow updates both automatically, including checksums.
- The flake builds reproducibly and pins its inputs.
- The README's install section covers both.

_Implementation guidance_

- Automation is the point: a formula a human has to remember to bump is the
  thing being fixed.
- The `--version` check in CI is what proves the package actually works, rather
  than merely building.
- Reuse the release workflow's existing checksum generation rather than
  computing them twice.

#### feat(integrations): browser extension that explains an entry before signing

A reference extension that intercepts a signing request, renders the entry's
structure and risk findings, and requires an explicit confirmation.

**Why this matters:** A browser user asked to sign an authorization entry sees
base64. The library already has `Inspect`, the risk analyzer, the tree renderer
and a wasm build — every piece needed to show the user what they are approving,
with nothing assembling them at the point of decision.

_Acceptance criteria_

- Renders arm, address, nonce, expiration, the delegate tree and the invocation
  tree from the wasm core, not a reimplementation.
- Risk findings are shown with the analyzer's documented limits visible, not as
  a safety verdict.
- Works against the existing browser passkey example end to end.
- States plainly that it reports structure and does not interpret what a
  contract call will do.

_Implementation guidance_

- `soroauth-explain` is the project that interprets entries; this is the
  structural view, so link rather than duplicate it.
- A reference extension, not a product: no store listing, no telemetry, no
  update channel.
- `docs/analyzer-heuristics.md` lists what the analyzer misses — the UI must not
  imply more than that.

#### feat(integrations): Node.js native binding over the C ABI

A Node package exposing the signing core natively, for backends that cannot run
the wasm build.

**Why this matters:** `@soroauth/wasm` targets the browser, and a Node backend
pays wasm's startup and copying costs for no benefit. Node is also the most
likely server-side consumer, since the reference implementation these vectors
are proven against is the JS SDK.

_Acceptance criteria_

- Installs from a published package with prebuilt binaries, falling back to a
  source build.
- Every golden vector replayed through the Node API in CI with byte equality
  asserted.
- Prebuilds for Linux and macOS on the supported Node versions, with the matrix
  documented.
- Errors surface as typed exceptions preserving the Go sentinels' distinctions.

_Implementation guidance_

- Depends on the C ABI issue; check its state first and say so on the issue.
- The wasm package stays — this is for Node, not a replacement, and the README
  should say which to use when.
- A binding that can disagree with the Go library is worse than none, so the
  vector replay is the gate.

### `area:protocol`

#### feat(protocol): support CreateContractV2HostFn invocations

Handle `SOROBAN_AUTHORIZED_FUNCTION_TYPE_CREATE_CONTRACT_V2_HOST_FN` everywhere
the library reads an invocation tree: `Inspect`, `Verify`, `DiffEntries`, the
risk analyzer and the tree renderer.

**Why this matters:** `CreateContractV2HostFn` carries constructor arguments,
which a V1 create does not. Today the create arm is handled generically —
`diff.go` byte-compares it rather than reading its fields, and `Inspect` reports
no constructor detail — so an entry that authorizes a contract deployment with
attacker-chosen constructor args looks the same as a harmless one.

_Acceptance criteria_

- `Inspect` reports the wasm hash, salt and constructor argument count for both
  create arms.
- `DiffEntries` reports a changed wasm hash, salt or constructor argument at its
  own path rather than as one opaque difference.
- The risk analyzer treats a create-with-constructor-args as a distinct finding
  from a plain create.
- A golden vector covers a V2 create with at least two constructor arguments,
  generated by the pinned JS SDK.

_Implementation guidance_

- Read the arm's fields from `go-stellar-sdk`'s `xdr` package rather than
  assuming the field names; cite the file you read.
- `diff.go`'s `diffInvocation` has a `default:` branch that byte-compares
  non-contract-fn arms — that is the seam to extend.
- Do not change what is signed. The preimage already covers the whole invocation
  tree; this is reporting only.

#### feat(protocol): helpers for the Stellar Asset Contract admin interface (CAP-46-6)

Add helpers that build and recognise authorization entries for the SAC admin
functions — `set_admin`, `set_authorized`, `clawback`, `mint` — so a caller
signing one knows which it is.

**Why this matters:** SAC admin calls are the highest-consequence authorizations
a classic asset issuer makes, and today they are indistinguishable from any
other `contract_fn` entry. `clawback` and `set_admin` in particular are
irreversible.

_Acceptance criteria_

- A recogniser that, given an entry, reports whether its root invocation is a
  SAC admin call and which one.
- `Inspect` surfaces that classification in a new field, empty for non-SAC
  entries.
- The risk analyzer flags `set_admin` and `clawback` at its highest severity,
  with a test asserting the severity and not merely that something was flagged.
- Recognition is by function name and argument shape, with a test proving a
  same-named function on a non-SAC contract is not misreported.

_Implementation guidance_

- Cite CAP-46-6 for each function's name and argument list; do not work from
  memory.
- A contract address alone cannot prove a contract is a SAC, and claiming
  otherwise offline would be dishonest — report the shape match and say what it
  does not establish.
- `risk.go` already has a severity scheme; reuse it rather than adding a second
  one.

#### feat(protocol): parse simulateTransaction responses into entries and resources

A typed reader that turns a `SimulateTransactionResponse` into the authorization
entries it recorded, the resource footprint, the minimum resource fee, and the
auth mode the host actually used.

**Why this matters:** `rpcflow.SignAndSubmit` does this inline. Every caller who
wants the two-pass flow without that helper's opinions reimplements the parsing,
and the subtle part — which arm the host recorded, and whether `UseUpgradedAuth`
was honoured — is exactly what gets guessed wrong.

_Acceptance criteria_

- Returns the entries, the `SorobanTransactionData`, the minimum resource fee,
  and the observed credential arm per entry.
- Reports whether the response is a recording or enforcing result rather than
  requiring the caller to remember which pass they ran.
- A simulation error, or a response with no auth and no result, is an error
  naming which field was missing — never an empty success.
- Offline tests drive it from committed JSON response fixtures, so the suite
  stays network-free.

_Implementation guidance_

- Live in `rpcflow`, and refactor `SignAndSubmit` onto it so there is one
  parser, not two.
- Capture the fixtures from a real testnet simulation and commit them; say in
  the PR which ledger and RPC version they came from.
- Read `protocols/rpc/simulate_transaction.go` in the pinned SDK for the
  response shape and cite line numbers.

#### feat(protocol): compute the resource-fee delta signatures add

Given an unsigned entry and the signature shape that will fill it, estimate the
increase in XDR size and the resource fee it implies — before the signer is
called.

**Why this matters:** The two-pass simulation requirement exists because
signatures cost resources. A caller who wants to know whether the enforcing pass
will blow a fee ceiling currently finds out only after the signers have
approved, which for a hardware wallet or a multi-party flow is the expensive
moment to discover it.

_Acceptance criteria_

- Reports the byte delta exactly (it is computable: the signature `ScVal`'s
  marshalled length) and the fee delta as a documented function of it.
- Handles the delegates arm, where every node's signature counts.
- Any part of the fee that depends on a network setting the library cannot know
  offline is reported as such rather than guessed.
- A test compares the predicted byte delta against a real signed entry's actual
  size and asserts they agree exactly.

_Implementation guidance_

- Be precise about which half is exact and which is an estimate; a confident
  wrong fee is worse than no fee.
- Cite the fee rule from the protocol or the host rather than deriving it from
  one observation.
- An e2e assertion against a real enforcing-pass fee would make this evidence
  rather than arithmetic.

#### feat(protocol): contract addresses as delegates

Audit and complete support for a `C…` contract address appearing as a delegate
at any depth: ordering, validation, signing, verification and reporting.

**Why this matters:** CAP-71-01 permits a contract as a delegate — that is how a
smart account delegates to another smart account — but every fixture and golden
vector uses `G…` delegates. The ordering comparison, the `cannot_check` path and
the tree renderer are all untested against a contract delegate, so whether they
are correct is currently unknown rather than known.

_Acceptance criteria_

- Golden vectors covering a contract delegate, a contract delegate nested under
  a G-account delegate, and a mixed level that exercises the XDR byte ordering
  between the two address types.
- `VerifyEntry` reports a contract delegate as `cannot_check` with a reason
  naming the contract, never as `unsigned`.
- An e2e scenario on testnet where a smart account delegates to another smart
  account.
- A test asserting the ordering of a mixed `G…`/`C…` level matches what the
  pinned JS SDK produces.

_Implementation guidance_

- `ScAddress` discriminates account before contract, so the byte ordering
  between the two types is decided by the discriminant — prove this with the SDK
  rather than asserting it.
- `e2e/contracts/modular-account` is the natural delegate target; a second
  instance of it can be the delegating account.
- If any current behaviour turns out wrong, that fix is its own commit with the
  evidence that found it.

#### feat(protocol): reconstruct the __check_auth Context a host would pass

Build the `Vec<Context>` an account contract's `__check_auth` receives for a
given entry, so a caller can reason about — and a test can assert — what the
contract will actually see.

**Why this matters:** An account contract's policy is written against the
contexts it is handed, not against the entry. Today the only way to learn what
those contexts are is to deploy the contract and simulate, which makes policy
bugs a testnet-only discovery.

_Acceptance criteria_

- Produces the contexts for a contract-fn root with sub-invocations, and for
  both create arms.
- The mapping from invocation tree to contexts is cited to the protocol or
  `rs-soroban-env`, not inferred from one example.
- An e2e test compares the reconstruction against what a fixture contract
  actually receives, logging both.
- Where the reconstruction cannot be exact offline, it reports that rather than
  returning a plausible guess.

_Implementation guidance_

- This is a correctness claim about host behaviour, so it needs the host source:
  name the file and function.
- A fixture contract that echoes its contexts in a diagnostic event would make
  the e2e comparison direct.
- Fail closed: an invocation shape the mapping does not cover is an error, not a
  partial context list.

#### feat(protocol): golden vectors covering every ScVal argument type

Extend the generator so the invocation arguments in the vector set cover every
`ScVal` type the XDR defines, including the nested and edge-case ones.

**Why this matters:** The vectors prove byte equality against the JS SDK for the
argument types they happen to use. A type nobody put in a vector — `ScvI256`,
`ScvDuration`, a deeply nested map, an empty vec — is untested, and the XDR
encoding of exactly those is where a cross-implementation disagreement would
hide.

_Acceptance criteria_

- A vector whose argument list includes every `ScValType` the pinned SDK can
  construct, with the ones it cannot documented and listed.
- Boundary values for each numeric type: zero, minimum, maximum.
- The differential and parity harnesses pick the new vectors up without changes,
  or the PR explains why they cannot.
- `make vectors-check` stays green, and no committed vector is hand-edited.

_Implementation guidance_

- `testdata/gen/gen.mjs` is the only place these are built; the generator
  refuses any SDK version but the pin.
- Enumerate the types from the XDR definition rather than from memory, and say
  where you read it.
- If a type turns out to disagree across implementations, stop and report it —
  do not adjust a vector to make a test pass.

#### feat(protocol): entries across a multi-operation transaction

Handle a transaction carrying several `invokeHostFunction` operations, each with
its own authorization entries: signing them as one batch, reporting them with
their operation index, and reassembling them in place.

**Why this matters:** `EnvelopeEntries` and `InspectEnvelope` read entries out
of an envelope, but the write path back — signing a whole envelope's worth of
entries and putting each back where it came from — does not exist. A caller with
a two-operation transaction has to do that bookkeeping by hand, and putting an
entry back on the wrong operation produces a transaction that pays fees and
fails.

_Acceptance criteria_

- A function that takes an envelope and signers and returns an envelope with
  every address entry signed, preserving operation and entry order exactly.
- An entry with no applicable signer fails the whole call naming its operation
  and entry index, never a partial envelope.
- A test proving the input envelope's bytes are unchanged, and a test proving a
  round trip through read-and-write with no signers is byte-identical.
- Fee-bump envelopes are read through to the inner transaction, with a test.

_Implementation guidance_

- `envelope.go` already has the read side; this is its counterpart, and the two
  should share one notion of position.
- `txnbuild.Transaction` has no exported fields and `GetInvokeHostFunctionOp()`
  returns a copy — work at the `xdr` level, not through `txnbuild`.
- All-or-nothing, like `AuthorizeAll`: never return a half-signed envelope with
  a non-nil error.

#### feat(protocol): detect and refuse nonce reuse across a batch

Refuse a batch in which two address entries for the same address carry the same
nonce, and surface the check for callers assembling entries from several
sources.

**Why this matters:** The host consumes a nonce per address so an entry cannot
be replayed. Two entries in one transaction sharing an address and a nonce means
the second is rejected during application, after fees — and the failure reads as
an authorization problem rather than the bookkeeping mistake it is.
`noncetracker.go` tracks nonces a caller issued; it does not catch a collision
in a batch assembled from elsewhere.

_Acceptance criteria_

- `AuthorizeAll` refuses such a batch with a sentinel error naming the address,
  both entry indices and the nonce.
- An exported check callable independently of signing, so a caller can validate
  before involving signers.
- The same address with different nonces, and different addresses with the same
  nonce, both pass — with tests for each, since only the first pair is a
  conflict.
- The new sentinel has a test producing it, as
  `TestEverySentinelHasAProducingTest` requires.

_Implementation guidance_

- Cite `verify_and_consume_nonce` for the host's rule rather than describing it
  from memory.
- Check before any signer runs, so a hardware wallet is never asked to approve a
  batch that cannot land.
- Source-account entries carry no nonce and must be skipped, not treated as a
  collision on the zero value.

#### feat(protocol): CAP-85 and Protocol 28 support once the Go SDK ships helpers

Re-audit the library against CAP-85 / Protocol 28 when `go-stellar-sdk` releases
types and helpers for it, and either state that nothing changed or ship the
change with a vector.

**Why this matters:** The README's CAP-85 section currently states, with
evidence, that no change is required against SDK v0.7.3 — and commits to
revisiting it when the SDK ships P28 helpers. That promise is only kept if
someone does the audit.

_Acceptance criteria_

- The audit is recorded: which SDK version, which types are new, and whether any
  touches `SorobanAuthorizationEntry`, `SorobanCredentials`,
  `SorobanDelegateSignature` or the preimage variants.
- If the wire format changed, a golden vector and an e2e scenario land with the
  change.
- If nothing changed, the README section says so explicitly against the new
  version rather than being left stale.
- `docs/sdk-support.md` records the version move under its existing policy.

_Implementation guidance_

- Blocked until the SDK ships P28 helpers — check before starting, and say on
  the issue what you found.
- Every claim here needs the file and line you read in the new SDK, not a
  release note summary.
- If the audit finds nothing, that is a real and useful result; say it plainly.

### `area:signers`

#### feat(signers): Azure Key Vault signer

A `Signer` backed by Azure Key Vault / Managed HSM, in its own Go module under
`adapters/azurekv`, matching the shape the AWS and GCP KMS adapters already set.

**Why this matters:** Azure is the third of the three clouds a backend is likely
to already be on, and its absence is the reason an Azure-hosted service
hand-rolls a signer. The adapter pattern is established; this is filling the gap
in it.

_Acceptance criteria_

- Its own `go.mod`, so the root module gains no Azure dependency.
- Produces the classic-account `ScVal` shape, verified against
  `NewEd25519Signer`'s output for the same key material where the key type
  allows it.
- A typed-nil client is rejected rather than panicking, as `adapters/gcpkms`
  does via its `isNilClient` check.
- Offline tests against a fake client covering success, permission failure and
  context cancellation; no test needs an Azure account.

_Implementation guidance_

- Read `adapters/awskms` and `adapters/gcpkms` first and follow them; three
  adapters that differ in shape is worse than three that match.
- Azure's Ed25519 support varies by tier — state plainly in the doc comment
  which key types are supported and which are refused.
- `ci-adapters.yml` reads each adapter's own `go.mod` for its toolchain; add the
  job the same way.

#### feat(signers): PKCS#11 signer for HSMs and smartcards

A `Signer` speaking PKCS#11, in its own module, covering the YubiKey PIV and
SoftHSM cases.

**Why this matters:** PKCS#11 is the one interface that covers every on-premise
HSM and most smartcards at once, so a single adapter replaces a long tail of
vendor-specific ones. It is also the only option for an operator who cannot use
a cloud KMS.

_Acceptance criteria_

- Its own module; the root module gains no CGO dependency.
- Session and PIN handling documented, with the PIN never accepted as a struct
  literal that could end up in a log — and a test asserting no error message
  contains it.
- Tests run against SoftHSM in CI so the path is exercised without hardware.
- A documented list of what was actually tested on real hardware, and what was
  not.

_Implementation guidance_

- CGO is the reason this cannot live in the root module; say so in the doc
  comment.
- Follow `docs/signers.md`'s threat-model framing and add this signer to its
  table.
- Do not claim hardware support you have not run; `docs/signers.md` is explicit
  about evidence per signer.

#### feat(signers): Trezor hardware wallet signer

A `Signer` for Trezor devices, alongside the existing Ledger adapter, including
the device-confirmation flow and its failure modes.

**Why this matters:** Ledger shipped in Wave 9 and Trezor is the other device a
Stellar user is likely to hold. Without it, Trezor users are the one hardware
cohort with no path through this library.

_Acceptance criteria_

- Device rejection, timeout and disconnection are distinct errors, not one
  opaque failure.
- The preimage is passed to the device so the user confirms what they are
  approving, not a bare hash.
- Offline tests against a fake transport cover each failure mode; a documented
  manual run against real hardware records firmware version and what was
  confirmed on screen.
- `docs/signers.md` gains a row stating the evidence for this signer honestly.

_Implementation guidance_

- Read the Ledger adapter first and match its ergonomics and error taxonomy.
- `Signer.Sign` receives both preimage and payload precisely so a device signer
  can show the user the real thing — use it.
- A hardware signer must never be asked to confirm something that will be
  discarded; the pre-sign guards in `authorize.go` already ensure this, so do
  not bypass them.

#### feat(signers): batched user presence for passkey and hardware signers

Let one user confirmation cover several entries, where the signer and the
payload set allow it, instead of one prompt per entry.

**Why this matters:** A delegate tree or a multi-operation transaction needs
several signatures. With a hardware or passkey signer that is one prompt each,
which users click through without reading — the prompt stops being a security
control precisely when there are most of them.

_Acceptance criteria_

- An API that presents the full set of payloads for one confirmation and then
  produces every signature.
- Refuses to batch across differing addresses or expirations unless the caller
  explicitly opts in, since those are different authorizations.
- A test proving the batched result is byte-identical to signing each entry
  individually.
- The doc comment states what the user is actually confirming, and what is lost
  compared with per-entry prompts.

_Implementation guidance_

- The honesty question matters more than the ergonomics: one prompt for twenty
  payloads must not read as one authorization.
- `batch_sign.go` is the existing batch path; extend it rather than adding a
  parallel one.
- Not every signer can do this — make it an optional interface a signer may
  implement, with a documented fallback.

#### feat(signers): key rotation and versioned signer identity

Support a signer whose underlying key can change — a rotated KMS key version —
while the account address stays the same, including which version signed a given
entry.

**Why this matters:** Every KMS adapter signs with whatever version the key
alias currently points at. After a rotation, an entry signed before it and an
entry signed after are indistinguishable, so an operator investigating a bad
signature cannot tell which key produced it.

_Acceptance criteria_

- A signer may report the key version it used, and that version reaches the
  audit record and the hook events.
- A rotation mid-batch is detected and refused rather than producing a batch
  signed by two keys without saying so.
- Tests against a fake KMS covering rotation between two calls.
- `docs/signers.md` states what rotation means for entries already signed and
  not yet submitted.

_Implementation guidance_

- `Signer.Address()` is the account identity and must not change on rotation —
  the version is extra, not a replacement.
- For a classic account the public key is in the signature itself, so a rotation
  that changes it changes who can authorize: state that consequence plainly.
- Coordinate with the audit-record issue so there is one notion of key version,
  not two.

#### feat(signers): rate-limited and quota-aware signer wrapper

A decorator that bounds how often a wrapped signer is called, with the limit,
the wait behaviour and the refusal all explicit.

**Why this matters:** A cloud KMS bills per operation and throttles; a
compromised service that can call a signer without bound can drain a quota or
sign an unbounded number of authorizations before anyone notices. Rate limiting
is a containment control and there is nowhere to put it today.

_Acceptance criteria_

- A documented limiter whose refusal is a distinct error a caller can match on,
  not a generic failure.
- Context cancellation and deadline are honoured while waiting, with a test
  asserting the wrapped signer was not called.
- Concurrency-safe, with a `-race` test driving it from several goroutines.
- Composes with the retry wrapper from Wave 9 in both orders, with the
  recommended order documented and justified.

_Implementation guidance_

- Follow the existing retry/backoff wrapper's shape so the decorators are
  recognisably a family.
- No `math/rand`: if jitter is wanted, use `crypto/rand`, per the repo's coding
  standards.
- Waiting silently is the wrong default for a signing path — make blocking
  versus refusing an explicit choice.

#### feat(signers): policy-enforcing signer wrapper

A decorator that inspects what it is about to sign and refuses if it violates
caller-supplied rules — contract allowlist, maximum amount argument, forbidden
SAC admin calls.

**Why this matters:** The last place a bad authorization can be stopped is the
signer, and it is the only place that sees every one. `SignerFunc` lets a caller
write this by hand against raw XDR, which is the error-prone way to do a
security check.

_Acceptance criteria_

- Rules evaluated against the decoded invocation tree, not the raw bytes, and
  reusing the risk analyzer where it already answers the question.
- A refusal names the rule and the offending node; it is a distinct error type.
- Fails closed: a tree the rules cannot evaluate is refused, not allowed, with a
  test proving it.
- A test proving the wrapped signer is never invoked on a refusal.

_Implementation guidance_

- `risk.go` already classifies entries — build on it so there is one set of
  heuristics with one set of documented limits.
- `docs/analyzer-heuristics.md` states what the analyzer misses; the wrapper's
  doc comment must inherit those caveats rather than implying completeness.
- An allowlist is a real control; an amount check on an arbitrary ScVal argument
  is heuristic. Do not present the second as the first.

#### feat(signers): Turnkey signer

A `Signer` backed by Turnkey's signing API, in its own module.

**Why this matters:** Turnkey is a key-management service several Stellar wallet
teams already use, and its policy engine pairs naturally with the authorization
entries this library builds. Today those teams write a bespoke `SignerFunc`.

_Acceptance criteria_

- Its own module; no root-module dependency.
- Request signing and credential handling follow the vendor's documented scheme,
  cited.
- Offline tests against a recorded HTTP transport covering success, a policy
  denial and cancellation.
- A policy denial from the service is a distinct, matchable error, since it is
  an expected outcome rather than a fault.

_Implementation guidance_

- `remote/` already defines a signing protocol and reference server — if the
  vendor's API maps onto it, reuse rather than duplicate.
- Never commit a credential or a recorded response containing one; scrub the
  fixtures and say in the PR how.
- State in the doc comment what is proven by test and what was only run by hand.

#### feat(signers): Fireblocks signer

A `Signer` backed by Fireblocks' raw-signing API, in its own module, including
the asynchronous approval flow.

**Why this matters:** Fireblocks is the custody platform institutional Stellar
holders use, and its signing is asynchronous with human approval — a flow the
current `Signer` interface has never been exercised against. Supporting it tests
whether the interface is actually sufficient.

_Acceptance criteria_

- The asynchronous approval is handled within the `Signer` contract, or the PR
  states precisely why the interface is insufficient and what minimal change it
  needs.
- Long waits are bounded by the context, with a test asserting cancellation does
  not leak a goroutine.
- Offline tests against a recorded transport covering approval, rejection and
  timeout.
- A rejection by a human approver is a distinct error, not a timeout.

_Implementation guidance_

- If the interface genuinely does not fit, say so on the issue before building a
  workaround — that finding is more valuable than the adapter.
- `feat(signers): cancellation and deadline semantics audit` from Wave 9 set the
  rules here; read it and comply.
- Scrub every recorded fixture of credentials and account identifiers.

#### feat(signers): threshold signing with real key shares

Complete the threshold/MPC signer interface from Wave 9 with a working Ed25519
threshold implementation, or document with evidence why it cannot be done safely
in-repo.

**Why this matters:** Wave 9 shipped the interface; nothing implements it, so
whether the interface is right is unknown. An unimplemented interface in a
signing library is a liability — it reads as a supported capability.

_Acceptance criteria_

- Either a working implementation with test vectors, or a written finding
  explaining what blocks it and what the interface should become.
- If implemented: the aggregated signature verifies under the standard Ed25519
  verifier, asserted against `NewEd25519Signer` output for a reconstructed key.
- If implemented: the share-handling threat model is stated, including what this
  does not protect against.
- If not implemented: the interface is either removed or clearly marked as
  unimplemented, so it cannot be mistaken for a shipped feature.

_Implementation guidance_

- Rolling threshold cryptography by hand is the wrong answer. Use a reviewed
  library or report that none fits, with evidence.
- This repo is unaudited and says so; a cryptographic primitive added here
  inherits that and the docs must not overclaim.
- Classic Stellar multisig already solves many real cases — `AccountMultiSigner`
  exists, so say where threshold signing adds something it does not.

#### feat(signers): conformance test suite every signer must pass

An exported suite that takes a `Signer` and asserts the contract: address
stability, context handling, determinism where applicable, no mutation of
inputs, and correct behaviour on refusal.

**Why this matters:** There are now a dozen signer implementations across
several modules, each tested its own way. The `Signer` contract is stated in
prose in `signer.go` and nowhere enforced, so a new adapter can satisfy the
compiler and violate the contract.

_Acceptance criteria_

- The suite is importable by the adapter modules and run by each of their test
  suites.
- Covers: `Address()` is stable across calls, a cancelled context is honoured
  without signing, the preimage argument is not mutated, and a failure returns
  no partial `ScVal`.
- Every shipped signer passes, and the PR reports any that did not before being
  fixed.
- The suite fails loudly if handed a nil signer, rather than passing vacuously.

_Implementation guidance_

- Model it on how `errors_meta_test.go` turns a prose rule into a check that
  bites.
- A conformance suite that no implementation fails is either perfect or not
  checking anything — report what it caught.
- Deterministic signers and interactive ones differ; let the suite be told which
  contract applies rather than assuming.

#### feat(signers): signer that proves possession before use

A startup check that a configured signer actually controls the address it
claims, by signing and verifying a throwaway payload before the service accepts
traffic.

**Why this matters:** A misconfigured KMS key alias or a wrong account address
produces a service that starts cleanly and fails every submission on-chain,
after fees. The mismatch is cheap to detect at startup and expensive to detect
in production.

_Acceptance criteria_

- A check that signs a payload which cannot be a real authorization, and
  verifies the result against the claimed address.
- For a custom account where the library cannot verify offline, it reports
  `cannot_check` rather than passing — the distinction `VerifyEntry` already
  draws.
- `soroauth doctor` runs it when a signer is configured.
- A test proving a signer whose address does not match its key is caught.

_Implementation guidance_

- The throwaway payload must be unmistakably not an entry preimage; say in the
  doc comment why it cannot be replayed as one.
- `doctor.go` is the natural home for the operator-facing half.
- A pass here proves key control, not that the key is a signer of the account
  on-chain — state that limit.

#### feat(signers): WebAuthn attestation verification for passkey enrolment

Verify the attestation object produced when a passkey is created, so a wallet
can check what authenticator a key came from before enrolling it as a signer.

**Why this matters:** `webauthn.go` parses assertions — the signing step.
Enrolment is the other half, and it is where a wallet decides to trust a key at
all. Without attestation checking, any claimed public key can be enrolled.

_Acceptance criteria_

- Parses the attestation object and verifies the statement for at least the
  `packed` and `none` formats, with unsupported formats refused rather than
  skipped.
- Reports the authenticator AAGUID and whether the key is hardware-backed,
  clearly separating what was proven from what was merely asserted by the
  client.
- Test vectors from a real authenticator or an established test library,
  committed, with their origin recorded.
- A tampered attestation is rejected, with a test for each field that matters.

_Implementation guidance_

- Cite the WebAuthn specification section for each check; this is a security
  verification and memory is not a source.
- `none` attestation proves nothing about the authenticator — report it as such
  rather than as a weak pass.
- Coordinate with `docs/passkeys.md` so enrolment and signing are described as
  one flow.

#### feat(signers): signer chain with explicit fallback and quorum

Combine several signers for one address under a declared rule — first that
succeeds, or N of M must agree — with the rule and its failure modes explicit.

**Why this matters:** An operator with a primary KMS and a backup HSM currently
writes the failover by hand, and the dangerous version is easy to write: fall
through on any error, including a policy refusal that was meant to stop the
signing.

_Acceptance criteria_

- A policy refusal is never treated as a transient failure to fall through from;
  a test proves it stops the chain.
- For the quorum rule, disagreeing signatures are a refusal naming the signers,
  not a silent pick.
- Every attempt reaches the audit record, including the ones that were skipped
  and why.
- Context cancellation stops the chain immediately, with a test asserting no
  later signer was called.

_Implementation guidance_

- The error taxonomy is the hard part: fallback is only safe when transient and
  terminal failures are distinguishable, so define that distinction first.
- For a classic account, two different keys produce different signatures — a
  quorum here is not the same thing as `AccountMultiSigner`, so say which
  problem it solves.
- Fail closed: an error the chain cannot classify is terminal.

### `area:testing`

#### test: mutation testing over the signing path

Run a mutation tester over `preimage.go`, `authorize.go`, `delegates.go` and
`diff.go`, and either kill every surviving mutant or record why it survives.

**Why this matters:** Coverage says these lines ran. It does not say a test
would notice if they were wrong. For a library whose output moves money, the
question that matters is whether a changed comparison or a flipped boundary is
caught — and the only way to know is to change one and see.

_Acceptance criteria_

- A documented, reproducible way to run it locally, with a committed
  configuration.
- Every surviving mutant is either killed by a new test or recorded with the
  reason it is equivalent or unreachable.
- A report committed with the run's date, tool version and score.
- At least one real test gap found and fixed, or a statement with evidence that
  none was.

_Implementation guidance_

- Scope to the signing path first; mutation testing the whole repo will drown
  the signal.
- Keep it out of required CI until the survivor list is empty — a noisy gate
  gets ignored.
- A surviving mutant in the preimage builder is a finding worth its own commit,
  not a line in a report.

#### test: fuzz DiffEntries against entry pairs

A fuzz target feeding two decoded entries into `DiffEntries`, asserting its
invariants rather than only that it does not panic.

**Why this matters:** `DiffEntries` landed with table tests. It walks two
untrusted trees at once and makes a claim — `PayloadChanged` — that other code
will act on, and nothing currently generates adversarial pairs.

_Acceptance criteria_

- Invariants asserted: a diff of an entry against itself is `Identical` with no
  changes; `PayloadChanged` is false whenever every preimage-derived field is
  equal; `StaleSignatures` is empty when `PayloadChanged` is false.
- `PayloadChanged` is cross-checked against `Preimage`/`Payload` on both
  entries, so the fuzzer tests the claim and not the implementation's opinion of
  itself.
- Seed corpus built from the golden vectors and their tampered variants, in
  `testdata/fuzz/`.
- Wired into the continuous fuzzing workflow alongside the existing targets.

_Implementation guidance_

- The payload cross-check is the valuable assertion — a fuzzer that only checks
  for panics would have missed every bug found while building the feature.
- `cmd/gencorpus` already emits Go corpus format; extend it rather than
  hand-writing seeds.
- Source-account entries have no payload; the invariant has to account for that
  rather than skipping them.

#### test: fuzz VerifyEntry

A fuzz target over `VerifyEntry`, asserting that it never reports `verified` for
a signature that does not verify, and never panics on a malformed signature
`ScVal`.

**Why this matters:** `VerifyEntry` decides whether a signature is good, and a
false `verified` is the worst output this library can produce. Its tests use
well-formed signatures; the inputs that would break it are the malformed ones.

_Acceptance criteria_

- A `verified` verdict is independently re-checked with `crypto/ed25519` in the
  target, so the verdict is validated and not assumed.
- Malformed, truncated and wrong-type signature values produce a verdict, never
  a panic.
- A node addressed to a contract is always `cannot_check`, asserted as an
  invariant.
- Seed corpus from the vectors plus deliberately corrupted variants; wired into
  continuous fuzzing.

_Implementation guidance_

- Independent re-verification is what makes this evidence rather than a
  tautology.
- `docs/verification-limits.md` states the guarantees — the invariants should be
  exactly those, so a drift in either is caught.
- Any crash found becomes a committed regression seed, per `docs/fuzzing.md`.

#### test: property tests for the delegate tree invariants

Generate random delegate trees and assert the invariants `WithDelegates` and
`ValidateDelegateOrder` promise, at every depth.

**Why this matters:** The ordering rule is the one place a wrong answer is
rejected by the host before the account contract runs, and the current tests use
a handful of hand-built trees. The interesting cases — deep nesting, the same
address at several levels, mixed address types, adjacent addresses that differ
in one byte — are not among them.

_Acceptance criteria_

- Generated trees are always sorted at every level after `WithDelegates`, and
  always pass `ValidateDelegateOrder`.
- A duplicate within a level is always rejected; the same address at different
  levels is always accepted.
- Sorting is idempotent, and the result is independent of input order — asserted
  over generated permutations.
- Deterministic seeded subset in CI, per the repo's existing property-test
  convention.

_Implementation guidance_

- `gopter` is already a dependency and the repo has a documented property-test
  convention — follow it.
- Generate adjacent-by-one-byte addresses deliberately; a comparison bug hides
  there and nowhere else.
- Cap generated depth below `MaxDecodeDepth` so a refusal is not mistaken for a
  failure.

#### test(e2e): expired signature is rejected on-chain

A live scenario submitting an entry whose `signatureExpirationLedger` has
passed, asserting the specific host error.

**Why this matters:** The expiration bound's inclusivity is documented from the
host source and asserted in unit tests, and never checked against a real
network. It is also the rule most likely to be off by one, because the JS SDK
documents it the other way round.

_Acceptance criteria_

- Submits at a ledger past the expiration and asserts the specific rejection,
  not merely that the transaction failed.
- A companion submission at exactly the expiration ledger succeeds, which is
  what proves the bound is inclusive.
- The raw host error is logged verbatim in `e2e/RESULTS.md`.
- The scenario skips cleanly rather than failing if the ledger cannot be hit
  precisely, and says so.

_Implementation guidance_

- `CONTRIBUTING.md` is explicit that a rejection test asserting only 'it failed'
  passes for the wrong reason — assert which failure.
- Hitting an exact ledger is timing-sensitive; poll `getLatestLedger` rather
  than assuming a rate.
- The boundary pass is the harder and more valuable half; do not ship only the
  failure case.

#### test(e2e): nonce replay is rejected on-chain

Submit a valid entry, then submit a second transaction reusing the same address
and nonce, asserting the host's rejection.

**Why this matters:** The nonce exists so an entry cannot be replayed, and that
claim is currently sourced from reading the host rather than from observing it.
It is also the claim the new batch-collision check is built on, so it ought to
be grounded.

_Acceptance criteria_

- The first submission succeeds and is confirmed in a ledger; the second is
  rejected with the specific nonce error, logged verbatim.
- A control submission with a fresh nonce succeeds afterwards, proving the
  account is not simply broken.
- Both transaction hashes recorded in `e2e/RESULTS.md` with explorer links.
- The scenario is independent of other scenarios' accounts, so it cannot be
  poisoned by them.

_Implementation guidance_

- The enforcing pass will catch this locally, so the scenario has to skip it
  deliberately — `e2e/README.md` documents how the existing rejection scenarios
  do that.
- Use a freshly funded account so the nonce state is known.
- Report the raw error; a paraphrase is not evidence.

#### test(e2e): multisig threshold not met is rejected on-chain

A scenario where an account requiring two signers is given one, asserting the
host rejects it.

**Why this matters:** Scenario C proves `AccountMultiSigner` is accepted when
the threshold is met. The complementary case — that one signature on a
two-of-two account is actually refused — is what proves the threshold is doing
anything, and it is untested.

_Acceptance criteria_

- The same account and thresholds as the passing scenario, differing only in the
  signatures supplied.
- Asserts the specific host error rather than a generic failure.
- The raw error is recorded in `e2e/RESULTS.md`.
- Shares the account setup with the passing scenario so the two cannot drift
  apart.

_Implementation guidance_

- `refactor(e2e): reduce duplication across scenario runners` from Wave 9 built
  the shared harness — use it.
- Assert which failure, not that something failed; an instruction-budget
  exhaustion would otherwise pass as a success.
- The contrast with the passing scenario is the evidence, so run both in the
  same session.

#### test(e2e): three-level nested delegate tree on testnet

A live scenario with delegates nested three levels deep, every node signed,
submitted and confirmed.

**Why this matters:** CAP-71-01 allows arbitrary nesting and the deepest tree
ever submitted from this repo is one level. Whether the host walks a deeper tree
the way the library assumes is an assumption, not a result.

_Acceptance criteria_

- A real three-level tree deployed and submitted, with the hash and ledger
  recorded.
- The submitted envelope is decoded back and the observed tree shape logged,
  rather than assumed from what was built.
- The per-node signatures are confirmed to be over the same payload, which is
  the CAP's central claim.
- `e2e/RESULTS.md` records the run with explorer links.

_Implementation guidance_

- `e2e/contracts/modular-account` delegates to addresses it stores; chaining
  instances gives the depth.
- Two simulation passes are required, per CAP-71-01 — the record-sign-enforce
  flow is not optional here.
- If the host behaves differently from the library's assumption, stop and report
  it; that is the most valuable possible outcome.

#### test: cross-version compatibility of entries and vectors

Assert that entries and vectors produced by an earlier release of this library
still verify and still diff correctly against the current code.

**Why this matters:** Entries are pre-signed and stored. If a future change
alters how one is read, an entry signed last month stops verifying, and nothing
in CI would notice — the vectors are regenerated alongside the code, so they
move together.

_Acceptance criteria_

- A frozen set of entries from the `v0.1.0` tag, committed separately from the
  regenerated vectors.
- A test asserting each still verifies and inspects as it did, with the expected
  results committed.
- The frozen set is explicitly never regenerated, and a check prevents it being
  rewritten by `make vectors`.
- A documented process for adding a frozen set at each release.

_Implementation guidance_

- The whole value is that this set does not move with the code — keep it well
  away from `testdata/vectors`.
- `test: version the golden vector schema` from Wave 9 is related; read it so
  the two schemes agree.
- If a frozen entry ever stops verifying, that is a wire-format regression and
  must stop the build.

#### test: per-package coverage floors with a documented rationale

Replace the single repository coverage floor with per-package floors, set from
current measured values and justified per package.

**Why this matters:** One global floor lets a well-covered package subsidise a
thin one. The packages where coverage matters most — the root signing path — are
averaged together with the CLI and the examples, so a real regression in the
former can hide behind the latter.

_Acceptance criteria_

- A committed per-package floor table with the measured current value and a
  one-line reason for each.
- CI fails naming the package and both numbers when one drops.
- The signing-path packages carry a strictly higher floor than the rest, stated
  as policy.
- A deliberate drop proves the gate bites, shown in the PR and not committed.

_Implementation guidance_

- Set floors from measurement, not aspiration; a floor nobody can meet gets
  raised away.
- Coverage is not correctness — say so in the policy, and point at the
  mutation-testing work as the stronger check.
- Packages with no tests by design (examples) should be excluded explicitly, not
  given a floor of zero.

#### test: soak test for the batch signing path

A long-running test signing large batches continuously, watching for leaked
goroutines, unbounded memory and pool corruption.

**Why this matters:** `internal/xdrcopy` shares encoder and decoder buffers
through `sync.Pool`, and `batch_sign.go` runs concurrently. The race detector
covers correctness under contention for the duration of a test; it says nothing
about what happens over hours, which is how the service actually runs.

_Acceptance criteria_

- Runs under a build tag or long flag so it never slows the normal suite.
- Asserts goroutine count and heap in use return to a baseline after each round,
  with the tolerance justified.
- Output bytes are checked against the golden vectors throughout, so corruption
  is caught and not merely leakage.
- Scheduled in CI alongside the existing long-running jobs, with a committed
  report from a real run.

_Implementation guidance_

- A pooled buffer handed to two callers is the failure this is looking for —
  asserting bytes, not just memory, is what would catch it.
- `TestCopyConcurrentReuse` exists for the short version; this is the long one,
  not a replacement.
- Report the real numbers from a real run; a soak test nobody has run is not
  evidence.

#### test: adversarial corpus of malformed entries

A committed corpus of deliberately hostile entries — depth bombs, huge argument
lists, non-canonical strkeys, truncated XDR, inconsistent unions — with the
expected refusal for each.

**Why this matters:** Every public entry point decodes input from elsewhere. The
decode bound and the strkey check were each added in response to a specific
concern; there is no single place that asserts the whole family is handled, so
the next entry point added inherits none of that hardening by default.

_Acceptance criteria_

- Each case names the expected sentinel error, so the test asserts which refusal
  and not merely that one happened.
- Every public entry point that takes an entry — `Inspect`, `Verify`,
  `DiffEntries`, `AuthorizeEntry`, `Decode*`, the CLI, the service — is run
  against the whole corpus.
- A test that fails when a new public entry point is not covered, rather than a
  comment asking people to remember.
- No case causes a panic, a hang, or unbounded allocation.

_Implementation guidance_

- Reuse the frozen divergence corpus in `testdata/differential/regressions` for
  cases already known; do not duplicate them.
- The coverage check over entry points is what keeps this from going stale —
  model it on `errors_meta_test.go`.
- A case that currently is not refused is a finding: report it before fixing it.

#### test: assert the wasm core and the Go library agree exhaustively

Extend the wasm parity check from replaying the golden vectors to replaying the
fuzz and differential corpora.

**Why this matters:** `make wasm-check` replays the vectors through the wasm
core, which proves agreement on the cases someone thought of. The wasm build is
a second compilation of the same code under a different toolchain and a
different integer and memory model, so the cases that would diverge are the
generated ones.

_Acceptance criteria_

- The differential and fuzz corpora replayed through the wasm core with byte
  equality asserted.
- Any divergence is frozen as a regression case, per the existing convention.
- Runs in the wasm CI job within a stated time budget.
- A report of how many cases are covered, before and after.

_Implementation guidance_

- `wasm/parity.mjs` is the existing harness; extend it rather than writing a
  second one.
- `js/wasm` differs from native in number handling — the int64 nonce boundaries
  are the first place to look.
- `docs/parity.md` frames what agreement proves; keep that framing.

#### test: benchmark regression gate per credential arm

Extend the signing-path budget check from one aggregate number to a per-arm,
per-operation budget with its own threshold.

**Why this matters:** `scripts/checkbench` gates the signing path against a
budget. One number means a regression in the delegates arm can be masked by an
improvement in the legacy arm, and the delegates arm is the one that scales with
tree size.

_Acceptance criteria_

- Separate budgets per arm for signing, verification and diffing, with committed
  baselines and justified thresholds.
- Failure names the arm, the operation, the baseline and the measured value.
- A delegate-tree benchmark parameterised by node count, so super-linear growth
  is visible.
- A deliberate regression proves the gate bites, shown in the PR and not
  committed.

_Implementation guidance_

- `scripts/checkbench` and the existing budget job are the starting point; do
  not add a parallel mechanism.
- Set thresholds from repeated runs on the CI runner, not from one local
  measurement — noise is the reason these gates get disabled.
- No floats in library code; this is tooling, so the constraint does not bind,
  but keep the comparison integer-based where you can.

#### test: golden vectors at every structural boundary

Vectors at the structural limits: maximum delegate nesting, maximum signatures
on a multisig account, an empty argument list, a single-node tree, and the
widest tree the generator can build.

**Why this matters:** Wave 9 added expiration boundary vectors. The structural
boundaries got no equivalent treatment, and the host enforces limits there too —
`MAX_ACCOUNT_SIGNATURES` is 20, and the library's own `MaxDecodeDepth` is 64.

_Acceptance criteria_

- A vector at exactly 20 account signatures, and a unit test proving 21 is
  refused with `ErrTooManySignatures`.
- A vector at the deepest nesting the pinned JS SDK will produce, with the depth
  recorded in the vector's name.
- Vectors for an empty argument list and a single-delegate tree.
- All generated, none hand-edited, and `make vectors-check` green.

_Implementation guidance_

- Cite the host constant for the signature cap rather than trusting the number
  in this description.
- If the JS SDK refuses a depth the Go library accepts, that disagreement is the
  finding — report it, do not paper over it.
- Keep vector names descriptive of the boundary, since that is how the next
  person finds them.

#### test: reproducible e2e runs against a local Stellar quickstart

Let the e2e suite run against a local quickstart container as well as testnet,
so the scenarios are reproducible offline and in CI without friendbot.

**Why this matters:** Every e2e scenario needs testnet and friendbot, which
makes them slow, rate-limited, and unavailable when testnet is unhealthy. A
contributor who cannot run them does not run them, and reviews the delegate
scenarios by reading.

_Acceptance criteria_

- The suite selects network by configuration, with the same scenarios passing
  against both.
- Account funding works without friendbot in the local case.
- `make e2e-local` or equivalent documented, from a clean checkout.
- A run against both recorded, with the protocol version each reported.

_Implementation guidance_

- `SOROAUTH_RPC_URL` already exists and the suite verifies the endpoint with a
  live call — extend that rather than branching on a flag everywhere.
- A local network may run a different protocol version; report it rather than
  assuming parity with testnet.
- Testnet remains the evidence of record for `RESULTS.md`; local is for
  iteration. Say which is which.

### `area:tooling`

#### feat(cmd): soroauth simulate

A subcommand that runs the record pass against an RPC endpoint and prints the
returned entries, resources and minimum fee.

**Why this matters:** The CLI can sign, inspect, verify and diff an entry but
cannot obtain one. Getting an unsigned entry means writing a Go program or
hand-driving curl, which puts the CLI's whole workflow out of reach of someone
exploring.

_Acceptance criteria_

- Takes a transaction envelope, runs the record pass, prints each entry as
  base64 with its operation and entry index.
- Reports the arm the host actually recorded, decoded from the response rather
  than assumed.
- `--json` output composes with the other subcommands, as the existing `--json`
  contract requires.
- A simulation error is reported with the host's message and a non-zero exit
  code.

_Implementation guidance_

- The parsing belongs in `rpcflow`; this subcommand should be a thin front end
  to it.
- Tests must not touch the network — drive them from committed response
  fixtures.
- `--rpc-url` and `$SOROAUTH_RPC_URL` already exist on other subcommands; follow
  that convention exactly.

#### feat(cmd): soroauth submit

A subcommand that runs the enforcing pass with signed entries, assembles,
submits and polls to completion.

**Why this matters:** With `simulate` and `sign` present, submission is the
missing step that turns the CLI from a decoder into something that completes the
flow — and the two-pass requirement is exactly what people get wrong by hand.

_Acceptance criteria_

- Runs the enforcing pass with the signed entries, so the submitted fee covers
  the signatures.
- Prints the transaction hash before polling, so a timeout still leaves the user
  something to look up.
- Polls to a terminal state and exits non-zero on failure, reporting the host's
  error verbatim.
- Refuses to submit if an address entry is unsigned, unless explicitly
  overridden.

_Implementation guidance_

- `rpcflow.SignAndSubmit` already implements this flow — reuse it rather than
  writing a second one.
- The envelope signing key must come from an environment variable, never a flag,
  like `sign`.
- Printing the hash before polling matters: that is the difference between a
  recoverable and an unrecoverable timeout.

#### feat(cmd): batch mode reading many entries from a file

Let the entry-taking subcommands read a newline-delimited or JSON list of
entries and emit one result per input.

**Why this matters:** Every subcommand takes exactly one entry, so processing a
batch means a shell loop that starts a process per entry and, worse, usually
drops the error from one iteration.

_Acceptance criteria_

- Supported by `inspect`, `verify`, `diff` and `sign`, with one consistent input
  and output format.
- A per-entry failure is reported with its index and does not silently end the
  run; the exit code reflects that something failed.
- `--json` emits one array or one object per line, documented, so it composes
  with `jq`.
- The all-or-nothing rule is honoured for `sign`: a batch that cannot be fully
  signed produces no signed output.

_Implementation guidance_

- `AuthorizeAll` already defines the all-or-nothing semantics for signing — the
  CLI must not loosen them.
- Choose one streaming format and document it; two half-supported formats is
  worse than one.
- Never echo an entry into an error message, per the CLI's existing rule.

#### feat(cmd): configuration file for the CLI

Let the CLI read defaults — network, RPC URL, secret variable name, output
format — from a config file, with a documented precedence order.

**Why this matters:** Every invocation repeats `--network` and `--rpc-url`.
Repetition invites shell aliases and history, and history is where a mistyped
network silently becomes the default.

_Acceptance criteria_

- Documented precedence: flag, then environment, then file, then built-in
  default.
- `soroauth doctor` reports which file was loaded and which value came from
  where.
- No secret value may be stored in the file; only the name of an environment
  variable, with a test asserting a secret-shaped value is refused.
- A missing file is not an error; an unparseable one is.

_Implementation guidance_

- Standard library only, per the CLI's constraint — choose a format the standard
  library can parse.
- Refusing to hold secrets is the security-relevant decision; make it explicit
  and tested rather than documented.
- `doctor` reporting the resolved source is what makes a precedence bug
  findable.

#### feat(cmd): exec-based external signer

Let `soroauth sign` delegate to an external program over a documented protocol
on stdin and stdout, so any signer can be used without a Go dependency.

**Why this matters:** The CLI can sign with a seed from the environment and
nothing else. Every KMS, HSM and hardware signer in the repo is unreachable from
the command line, which is where someone would most want to try one.

_Acceptance criteria_

- A documented protocol passing the preimage and payload and receiving the
  signature `ScVal`.
- The signature is validated as well-formed before being written into the entry;
  a malformed response is an error naming what was wrong.
- The helper's non-zero exit, timeout and malformed output are three distinct
  errors.
- No secret is passed to the helper on the command line or in the environment by
  this mechanism.

_Implementation guidance_

- `remote/protocol.go` already defines a signing protocol over HTTP — reuse its
  message shapes so there is one contract in two transports.
- Passing the preimage, not just the payload, is what lets the helper show a
  user what they are approving.
- Validate the returned `ScVal` — the CLI must not write arbitrary bytes into an
  entry because a helper said so.

#### ci: SLSA build provenance and signed release artifacts

Generate build provenance for every released artifact, sign them, and document
how a consumer verifies both.

**Why this matters:** The release workflow publishes binaries and a container
image. Nothing about them is verifiable, so a consumer cannot distinguish a real
release from a convincing one — which for a library that produces signatures is
the supply-chain risk that matters.

_Acceptance criteria_

- Provenance attestations generated in the release workflow for every artifact.
- Artifacts signed, with verification commands documented in the README and
  actually run in CI.
- An SBOM published per release.
- A deliberately tampered artifact fails verification, demonstrated in the PR.

_Implementation guidance_

- Keyless signing keeps a long-lived key out of CI; if you choose a key, justify
  it.
- The demonstration that verification rejects a tampered artifact is the
  evidence — without it this is configuration nobody has tested.
- Coordinate with the multi-arch image issue so the image and the binaries are
  covered by one scheme.

#### ci: reproducible builds with a verification job

Make the released binaries byte-reproducible from a tagged source tree, and add
a job that rebuilds and compares.

**Why this matters:** Provenance says who built an artifact. Reproducibility
lets anyone check what was built. For a signing library the two together are
what make a release auditable by someone who does not trust the CI.

_Acceptance criteria_

- Documented build command producing byte-identical binaries for each target
  from a clean checkout.
- A CI job rebuilding the latest release and comparing checksums, failing on any
  difference.
- Every source of non-determinism — paths, timestamps, build IDs — identified
  and neutralised, and the list documented.
- Instructions a third party can follow to reproduce, verified by someone other
  than the author.

_Implementation guidance_

- `-trimpath` and a pinned toolchain are the start; module cache state and VCS
  stamping are the usual remaining culprits.
- The CLI embeds version, commit and Go version — make sure that stamping is
  deterministic given the same inputs.
- If a target cannot be made reproducible, say which and why rather than quietly
  excluding it.

#### ci: CodeQL and dependency review on pull requests

Add static security analysis and dependency review, with findings triaged rather
than merely collected.

**Why this matters:** `cspell` mentions a `codeql` word and nothing runs it. A
library that decodes untrusted input and handles key material has exactly the
shape static analysis is good at, and dependency review is the cheapest guard
against a malicious transitive update.

_Acceptance criteria_

- CodeQL runs on pull requests and on a schedule, with the Go query suite.
- Dependency review blocks a pull request introducing a known-vulnerable
  dependency.
- Existing findings are triaged: fixed, or dismissed with a written reason.
- Pull-request check count stays within the repository's stated cap, or the cap
  is revisited deliberately.

_Implementation guidance_

- `CONTRIBUTING.md` says pull requests are capped at three checks and explains
  why — respect that or change it explicitly.
- A scanner whose findings nobody reads is worse than none; the triage is the
  deliverable.
- Pin the actions by commit SHA, as every other workflow here does.

#### ci: nightly build against the Go SDK's main branch

A scheduled job building and testing against `go-stellar-sdk@main`, reporting
breakage without failing the pinned build.

**Why this matters:** `docs/sdk-support.md` sets a policy for moving the pin,
and the pin moves when someone tries it. Finding out at that moment that the SDK
changed an XDR type is the expensive version; finding out the night it lands is
cheap.

_Acceptance criteria_

- Runs on a schedule against the SDK's default branch, isolated so it cannot
  affect the pinned build's status.
- On breakage it opens or updates a single tracking issue rather than emitting a
  notification per run.
- The golden vectors are part of what it runs, since a wire-format change there
  is the finding that matters most.
- A green run is visible somewhere, so silence is distinguishable from a broken
  job.

_Implementation guidance_

- A scheduled job that only speaks up on failure is indistinguishable from one
  that has stopped running — make success observable.
- One rolling issue, not one per night; a noisy bot gets muted and then ignored.
- `ci-parity.yml` already runs on a schedule — follow its conventions for
  staggering.

#### ci: enforce that every public entry point bounds its input

A check that every exported function taking an entry, envelope or base64 blob
goes through the bounded decoder rather than the SDK's default.

**Why this matters:** `decode.go` exists because the SDK's default limits are
much looser than this library wants. The bound only helps where it is used, and
nothing stops the next exported function from calling `xdr.SafeUnmarshalBase64`
directly — which is how the hardening quietly stops covering the newest code.

_Acceptance criteria_

- A check over the AST that fails naming any exported function reaching the SDK
  decoder directly.
- Deliberate exceptions are explicit and annotated, not implicit.
- It fails on a newly added violation, demonstrated in the PR and not committed.
- It fails loudly if it finds no entry points at all, so it cannot pass
  vacuously.

_Implementation guidance_

- `errors_meta_test.go` and `internal/doccheck` are the models: turn a prose
  rule into a check that bites.
- A test is enough; it need not be a separate CI job, given the check-count cap.
- The vacuous-pass guard matters — a scanner that silently matches nothing is
  the failure mode here.

#### ci: publish the documentation as a browsable site

Build the eighteen documents in `docs/` into a navigable site published on each
release, with search and the Go API reference linked.

**Why this matters:** `docs/README.md` is a hand-maintained map of eighteen
documents, which works for someone already in the repository and not for someone
deciding whether to use the library. Nothing is cross-linked or searchable.

_Acceptance criteria_

- Every document reachable, with working internal links, checked by the existing
  link checker.
- Published automatically on release; no manual step.
- A version selector or a clear statement of which version the site documents.
- `docs/README.md` remains correct, or becomes generated from the same source
  rather than duplicating it.

_Implementation guidance_

- The repository is the source of truth; the site renders it. Do not let content
  move into a generator's templates.
- `links.yml` already checks links — keep it covering the sources so the site
  cannot ship broken ones.
- Avoid a second place to update when adding a document; generate the
  navigation.

#### feat(cmd): shell-completable dynamic values

Extend completions beyond subcommands and flag names to flag values — networks,
output formats, and addresses present in a supplied entry.

**Why this matters:** Completions cover names, so a mistyped `--network pubic`
is still a silent fall-through to a literal passphrase. Completing values is
where completion actually prevents an error rather than saving keystrokes.

_Acceptance criteria_

- The three named networks and every enumerable format complete in bash, zsh and
  fish.
- Addresses complete from an entry already named on the command line, where the
  shell allows it.
- The existing spec table stays the single source, so the completion test keeps
  catching drift.
- No completion path can execute an entry's contents or run a signer.

_Implementation guidance_

- `commandSpecs` in `completions.go` is the source of truth and a test already
  asserts it matches the usage text — extend it, do not fork it.
- Dynamic completion that shells out is a code-execution surface; keep it to
  parsing, and say so.
- A literal passphrase must remain possible — completion suggests, it must not
  constrain.

#### feat(cmd): machine-readable error output for every subcommand

Give `--json` errors a stable schema — a code, a message, and the offending
field — rather than a single free-text `error` string.

**Why this matters:** `writeJSONError` emits `{"error": "..."}`. A caller that
needs to branch has to match on prose, which is not a contract and changes
whenever a message is improved. The library already has sentinel errors; the CLI
flattens them away.

_Acceptance criteria_

- A documented schema with a stable code per sentinel error, versioned so a
  change is detectable.
- Every subcommand emits it, asserted by a test over all of them rather than per
  subcommand.
- No error payload contains an entry, a secret or a key, with a test asserting
  it.
- The exit code and the code in the payload always agree, asserted.

_Implementation guidance_

- `errors.go`'s sentinels are the natural code set; map them explicitly rather
  than deriving codes from message text.
- A test that iterates every subcommand is what stops the next one from being
  added without this.
- Keep the human output unchanged; this is the machine contract.

#### chore: split the root package along its seams

Assess whether the thirty-one files and roughly 490 exported symbols in the root
package should be split into subpackages, and either do it behind an unchanged
public surface or record why not.

**Why this matters:** The root package has grown from the eleven files the
design called for to thirty-one, spanning signing, verification, inspection,
risk analysis, planning, coordination, TUI and WebAuthn. Whether that is one
coherent package or several is now a real question, and answering it after the
API has more consumers is harder.

_Acceptance criteria_

- A written assessment of the seams, with the dependency graph between current
  files as evidence.
- If split: the public import path and every exported name are unchanged, proven
  by a compile-time check against the current surface.
- Every golden vector and parity suite stays green, proving the move is
  behaviour-preserving.
- If not split: the reasoning is committed, so the question is settled rather
  than re-raised.

_Implementation guidance_

- Deciding not to split is a legitimate and valuable outcome — the deliverable
  is the decision with its evidence.
- A `go/ast` snapshot of the exported surface, compared before and after, is
  what makes 'unchanged' a fact rather than a claim.
- Do not combine this with any behaviour change; a refactor whose diff includes
  a fix cannot be verified by the vectors.

#### chore: generate the CLI reference from the command specs

Generate the README's CLI section, the man page and the completions from one
source, so none can drift from the flags the code actually parses.

**Why this matters:** The man page and completions already derive from
`commandSpecs`, and the README's CLI section is written by hand — nine
subcommands documented in prose beside a spec table that a test checks against
real flag parsing. The README is the copy that drifts.

_Acceptance criteria_

- The README's CLI flag documentation is generated or checked against the specs,
  failing CI on divergence.
- A new subcommand or flag cannot be added without the documentation following,
  demonstrated by adding one in the PR and showing the check fire.
- Hand-written prose and examples survive — only the flag tables are generated.
- The generated output is committed, so the README is readable on GitHub without
  a build step.

_Implementation guidance_

- `TestSpecsCoverTheUsageText` already proves this approach works for
  completions; extend the same idea to the README.
- Do not generate the explanatory prose: the CLI section's value is the
  explanation, and a generator would flatten it.
- Keep the committed output in the diff so a reviewer sees what changed.

#### chore: a release checklist that CI enforces

Turn the release process into a preflight job that verifies the conditions
before a tag is published rather than a document someone follows.

**Why this matters:** Releasing currently depends on remembering: CHANGELOG
updated, vectors regenerated, version bumped, docs consistent, every workflow
green. Each of those is checkable, and the one that gets forgotten is the one
that matters.

_Acceptance criteria_

- A job asserting: CHANGELOG has an entry for the version, the vectors are
  reproducible, every workflow is green on the commit, and no document
  references a stale version.
- It blocks the release workflow rather than reporting afterwards.
- It checks every workflow's conclusion on the exact commit, not just the
  required checks — the gap that let a red `spellcheck` reach main.
- A deliberately incomplete release is refused, demonstrated in the PR.

_Implementation guidance_

- Checking all workflows on the commit, not the pull request's checks, is the
  specific lesson from the `spellcheck` incident — see the 'Editing a workflow'
  section in CONTRIBUTING.
- Reuse the release workflow; this is a gate in front of it, not a replacement.
- A checklist in a document is what is being replaced — resist adding another
  one.

## Medium — 150 points each (40 issues)

### `area:api`

#### feat(api): errors.Join for batch failures

Where a batch operation can fail for several independent reasons, report all of
them with `errors.Join` instead of only the first.

**Why this matters:** `AuthorizeAll` returns on the first failure, so a caller
with three unsigned entries fixes one, reruns, and finds the next. Each round
trip through a batch of entries is cheap for the library and slow for the
person.

_Acceptance criteria_

- Validation failures that can be collected are collected; the first signing
  failure still stops immediately, since signing has side effects.
- `errors.Is` continues to match every joined sentinel, asserted by test.
- The all-or-nothing contract is unchanged: still no partial results.
- Each joined error still names its entry index and address.

_Implementation guidance_

- Separate validation from execution: collecting pre-flight problems is safe,
  continuing past a signer failure is not.
- `errors.Join` preserves `errors.Is` across all wrapped errors — add a test
  proving it for a joined pair.
- Do not change any existing error's text beyond what joining requires.

#### feat(api): Equal and Clone helpers for entries

Exported `Equal` and `Clone` for `SorobanAuthorizationEntry`, with semantics
stated: byte equality and an unaliased deep copy.

**Why this matters:** `internal/xdrcopy` is internal, so callers write their own
deep copy — usually a struct assignment, which aliases the pointers and slices
the XDR types are full of. That is the exact bug the repo's own no-mutation rule
exists to prevent, and external callers get no help with it.

_Acceptance criteria_

- `Clone` returns a copy sharing no memory with its input, asserted by a test
  that mutates the copy and checks the original.
- `Equal` is XDR byte equality, documented as such, and distinguished in the doc
  comment from semantic equivalence.
- An encoding failure is an error, never a false from `Equal` or a zero value
  from `Clone`.
- A fuzz target asserting `Equal(e, Clone(e))` holds for arbitrary entries.

_Implementation guidance_

- Thin exported wrappers over `internal/xdrcopy`, not a second implementation.
- Say plainly that `Equal` is byte equality: two entries that differ only in
  delegate order are unequal here and both may be valid.
- `xdrcopy` pools buffers; make sure the exported path is safe for concurrent
  use and test it under `-race`.

#### feat(api): iterator over credential nodes

An exported iterator over an entry's credential nodes, yielding address, path
and signature state for each.

**Why this matters:** `Inspect` returns a nested `EntryInfo` that a caller must
walk recursively to answer 'which nodes are unsigned' — which the docs tell
every caller to check before submitting. `credentialNodes` does exactly this
internally and is unexported.

_Acceptance criteria_

- Yields the top-level node and every delegate at every depth, in a documented
  stable order.
- Carries the path string `DiffEntries` uses, so findings from the two can be
  correlated.
- Read-only: the iterator cannot be used to write a signature.
- Depth-bounded like every other traversal, with a test proving a pathological
  tree is refused.

_Implementation guidance_

- Use the `iter.Seq` form the Go version in `go.mod` supports, and say so in the
  doc comment.
- Reuse `diff.go`'s path scheme rather than inventing a second one; correlating
  the two is the point.
- Read-only matters: the internal walker returns pointers for writing, and that
  must not leak.

#### feat(api): sentinel error for an unsupported invocation function type

Add a sentinel for an invocation whose function type the library does not
handle, and use it instead of falling through to generic handling.

**Why this matters:** An unrecognised `SorobanAuthorizedFunctionType` is
currently handled generically — byte-compared in `diff.go`, reported with a
numeric fallback name in the tree renderer. The repo's tie-break rule is to fail
closed, and a silently generic answer about what an entry authorizes is the
opposite.

_Acceptance criteria_

- A new exported sentinel, with a test that produces it, as the sentinel
  meta-test requires.
- Every reader of the invocation tree either handles the type or returns the
  sentinel; none reports a generic description.
- A test constructing an out-of-range function type asserts the sentinel from
  each reader.
- `errors.go`'s documentation explains when a caller should expect it.

_Implementation guidance_

- Decide deliberately whether `Inspect` should fail or report — and say which
  reading you chose in the commit, per the tie-break rule.
- Do not break the two real arms: `contract_fn` and the create arms must behave
  exactly as they do today.
- The vectors prove the real arms are unaffected; run them.

#### feat(api): expose the decode limits as documented constants

Audit the decode limits in `decode.go`, make each an exported documented
constant, and let a caller tighten them.

**Why this matters:** `MaxDecodeDepth` is exported at 64; other limits in the
same file may not be, and the number is a policy choice a caller with stricter
requirements cannot express. A caller who wants depth 8 has to validate
separately and hope the two checks agree.

_Acceptance criteria_

- Every limit is an exported constant with a doc comment saying what it protects
  against and why that value.
- An options form lets a caller supply stricter limits; looser than the default
  is refused.
- Refusals cite the limit that was hit, which the existing `ErrDecodeLimit`
  message already does for depth.
- A test per limit proving it is enforced at the boundary, not one past it.

_Implementation guidance_

- Tightening only: allowing a caller to loosen the bound would turn a safety
  default into a footgun.
- `decode.go` has the rationale for bounding at all; extend it rather than
  restating it.
- Keep the default behaviour byte-identical — the vectors are the check.

#### feat(api): String methods for the exported report types

Give `EntryInfo`, `VerificationReport` and the risk findings `String` methods,
as `EntryDiff` has.

**Why this matters:** `EntryDiff.String()` renders a readable report and the CLI
uses it. `EntryInfo` and `VerificationReport` have no equivalent, so the CLI
formats them itself and any other consumer formats them again, differently.

_Acceptance criteria_

- Each renders the same information the CLI currently prints, verdict or summary
  first.
- The CLI is refactored onto them, so there is one renderer per type and no
  drift.
- A golden-output test per type, so a formatting change is a visible diff rather
  than a surprise.
- No `String` method panics or allocates unboundedly on a pathological value.

_Implementation guidance_

- `EntryDiff.String()` is the model: lead with the line that answers the
  reader's actual question.
- Do not let `String` imply a verdict the type cannot support — a `cannot_check`
  must read as such.
- Golden-output tests make these safe to change later; without them nobody will
  touch the formatting.

### `area:docs`

#### docs: threat model

A document stating what soroauth defends against, what it does not, and which
component is responsible for each boundary.

**Why this matters:** `SECURITY.md` covers reporting and
`docs/verification-limits.md` covers what verification proves. Nothing states
the overall model, so a reader cannot tell whether a given risk — a compromised
signer, a hostile entry, a malicious RPC — is in scope.

_Acceptance criteria_

- Enumerates the trust boundaries: caller, signer, RPC endpoint, entry source,
  network.
- For each, what the library assumes, what it checks, and what it cannot check.
- Cites the code that enforces each check, so a claim can be followed to its
  implementation.
- States plainly that the library is unaudited, consistent with the README.

_Implementation guidance_

- Every claim needs the file that implements it; a threat model nobody can
  verify is marketing.
- A hostile RPC is a real and under-discussed case: it can lie about the entries
  to sign, and `--network` from an endpoint makes that sharper.
- Be explicit about the limits rather than diplomatic; the honest version is the
  useful one.

#### docs: performance characteristics and when they matter

A document reporting measured costs of the main operations, how they scale, and
which are dominated by the signer rather than the library.

**Why this matters:** Benchmarks and a budget check exist, and the numbers live
only in CI. Someone sizing a service has nothing to read, and the most important
fact — that a remote signer dominates everything the library does — is nowhere
stated.

_Acceptance criteria_

- Measured numbers per operation and per arm, with the machine and Go version
  recorded.
- Scaling with delegate count shown, since that is the one super-linear risk.
- States plainly where the library's cost is irrelevant next to signer latency
  or RPC round trips.
- Says how to reproduce every number.

_Implementation guidance_

- Report what you measured, not what you expect; an unreproduced number is worse
  than none.
- `scripts/checkbench` and the existing benchmarks are the source — do not
  invent a parallel harness.
- Date the numbers. Performance documentation without a date is read as current
  forever.

#### docs: recipes for the ten most common tasks

A cookbook of short, complete, compiling examples for the tasks people actually
arrive wanting.

**Why this matters:** The README has one quickstart and the guides are deep.
Between them is the gap where most questions live: sign for a multisig account,
sign one node of a delegate tree, check an entry before submitting, upgrade a
simulated entry.

_Acceptance criteria_

- At least ten recipes, each a complete compiling program, not a fragment.
- Covered by the README-snippet compilation check, so none can rot.
- Each states the task in the reader's words and links the deeper guide.
- No recipe prints or accepts a secret.

_Implementation guidance_

- `internal/readmesnippets` already verifies snippets compile — extend it to
  cover these.
- Complete programs: a fragment that does not compile is where documentation
  decays first.
- Link rather than restate; the guides are the explanation and the recipe is the
  shortest path.

#### docs: the delegates arm end to end

One document following a delegates entry from construction through signing,
verification and submission, with the protocol rule at each step.

**Why this matters:** The delegates arm is the newest and least familiar wire
format, and its explanation is spread across `AuthorizeAll`'s doc comment, the
multi-party guide, the glossary and the README. A newcomer has to assemble it
from four places.

_Acceptance criteria_

- Follows one real entry through every step, with actual bytes or CLI output at
  each.
- States at each step which CAP-71-01 rule applies and why.
- Covers the three traps: ordering, the Void top-level signature, and the shared
  payload that makes the expiration fatal.
- Links the existing documents rather than restating them.

_Implementation guidance_

- Use a committed golden vector as the worked example so the bytes are real and
  reproducible.
- The shared-payload consequence is the thing people get wrong — give it the
  most room.
- Do not duplicate `docs/multi-party-signing.md`; this is the single-party
  structural walkthrough.

#### docs: what to do when a submission fails

A troubleshooting guide from the symptom a user sees to the cause and the check
that confirms it.

**Why this matters:** The failure modes are known and documented in the places
that cause them — the two-pass requirement in the README, the expiration rule in
`expiration.go`, stale signatures in the diff docs. A user with a failed
transaction does not know which of those to read.

_Acceptance criteria_

- Organised by symptom, since that is what the reader has.
- Each entry names the confirming check: a CLI command or a library call.
- Covers at minimum: resource budget exceeded, expiration passed, nonce
  consumed, wrong network, signature on the wrong node, unsigned delegate.
- Every claim about host behaviour cites its source.

_Implementation guidance_

- Start from the real errors in `e2e/RESULTS.md` and the rejection scenarios,
  not from imagined failures.
- Give the command that confirms each cause; a guide that only names causes
  leaves the work undone.
- Coordinate with the `explain-error` subcommand so the two agree.

#### docs: architecture decision records for the deliberate departures

Short ADRs for the decisions that differ from the obvious choice: the
target-address rule, refusing to re-sign, no expiration cap, V2 by default,
`cannot_check` as a verdict.

**Why this matters:** Each is explained in a doc comment at the point of use,
which tells a reader what the code does and not why that was chosen over the
alternative. The reasoning is in commit messages, which nobody reads at review
time — so the decisions get re-argued.

_Acceptance criteria_

- One record per decision: context, the alternatives, the choice, and its
  consequences.
- Each cites the code that implements it and the commit that introduced it.
- Each records what would have to change for the decision to be revisited.
- Indexed from `docs/README.md`.

_Implementation guidance_

- The repo's commit bodies are unusually rich — mine them rather than
  reconstructing the reasoning.
- Short records. An ADR nobody finishes reading does not preserve a decision.
- Include at least one decision that is genuinely arguable, so the format is not
  just self-justification.

#### docs: how soroauth and soroauth-explain divide the problem

A document stating which library answers which question, and why interpreting an
entry is deliberately not done here.

**Why this matters:** `soroauth-explain` now exists and the glossary points at
it in one line. A user who wants to know what an entry authorizes needs to be
told clearly that this library reports structure and that one reports meaning —
otherwise they file the feature request here.

_Acceptance criteria_

- States the split: bytes and structure here, interpretation there.
- Explains why they are separate — different honesty boundaries and different
  failure consequences.
- Shows one entry through both, so the difference is concrete.
- Linked from both repositories' READMEs.

_Implementation guidance_

- Be accurate about `soroauth-explain`'s current state; check it rather than
  describing an intention.
- `Inspect`'s doc comment already draws this line — be consistent with it.
- Do not oversell either side; the value is the clarity of the boundary.

#### docs: operating the verification service

A runbook for running the service: configuration, deployment shape, what to
monitor, what the alerts mean, and how to respond.

**Why this matters:** `docs/verification-service.md` says what the service does
and what it refuses. Nothing says how to run it — what to watch, what a rising
refusal rate means, or what to do when it stops responding.

_Acceptance criteria_

- Configuration reference with every option, its default and its effect.
- The signals worth alerting on, with what each indicates.
- Response steps for the likely failures, including a wedged signer and an
  unreachable RPC.
- States the deployment assumptions, consistent with the threat model.

_Implementation guidance_

- Coordinate with the metrics issue so the runbook names signals that exist.
- Be honest about what the service does not do; a runbook implying high
  availability it has not been built for is a trap.
- Base the failure list on what has actually gone wrong in testing, not a
  generic checklist.

#### docs: versioning and compatibility promises

State what stability the library promises for its Go API, its wire output, its
CLI flags, its JSON shapes and its vector schema — each may differ.

**Why this matters:** Wave 9 produced a deprecation and support policy and a
vector schema version. There is no single statement of what a consumer may rely
on, and the answer genuinely differs per surface: wire output is fixed by the
protocol, CLI output is not.

_Acceptance criteria_

- A promise per surface, with the version scheme that governs it.
- States plainly which surfaces may change in a minor release.
- Covers pre-1.0 expectations honestly rather than implying stability the
  version number does not claim.
- Reconciled with `docs/sdk-support.md` and the deprecation policy, with no
  contradiction between them.

_Implementation guidance_

- Check the existing policy documents first and extend rather than overlay; a
  contradictory second policy is worse than one.
- The wire format is not this project's to change — say that explicitly, citing
  the CAPs.
- Promise what will be kept. An aspirational promise is worse than a narrow one.

#### docs: contributing a new signer

A guide for adding a signer adapter: the module layout, the contract, the
conformance suite, the test expectations and the documentation it must carry.

**Why this matters:** There are now a dozen signers across four modules, and the
pattern is learned by reading three of them. The next contributor either reads
them or guesses, and the parts that are easy to get wrong — typed-nil clients,
context handling, never logging a secret — are exactly the ones a guide would
catch.

_Acceptance criteria_

- Covers module layout, `go.mod` placement and the adapters CI job.
- States the `Signer` contract explicitly and points at the conformance suite.
- Covers the recurring traps, each with the existing adapter that demonstrates
  the fix.
- States the evidence an adapter must carry in `docs/signers.md`.

_Implementation guidance_

- Cite the real examples: `gcpkms`'s typed-nil check exists because that bug
  happened.
- Coordinate with the conformance-suite issue; the guide should point at a
  check, not a checklist.
- Be clear that an untested hardware claim is not acceptable, as
  `docs/signers.md` already requires.

### `area:integrations`

#### feat(integrations): publish the wasm package to a CDN-friendly layout

Publish the wasm artifact and its JavaScript glue so a browser page can load it
from a URL without a bundler.

**Why this matters:** `@soroauth/wasm` publishes to npm, which assumes a build
step. The browser passkey example is exactly the audience least likely to have
one, and a script-tag path is the shortest route from reading the docs to
running the thing.

_Acceptance criteria_

- A documented URL layout with versioned, immutable paths.
- Subresource integrity hashes published alongside, so a page can pin what it
  loads.
- A plain HTML page in the repo loading it with no build step, exercised in CI.
- The published artifact replays the golden vectors, same as the npm path.

_Implementation guidance_

- Immutable versioned URLs: a mutable `latest` for a signing library is a
  supply-chain risk, not a convenience.
- Publish the integrity hashes and document their use, or the layout adds a risk
  without a mitigation.
- Reuse the existing npm publishing pipeline rather than adding a second release
  path.

#### feat(integrations): devcontainer and Codespaces configuration

A devcontainer with Go, Node, Rust and `stellar-cli` at the repository's pinned
versions.

**Why this matters:** `CONTRIBUTING.md` lists four toolchains at specific
versions for the optional paths. A contributor who only wants to run the e2e
suite has to install Rust 1.93.0 and stellar-cli 28.0.0 first, which is where
most people stop.

_Acceptance criteria_

- Every pinned version matches the repository's pins, read from the pin files
  rather than duplicated.
- `make`, `make vectors` and `make e2e` all work in it from a clean start.
- Built in CI so it cannot rot silently.
- Documented in CONTRIBUTING as an option, not as the required path.

_Implementation guidance_

- Read the versions from `rust-toolchain.toml`, `go.mod` and the generator's
  `package.json`; a duplicated pin will drift.
- Building it in CI is what keeps it working — an unbuilt devcontainer is worse
  than none.
- Do not let it become the only supported environment; the local instructions
  stay.

#### feat(integrations): OpenTelemetry example covering the full flow

Extend the OpenTelemetry example from signing to the whole flow: both simulation
passes, signing, submission and polling, as one trace.

**Why this matters:** `examples/opentelemetry` instruments signing. The
interesting latency is elsewhere — the two simulation round trips and the
submission poll — and the two-pass requirement is much easier to understand as a
trace than as prose.

_Acceptance criteria_

- One trace spanning record pass, signing, enforcing pass, submission and
  polling, with spans named consistently.
- The resource-fee difference between the two passes is visible as an attribute,
  since that is the point of the second pass.
- No span attribute carries a secret, an entry or a signature; asserted by a
  test.
- Runnable against testnet with documented configuration, and the example's
  README shows a real captured trace.

_Implementation guidance_

- `rpcflow.SignAndSubmit` is the flow; instrument through `hooks.go` rather than
  forking it.
- A real captured trace in the README is what makes this teach something.
- Keep OpenTelemetry out of the root module; it stays an example dependency.

#### feat(integrations): Makefile target to run everything CI runs

A single target that runs locally everything CI runs, in CI's order, with the
same commands.

**Why this matters:** `make` runs fmt, vet and test. CI additionally runs the
vector drift check, the adapter modules, the parity suites, the wasm replay,
prettier, cspell and the link check — so a branch can be green locally and red
on push, which is how `spellcheck` got missed.

_Acceptance criteria_

- One target running every check CI runs, each with the same command CI uses.
- Prerequisites it cannot satisfy are reported as skipped with the reason, never
  silently passed.
- A check present in CI and absent from the target fails a meta-check, so the
  two cannot drift.
- Documented in CONTRIBUTING alongside the existing `make` guidance.

_Implementation guidance_

- The meta-check is the valuable part: without it this target drifts from CI
  within a month.
- Skipped-with-a-reason is essential — a silent skip is exactly the failure mode
  being fixed.
- Keep plain `make` fast; this is the thorough target, not a replacement.

### `area:signers`

#### feat(signers): cache a signer's address lookup

Let a signer whose `Address()` requires a remote call cache the result, with the
cache's lifetime and invalidation explicit.

**Why this matters:** `Address()` is called on every signing path and for every
node of a delegate tree. For a KMS signer that resolves a key to a public key
remotely, that is a network round trip per node — turning a tree walk into a
sequence of API calls.

_Acceptance criteria_

- A documented caching wrapper, with lifetime and invalidation stated.
- A rotation that changes the address invalidates the cache, or the wrapper
  documents that it cannot detect one and refuses to cache across it.
- Concurrency-safe, with a `-race` test.
- A test proving the underlying lookup happens once for a multi-node tree.

_Implementation guidance_

- `Address()` returning a stale value would write signatures to the wrong node —
  the invalidation story must be stated, not assumed.
- Coordinate with the key-rotation issue so there is one notion of when an
  address can change.
- A wrapper, not a change to the interface: not every signer needs this.

#### feat(signers): zero key material after use where the language allows

Audit where seeds and private keys are held in memory, zero them when their
lifetime ends, and document honestly what Go cannot guarantee.

**Why this matters:** `NewEd25519Signer` takes a `keypair.Full` and the CLI
reads a seed from the environment. Those bytes stay in memory, and Go's garbage
collector may copy them. The limits here are real, and the honest statement of
them is itself the deliverable.

_Acceptance criteria_

- An audit naming every place key material is held, from reading the code.
- Zeroing where the library owns the buffer, with a test asserting it.
- A documented statement of what Go cannot guarantee — GC copies, swap, core
  dumps — without overclaiming.
- The CLI's environment-read path covered, since that is the most likely real
  exposure.

_Implementation guidance_

- Do not claim memory hygiene Go cannot deliver; an overclaim here is worse than
  the current silence.
- `keypair.Full` is the SDK's type and this library does not own its internals —
  say what that means for the guarantee.
- The audit is the valuable half. If zeroing turns out to be mostly theatre,
  report that.

#### feat(signers): report a signer's capabilities

An optional interface letting a signer declare whether it is deterministic,
interactive, remote, or supports batched presence, so callers and tests can
adapt.

**Why this matters:** A caller cannot tell an in-memory ed25519 signer from a
hardware device that will prompt a human. That difference governs whether
retrying is safe, whether batching helps, and which conformance contract applies
— and it is currently inferred from the constructor's name.

_Acceptance criteria_

- An optional interface with a documented, closed set of capabilities.
- Every shipped signer declares its capabilities, asserted by a test over all of
  them.
- The conformance suite uses the declaration to choose which contract to apply.
- A signer that does not implement it gets documented conservative defaults.

_Implementation guidance_

- Optional, so no existing signer breaks: a type assertion, not a change to
  `Signer`.
- Conservative defaults: assume interactive and non-deterministic when unknown,
  since that is the safe direction for retries.
- Coordinate with the conformance-suite and batched-presence issues so there is
  one vocabulary.

#### feat(signers): refuse to sign for the wrong network

Let a signer be pinned to a network passphrase and refuse any preimage built for
another.

**Why this matters:** `Signer.Sign` receives the preimage, which carries the
network id — so a signer can check it, and none does. A production key signing a
testnet payload, or worse the reverse, is currently caught only by the
submission failing.

_Acceptance criteria_

- A wrapper pinning a signer to one passphrase, refusing others with a distinct
  error.
- The check compares the network id inside the preimage, not a caller-supplied
  string.
- A test proving a mainnet-pinned signer refuses a testnet preimage and vice
  versa.
- The source-account arm, which has no preimage, is handled explicitly rather
  than falling through.

_Implementation guidance_

- Deriving the id from the passphrase and comparing to the preimage's is the
  only check that cannot be fooled by a wrong argument.
- `network.ID` is the existing derivation — use it rather than hashing by hand.
- This is a containment control for a production key; make the refusal
  unmistakable.

### `area:testing`

#### test: assert every exported function checks its context

A meta-test asserting that every exported function taking a `context.Context`
checks `ctx.Err()` before doing work and has a cancellation test.

**Why this matters:** `CONTRIBUTING.md` states this rule and Wave 9 audited it
once by hand. An audit is a snapshot; the rule only holds if something checks it
when the next context-taking function is added.

_Acceptance criteria_

- Parses the package for exported functions whose first parameter is a
  `context.Context`, and fails naming any without a cancellation test.
- Fails loudly if it finds no such functions, so it cannot pass vacuously.
- Every current function passes, and any that did not before being fixed is
  named in the PR.
- Covers the adapter modules too, or states why it cannot reach them.

_Implementation guidance_

- `errors_meta_test.go` is the pattern: parse the source, scan the tests, fail
  with names.
- Be loose about how the test asserts cancellation and strict about its
  existence, exactly as the sentinel check is.
- The vacuous-pass guard is not optional; it is the failure mode of every check
  like this.

#### test: golden vectors for a muxed address in an invocation argument

Vectors where an invocation argument contains a muxed (`M…`) address, which
`ParseAddress` rejects for credentials but which is legal inside arguments.

**Why this matters:** `ParseAddress` rejects `M…` because credentials must name
the account itself. An argument is a different position with a different rule,
and nothing tests that the library passes such an argument through untouched
rather than rejecting the whole entry.

_Acceptance criteria_

- A vector with a muxed address argument, generated by the pinned JS SDK,
  byte-equal through the Go path.
- `Inspect` and `DiffEntries` handle it without error.
- A test asserting `ParseAddress` still rejects `M…` for credentials, so the two
  rules stay distinct.
- `docs/glossary.md` or the `ParseAddress` doc comment states the distinction.

_Implementation guidance_

- Confirm from the XDR that a muxed address is representable in an `ScVal`
  argument before building the vector; if it is not, report that and close the
  issue with the finding.
- The two positions having different rules is the thing worth documenting,
  whichever way the vector comes out.
- Never hand-edit a vector.

#### test: parity harnesses cover the delegates arm explicitly

Audit the Python and Rust parity harnesses for delegate-arm coverage and add the
cases they are missing.

**Why this matters:** `docs/parity.md` states what agreement proves. If the
harnesses only recompute the legacy and V2 vectors, that agreement says nothing
about the delegates arm — which is the newest wire format and the one most
likely to diverge.

_Acceptance criteria_

- A written statement of which vectors each harness currently covers, from
  reading the harness rather than assuming.
- Every delegates-arm vector covered by both, or a recorded reason a given SDK
  cannot express one.
- The parity report artifact states coverage per arm.
- `docs/parity.md` updated to say what is and is not covered.

_Implementation guidance_

- Start by measuring; the audit may show coverage is already complete, which is
  a perfectly good result to report.
- A harness that silently skips a vector is the failure mode — make skips
  explicit and counted.
- If an SDK genuinely cannot build a delegates entry, that is a finding about
  that SDK, not a gap to paper over.

#### test: assert e2e scenarios are independent and reorderable

Run the e2e scenarios in a shuffled order and in isolation, to prove none
depends on another's accounts or ledger state.

**Why this matters:** The scenarios share a fixture harness and all run against
one network. A scenario that passes only because an earlier one funded an
account is a scenario that will fail alone, and nothing currently distinguishes
the two.

_Acceptance criteria_

- Each scenario passes when run alone by name.
- The suite passes with scenarios shuffled, with the seed reported so a failure
  is reproducible.
- Any discovered dependency is fixed or documented as deliberate with its
  reason.
- `e2e/README.md` states the independence property so it is a rule rather than
  an accident.

_Implementation guidance_

- `refactor(e2e): reduce duplication across scenario runners` built the shared
  harness — shared setup is fine, shared mutable state is not.
- Report the shuffle seed on failure; a flaky ordering bug is unfixable without
  it.
- Friendbot rate limits may make isolated runs slow; that is a reason to
  document the cost, not to skip the check.

#### test: fuzz the canonical JSON round trip

A fuzz target asserting XDR → canonical JSON → XDR is the identity for arbitrary
decoded entries.

**Why this matters:** A canonical JSON encoding is only useful if it is exact. A
field that silently fails to round-trip turns the encoding from a representation
into a lossy summary, and table tests will not find which field.

_Acceptance criteria_

- Asserts byte-identical XDR after a round trip, for every entry the bounded
  decoder accepts.
- Input the encoding cannot represent exactly must be refused by the encoder,
  not silently altered — asserted.
- Seed corpus from the golden vectors.
- Wired into the continuous fuzzing workflow.

_Implementation guidance_

- Depends on the canonical JSON issue; check its state first and say so on the
  issue.
- The refusal assertion is as important as the identity one: a lossy success is
  the dangerous outcome.
- Any crash becomes a committed regression seed, per `docs/fuzzing.md`.

#### test: assert the container image runs the documented commands

A CI test that pulls the published image and runs each documented example
command inside it.

**Why this matters:** The README documents the container image with example
invocations. The image is built in CI and never exercised, so an image that
builds but cannot run the CLI — a missing certificate bundle, a wrong entrypoint
— would ship unnoticed.

_Acceptance criteria_

- Runs `--version`, `inspect`, `verify` and `diff` inside the image against
  committed fixtures.
- Asserts the exit codes, not merely that the commands produced output.
- Covers every architecture the image publishes.
- Fails the release if the image cannot run the documented commands.

_Implementation guidance_

- Test the published image, not a locally built one — the published artifact is
  what users get.
- A command needing network must be excluded explicitly, with a note, rather
  than failing intermittently.
- Coordinate with the multi-arch image issue so both architectures are covered
  once.

#### test: record and replay RPC fixtures for offline flow tests

A recorder that captures real RPC request and response pairs, and a replayer so
`rpcflow` and the new RPC subcommands can be tested offline against real
responses.

**Why this matters:** `rpcflow`'s tests use a hand-written fake client, which
tests the code against the author's belief about the RPC's responses. The
two-pass flow's correctness depends on details of real responses — which arm was
recorded, what the fee came back as — and a fake cannot be wrong in the same
ways the real thing is.

_Acceptance criteria_

- Recorded fixtures committed, each noting the RPC version, network and ledger
  it came from.
- Replay is byte-faithful, and a fixture that does not match the request is an
  error rather than a silent miss.
- `rpcflow`'s existing tests gain at least one real-fixture case alongside the
  fakes.
- No fixture contains a secret, with a documented scrubbing step.

_Implementation guidance_

- Keep the hand-written fakes for the failure injection they are good at;
  fixtures are for fidelity, not a replacement.
- Record against testnet and say exactly when — an RPC response is a dated
  artifact.
- A mismatched request must fail loudly: a replayer that falls through to a
  default is how an offline test passes against nothing.

### `area:tooling`

#### feat(cmd): --quiet and --verbose output levels

Consistent verbosity control across subcommands: `--quiet` for exit-code-only
use, `--verbose` for the reasoning behind a verdict.

**Why this matters:** Each subcommand prints one fixed amount. In a script the
output is noise and the exit code is the signal; while debugging a refusal the
output is too thin. Both users are currently served the same middle.

_Acceptance criteria_

- `--quiet` prints nothing on success and still exits with the right code, for
  every subcommand.
- `--verbose` explains the verdict — which node, which rule, which field —
  without printing an entry or a secret.
- Mutually exclusive, with a usage error if both are given.
- Covered by a test iterating every subcommand, so a new one cannot omit them.

_Implementation guidance_

- `--json` already exists and must be unaffected; verbosity governs the human
  output only.
- Add the flags to `commandSpecs` so completions and the man page follow
  automatically.
- `--verbose` must not become a channel for echoing input; the no-echo rule
  still holds.

#### feat(cmd): --network from an RPC endpoint's reported passphrase

Let `--network` be resolved by asking an RPC endpoint for its network
passphrase, instead of being named or typed out.

**Why this matters:** A mistyped passphrase or the wrong named network produces
a valid-looking signature over the wrong payload, which fails only on
submission. The endpoint already knows the answer authoritatively, and asking it
removes the class of error entirely.

_Acceptance criteria_

- A documented flag that fetches the passphrase from the configured RPC URL and
  uses it.
- Reports the resolved passphrase before signing, so the user sees which network
  they are about to commit to.
- A fetch failure is an error, never a fall-through to a default network.
- Tests drive it from committed fixtures and touch no network.

_Implementation guidance_

- Falling back to a default on failure would reintroduce exactly the bug this
  prevents — fail closed.
- Printing the resolved value is the point; a silent correct answer teaches the
  user nothing.
- The three named shorthands stay; this is an additional source, not a
  replacement.

#### ci: cache the Rust and Node toolchains across jobs

Audit cache usage across the workflows and add caching where a job rebuilds a
toolchain or dependency tree it could reuse.

**Why this matters:** The contract build, the parity harnesses and the vector
generator each install a toolchain. Slow CI is tolerated until it is not, and
then the response is usually to run less of it — which is the outcome worth
avoiding in a repo whose correctness gate is a regeneration.

_Acceptance criteria_

- Measured before-and-after wall-clock times per job, reported in the PR.
- Cache keys include the lockfiles and toolchain pins, so a stale cache cannot
  mask a dependency change.
- `make vectors-check` still regenerates from a clean state, since a cached
  generator output would defeat the gate.
- No job's correctness depends on a cache hit, demonstrated by a cold run.

_Implementation guidance_

- The drift check must not be cached in any way that lets it pass without
  regenerating; that is the one job where speed is not the priority.
- Report real numbers — a caching change without measurement is a guess.
- Pin the cache action by SHA like every other action here.

#### ci: fail the build on a stale generated artifact

One job that regenerates every generated artifact — vectors, corpora, man page,
completions, diagrams — and fails if any committed copy differs.

**Why this matters:** `make vectors-check` does this for the vectors. The man
page, completions, fuzz corpora and rendered diagrams are also generated and
committed, and nothing checks them, so a committed copy can silently stop
matching its source.

_Acceptance criteria_

- Every generated-and-committed artifact is covered, with a list in the job so a
  new one is an obvious omission.
- Failure names the artifact and the command that regenerates it.
- A deliberately stale artifact proves the gate bites, shown in the PR and not
  committed.
- Runs within the repository's check-count cap, by extending an existing job
  rather than adding one.

_Implementation guidance_

- `vectors-check` is the model and should be absorbed rather than duplicated.
- Anything whose output is not deterministic cannot be checked this way —
  identify those and say so rather than making the job flaky.
- Include the workflow file's own path in the `paths:` filter, or an edit to it
  will not run it.

#### chore: adopt a changelog-from-commits check

Check that every user-visible change since the last release has a CHANGELOG
entry, using the conventional-commit prefixes already in use.

**Why this matters:** The commit format is conventional and enforced by
convention, and the CHANGELOG is updated by hand. The entries that go missing
are the ones added in a hurry, which correlates with the changes most worth
announcing.

_Acceptance criteria_

- A check listing `feat` and `fix` commits since the last tag with no
  corresponding CHANGELOG line.
- `chore`, `ci`, `test` and `docs` commits are excluded by default, with the
  policy documented.
- Advisory on pull requests and blocking in the release preflight, so it does
  not become noise.
- A missing entry is demonstrated to be caught, in the PR.

_Implementation guidance_

- Do not generate the CHANGELOG from commits: the existing entries explain
  changes in a way commit subjects do not.
- Matching commit to entry needs a rule — issue number or scope — so define it
  rather than guessing at text similarity.
- Coordinate with the release-preflight issue so there is one gate.

#### feat(cmd): soroauth explain-error

A subcommand that takes a host or RPC error string and explains what it means
for an authorization entry, with the source cited.

**Why this matters:** The failures this library's users hit come back as host
error codes and terse strings. Mapping those to a cause — expiration passed,
nonce consumed, resource budget exceeded because the enforcing pass was skipped
— is knowledge currently spread across doc comments and the e2e README.

_Acceptance criteria_

- Covers the errors the e2e scenarios actually produced, each with the CAP or
  host source cited.
- An unrecognised error is reported as unrecognised, never guessed at.
- Suggests the concrete next check, such as re-running the enforcing pass.
- Every mapping has a test, and the text is sourced from a real recorded error
  rather than invented.

_Implementation guidance_

- `e2e/RESULTS.md` and the rejection scenarios are the corpus of real errors —
  use them as the input, not memory.
- A wrong explanation is worse than none here: the user will act on it. Fail
  closed on anything not recognised.
- Cite the host source for each explanation, as every protocol claim in this
  repo must.

#### chore: issue template for a wire-format or vector discrepancy

A dedicated issue template for reporting that two implementations disagree, or
that a golden vector looks wrong.

**Why this matters:** The repo's rule is to stop and report rather than edit a
vector to make a test pass. Nothing makes that easy: the bug template asks for
reproduction steps, not for the two byte strings and which SDK produced each.

_Acceptance criteria_

- Collects both encodings, both implementation versions, the vector name, and
  the command that produced the disagreement.
- States prominently that no vector may be edited by hand.
- Routes to maintainers at the severity a wire-format disagreement deserves.
- Linked from CONTRIBUTING's golden-vector section.

_Implementation guidance_

- The security template already routes to private advisories — follow its
  structure for a template that must be read before filing.
- Ask for the bytes. A prose description of a byte-level disagreement is not
  actionable.
- Keep it short enough to be used; a long form is a form nobody fills in.

#### chore: measure and report CI cost per workflow

A scheduled report of runner minutes per workflow, so the cost of ten workflows
is visible before it becomes a reason to delete one.

**Why this matters:** The repository now runs nine workflows plus continuous
fuzzing, several on schedules. Nobody knows which ones dominate, so any future
decision about what to cut would be made on impression rather than measurement.

_Acceptance criteria_

- A scheduled job reporting minutes per workflow over a trailing window.
- Published where a maintainer will see it, not only in a log.
- The report itself costs materially less than what it measures, and the PR says
  what it costs.
- No credential beyond the token the job needs.

_Implementation guidance_

- Use the Actions API rather than estimating from run counts and durations.
- A scheduled job that only reports anomalies is invisible when healthy — make a
  normal week legible too.
- Keep it advisory: this informs decisions, it should not gate anything.

#### chore: retire the Wave 9 issue script and archive its backlog

Remove `scripts/wave9_issues.py`, now superseded by `scripts/wave_issues.py`,
and archive the Wave 9 backlog documents as a completed record with their
outcomes.

**Why this matters:** Two scripts that create issues is one too many, and the
older one hard-codes Wave 9's file names plus the twenty-one issues that
predated it. Leaving both means the next person picks the wrong one. The Wave 9
documents are worth keeping as a record, but only if they say what actually
happened.

_Acceptance criteria_

- `scripts/wave9_issues.py` removed, with anything it did that the new script
  does not reproduced first.
- The Wave 9 backlog documents marked complete, recording which items shipped
  and which did not.
- Every reference to the old script in the documentation updated.
- A dry run of the new script against the Wave 9 backlog still produces a
  sensible plan, shown in the PR.

_Implementation guidance_

- Check the old script for behaviour the new one lacks — it re-rendered existing
  issues from a Markdown backlog, which the new one does not do.
- The archive should be honest about incomplete items; a record that lists only
  successes is not a record.
- Do not weaken the new script's dry-run default or its duplicate-title guard
  while consolidating.

## Trivial — 100 points each (30 issues)

### `area:docs`

#### docs: Go doc examples for diff.go

Runnable `Example` functions for `DiffEntries` and `EntryDiff.String`, in the
style of the existing example files.

**Why this matters:** Every other major entry point gained doc examples in
Wave 9. `DiffEntries` shipped after them and has none, so `pkg.go.dev` shows its
signature with no worked use — and the payload-versus-signature distinction is
exactly what an example conveys better than prose.

**Good first issue.** Entry point: `diff.go and inspect_example_test.go`.

_Acceptance criteria_

- At least one example showing a payload change with a carried-over signature,
  since that is the finding the type exists for.
- Output assertions use real values from a committed golden vector, not invented
  ones.
- File-scoped constants, so the file cannot collide with another example file's
  identifiers.
- `go test ./...` passes with the examples' output verified.

_Implementation guidance_

- Read `inspect_example_test.go` and follow it exactly; consistency across the
  example files is the point.
- Run the test to get the real output rather than predicting it — a guessed
  `// Output:` is the usual failure here.
- Keep each example short enough to read on `pkg.go.dev` without scrolling.

#### docs: Go doc examples for verify.go

Runnable examples for `VerifyEntry` covering a verified node, an unsigned node
and a `cannot_check` node.

**Why this matters:** The four verdicts exist precisely because collapsing them
loses information, and nothing on `pkg.go.dev` shows a reader what each looks
like in practice.

**Good first issue.** Entry point: `verify.go`.

_Acceptance criteria_

- One example per verdict a classic account can produce, plus `cannot_check` for
  a contract address.
- Output taken from a real run against a committed vector.
- File-scoped constants to avoid identifier collisions with other example files.
- The examples make clear that `cannot_check` is not a failure.

_Implementation guidance_

- Follow the existing example files' structure.
- `docs/verification-limits.md` has the framing — the examples should agree with
  it.
- Do not construct an `invalid` case by hand-editing a vector; build it in code
  from a signed entry.

#### docs: Go doc examples for the risk analyzer

Runnable examples for the risk analyzer showing a clean entry and one that
produces findings.

**Why this matters:** The analyzer is heuristic and its limits are documented
separately. An example is where a reader learns what a finding looks like, and
that an empty result is not a safety verdict.

**Good first issue.** Entry point: `risk.go`.

_Acceptance criteria_

- One example with no findings and one with at least one finding.
- A comment stating that no findings does not mean safe, consistent with
  `docs/analyzer-heuristics.md`.
- Output from a real run.
- File-scoped constants.

_Implementation guidance_

- `docs/analyzer-heuristics.md` lists what the analyzer misses — do not imply
  more than it claims.
- Build the risky entry in code so the example is self-contained.
- Match the existing example files' style.

#### docs: Go doc examples for the envelope helpers

Runnable examples for `EnvelopeEntries` and `InspectEnvelope`.

**Why this matters:** Envelope support shipped in Wave 9 and is the entry point
for anyone starting from a transaction rather than a bare entry — which is the
common case, since that is what simulation returns.

**Good first issue.** Entry point: `envelope.go`.

_Acceptance criteria_

- An example reading entries out of an envelope and reporting their operation
  and entry indices.
- An example covering a fee-bump envelope, since reading through to the inner
  transaction is the surprising part.
- Output from a real run against a committed fixture.
- File-scoped constants.

_Implementation guidance_

- `envelope_test.go` has fixtures already — reuse rather than building new ones.
- The index reporting is what callers need in order to put a signed entry back;
  make that visible.
- Follow the existing example files.

#### docs: document the exported constants in one place

A doc.go section listing the exported constants — credential type names,
verdicts, decode limits, signature shapes — with what each is for.

**Why this matters:** These are the values a caller switches on, and they are
declared across five files. `pkg.go.dev` lists them alphabetically with no
indication of which belong together.

**Good first issue.** Entry point: `doc.go`.

_Acceptance criteria_

- Every exported constant covered, verified by comparing against the package's
  actual exported surface rather than by reading.
- Grouped by the type or decision each belongs to.
- States which are stable strings safe to persist and which are not.
- No constant's existing doc comment is removed.

_Implementation guidance_

- Generate the list from `go doc` output so none is missed.
- `doc.go` already holds the credential-arm table; extend that rather than
  starting a new document.
- Saying which strings are safe to persist is the genuinely useful part.

#### docs: note the fail-closed tie-break rule in CONTRIBUTING

State the fail-closed rule explicitly in CONTRIBUTING, with examples of where it
was applied.

**Why this matters:** The rule governs every ambiguous decision in the codebase
and lives in the project's own instructions rather than in the
contributor-facing documentation. A contributor hitting an ambiguity has no way
to know what the project expects.

**Good first issue.** Entry point: `CONTRIBUTING.md`.

_Acceptance criteria_

- States the rule: where the protocol or intent is ambiguous, refuse and return
  an error rather than guess.
- Cites at least three real applications in the code, with the file.
- States that the chosen reading goes in the commit message.
- Placed near 'What a change needs', which already carries the related rules.

_Implementation guidance_

- The target-address rule and the re-sign refusal are the clearest examples —
  both already have doc comments explaining the reasoning.
- Keep it short; it belongs beside the existing rules, not as a new top-level
  section.
- Do not restate what 'What a change needs' already says.

#### docs: add the diff subcommand to the CLI docs index

Audit the CLI documentation for subcommands added after it was written and add
the missing ones consistently.

**Why this matters:** `diff` has a README section; whether every subcommand is
represented consistently across the README, the docs index and the man page is
unverified, and an undocumented subcommand is effectively absent.

**Good first issue.** Entry point: `cmd/soroauth/main.go and README.md`.

_Acceptance criteria_

- A list, from the dispatcher rather than from the documentation, of every
  subcommand.
- Each present in the README's CLI section and the docs index, or an explicit
  note of why not.
- Any gap found is fixed in the same style as the surrounding entries.
- The PR reports which were missing.

_Implementation guidance_

- Read the dispatch switch in `cmd/soroauth/main.go` for the authoritative list;
  the documentation is what is being checked.
- `commandSpecs` is checked against the usage text by a test — the README is the
  uncovered copy.
- If everything is already consistent, say so; that is a valid result.

#### docs: state the Go version policy in the README

Say in the README which Go versions are supported, and that the floor moves only
when a dependency raises it.

**Why this matters:** `go.mod` declares a floor and `CONTRIBUTING.md` mentions
it in passing. Someone deciding whether the library fits their build reads the
README, where the answer is absent.

**Good first issue.** Entry point: `README.md and go.mod`.

_Acceptance criteria_

- The supported floor stated, read from `go.mod` rather than from memory.
- The policy stated: the floor moves only when a dependency forces it.
- Consistent with `docs/sdk-support.md`, which governs the dependency pin.
- Placed in the install section where a reader will be looking.

_Implementation guidance_

- Read the version from `go.mod` and quote it; a stale version number here is
  worse than none.
- `docs/sdk-support.md` already has the pin policy — link rather than restate.
- One short paragraph.

#### docs: a worked example in the DiffEntries doc comment

Add a short worked example to `DiffEntries`'s doc comment showing the
stale-signature case as a table.

**Why this matters:** `ExpirationAfter` has a worked table in its doc comment
and it is the clearest explanation of the inclusive bound anywhere in the repo.
The payload-versus-signature distinction would benefit from the same treatment.

**Good first issue.** Entry point: `diff.go`.

_Acceptance criteria_

- A table showing which field changed, whether the payload moved, and whether a
  carried-over signature is stale.
- Covers the four combinations: identical, signature only, payload only, both.
- Consistent with what the code actually produces, checked by running it.
- Adds no claim not already true of the implementation.

_Implementation guidance_

- `ExpirationAfter`'s doc comment is the model for the format.
- Run the four cases and transcribe the real summaries rather than paraphrasing
  them.
- Keep it compact; the doc comment is already long.

#### docs: explain the deterministic key labels in the glossary

Add the deterministic test-key scheme to the glossary, with a pointer to the
fuller explanation.

**Why this matters:** Test keys derived from `sha256(label)` appear throughout
the vectors, the fixtures and the e2e suite. A reader meeting
`soroauth-vector-signer-1` in a vector has no entry point for what it means.

**Good first issue.** Entry point: `docs/glossary.md`.

_Acceptance criteria_

- A glossary entry explaining the derivation and why it is deterministic.
- States plainly that these are public test keys that must never be funded on
  mainnet.
- Links the existing fuller document rather than restating it.
- Fits the glossary's existing grouping and tone.

_Implementation guidance_

- Wave 9 documented the scheme in one place — find it and link it.
- The mainnet warning is the part that matters; keep it prominent.
- `docs/glossary.md` groups terms by what they belong to, not alphabetically —
  place it accordingly.

#### docs: add diff and verify to the glossary

Add glossary entries for the project's own terms introduced since it was
written: stale signature, payload change, credential-node path, verdict.

**Why this matters:** The glossary has a section for this project's own
vocabulary. `DiffEntries` introduced four more terms that appear in output a
user reads, and none is defined anywhere a reader would look.

**Good first issue.** Entry point: `docs/glossary.md`.

_Acceptance criteria_

- Entries for stale signature, payload change, node path and verdict.
- Each says plainly that it is this project's term and not protocol vocabulary.
- Cross-linked with the existing entries that relate to them.
- Placed in the existing 'this project's own terms' section.

_Implementation guidance_

- The glossary is explicit about which terms are the project's own — keep that
  distinction.
- Define them as the code uses them; read `diff.go` and `verify.go` rather than
  inferring.
- Match the existing entries' length and tone.

#### docs: link the e2e results from the scenario table

Cross-link `e2e/README.md`'s scenario table with the corresponding runs in
`e2e/RESULTS.md`.

**Why this matters:** One document says what each scenario proves and the other
records that it ran, with no link between them. A reader checking whether a
claim is backed by a real run has to match them up by hand.

**Good first issue.** Entry point: `e2e/README.md`.

_Acceptance criteria_

- Each scenario in the table links its recorded result.
- A scenario with no recorded run is marked as such rather than left ambiguous.
- Links verified by the link checker.
- No claim is added about a scenario that has not run.

_Implementation guidance_

- `RESULTS.md` is committed only from a real run — do not add a placeholder for
  a scenario that has not been run.
- `RESULTS.md` is in `.prettierignore`; take care not to reformat it.
- If a scenario has no run, say so plainly; that is useful information.

#### docs: state what the fuzz targets assert

Extend `docs/fuzzing.md` with a per-target statement of what each target
asserts, beyond not crashing.

**Why this matters:** The document covers how to run the fuzzers and how a crash
becomes a regression seed. It does not say what each target checks, so a reader
cannot tell which are real property checks and which only test for panics — a
difference that decides how much the suite proves.

**Good first issue.** Entry point: `docs/fuzzing.md`.

_Acceptance criteria_

- One line per target naming its invariants, read from the target's source.
- Targets that only check for panics are identified as such, honestly.
- The list is complete against the targets that exist, verified by enumerating
  them.
- Fits the document's existing structure.

_Implementation guidance_

- Read each target rather than inferring from its name.
- Being honest that a target only checks for panics is the useful part; it
  identifies where to strengthen.
- The document already names six targets — check whether that count is still
  right.

#### docs: README section on what soroauth deliberately does not do

A short README section listing the non-goals, so a reader can rule the library
in or out quickly.

**Why this matters:** The non-goals are real and deliberate — no transaction
builder, no key manager, no interpretation of what a call does — and they are
scattered across doc comments. A reader evaluating the library discovers them by
not finding the feature.

**Good first issue.** Entry point: `README.md`.

_Acceptance criteria_

- Lists the non-goals with one line each on why, and where to look instead.
- Points at `soroauth-explain` for interpretation and at the SDK's `txnbuild`
  for transaction building.
- Placed before the status section, where a reader deciding will reach it.
- Claims nothing about another project that is not true today.

_Implementation guidance_

- These are design decisions, not gaps — the tone should reflect that.
- Check what `soroauth-explain` actually does before describing it.
- Keep it to a short list; this is a filter, not an essay.

#### docs: fix the stale adapter count in the signers guide

Audit `docs/signers.md` against the adapters and signers that now exist, and
correct anything stale.

**Why this matters:** Signers were added across the wave and the guide was
written partway through. A guide that omits a shipped signer sends a reader to
write their own, which is the specific outcome the guide exists to prevent.

**Good first issue.** Entry point: `docs/signers.md`.

_Acceptance criteria_

- Every signer in the root package and every adapter module represented.
- The evidence column accurate for each — what is proven by test, by vector, by
  e2e, or only by hand.
- Any signer whose evidence was overstated is corrected, and the PR says which.
- No signer is claimed to be hardware-tested without a recorded run.

_Implementation guidance_

- Enumerate from the code and the `adapters/` directory, not from the guide.
- The evidence column is the guide's most valuable part; accuracy there matters
  more than completeness of prose.
- An overstatement found here is worth its own commit noting what was wrong.

#### docs: add a short security note about hostile entries

Note in `SECURITY.md` that entries come from elsewhere and state what the
library does to bound that, with pointers.

**Why this matters:** `SECURITY.md` covers reporting and the unaudited status.
The most common real exposure — decoding an entry supplied by someone else — is
handled in the code and not mentioned where a security reader looks.

**Good first issue.** Entry point: `SECURITY.md`.

_Acceptance criteria_

- States that entries are untrusted input and names the bound that applies.
- Points at the decode limits and the adversarial corpus.
- Does not overclaim: says what is bounded and what a caller still must do.
- Consistent with the threat model document if that exists, and flagged for
  reconciliation if not.

_Implementation guidance_

- `decode.go` states the reasoning; cite it rather than restating it.
- Keep it to a paragraph pointing at the real material.
- Do not weaken the existing unaudited statement.

#### docs: date and version every evidence claim in the README

Audit the README's evidence claims — the SDK pin, the protocol version, the
testnet results, the CAP-85 finding — and give each a date or version.

**Why this matters:** The README states facts that were true when checked:
testnet's protocol version, the SDK's contents, that no CAP-85 change is needed.
Without a date each reads as current indefinitely, which for a protocol-tracking
library is how documentation becomes wrong.

**Good first issue.** Entry point: `README.md`.

_Acceptance criteria_

- Every evidence claim carries the date or version it was checked at.
- Any claim that cannot be dated is re-verified and dated, or removed.
- The CAP-85 section states the SDK version its finding applies to.
- No claim's substance changes without the re-verification recorded in the PR.

_Implementation guidance_

- The repo's evidence rule applies to the audit too: re-verify rather than
  copying a date from a commit message.
- If a claim turns out stale, that is its own commit stating what was wrong and
  how you found it.
- Dating a claim is not hedging; it is what makes it checkable.

#### docs: a one-page summary of the signing flow

A single page showing the path from unsigned entry to submitted transaction,
pointing at the function responsible for each step.

**Why this matters:** `ARCHITECTURE.md` maps files to responsibilities and the
README explains the two-pass requirement. Nothing shows the sequence on one
page, which is what a newcomer needs before either document is readable.

**Good first issue.** Entry point: `docs/diagrams/ and ARCHITECTURE.md`.

_Acceptance criteria_

- The full sequence: simulate, choose arm, build preimage, hash, sign, write,
  re-simulate, assemble, submit.
- Each step names the function that does it, verified against the code.
- Fits on one page and links the deeper documents.
- Uses the existing rendered diagrams if they already cover it, rather than
  adding a near-duplicate.

_Implementation guidance_

- Check `docs/diagrams/` first — this may be a short page linking an existing
  diagram rather than new artwork.
- Naming the responsible function is what makes it navigable; verify each
  against the source.
- Do not restate the two-pass explanation; link it.

### `area:testing`

#### test: assert the golden vector set covers every credential arm

A test asserting at least one committed vector exists for each of the four
credential arms.

**Why this matters:** `loadVectors` fails if the directory is empty, which
catches total deletion. It does not catch the loss of every vector for one arm,
and an arm with no vector is an arm with no byte-level proof.

**Good first issue.** Entry point: `golden_test.go`.

_Acceptance criteria_

- Decodes each vector, classifies its arm, and fails naming any arm with no
  coverage.
- Reports the per-arm count, so thinning is visible before it reaches zero.
- Fails loudly on an empty vector set rather than passing vacuously.
- Deleting one arm's vectors is demonstrated to fail the test, and not
  committed.

_Implementation guidance_

- Classify by decoding, not by filename; a name is a convention and not
  evidence.
- `golden_test.go` already has the loader and the empty-set guard — extend it.
- The per-arm count in the output is what makes a slow erosion visible.

#### test: assert the sentinel errors are all distinct

A test asserting no two exported sentinel errors are the same value or carry the
same message.

**Why this matters:** There are twenty-nine sentinels matched with `errors.Is`.
Two that compare equal would make a caller's branch silently wrong, and the
existing meta-test checks only that each is mentioned by a test, not that each
is distinguishable.

**Good first issue.** Entry point: `errors_meta_test.go`.

_Acceptance criteria_

- Asserts pairwise inequality by value and by message.
- Reads the sentinel list from `errors.go` rather than a hand-written copy.
- Fails loudly if it finds no sentinels.
- A deliberate duplicate is demonstrated to fail, and not committed.

_Implementation guidance_

- `errors_meta_test.go` already parses `errors.go` with `go/ast` — reuse that,
  do not duplicate the parsing.
- Identical messages on distinct values are also worth catching: they make a
  failure unreadable even when the branch is right.
- Keep the failure output naming both sentinels.

#### test: assert the no-mutation rule for every entry-taking function

A test that passes the same entry to every exported function taking one and
asserts its bytes are unchanged afterwards.

**Why this matters:** The rule is stated in CONTRIBUTING and each function has
its own mutation test. A newly added function inherits neither, and the XDR
types alias pointers and slices by default, so forgetting the deep copy is the
easy mistake.

_Acceptance criteria_

- Enumerates exported functions taking an entry and runs each against a shared
  fixture.
- Asserts the fixture's marshalled bytes are identical afterwards.
- Fails naming any function not covered, rather than silently skipping it.
- Fails loudly if it enumerates nothing.

_Implementation guidance_

- Reflection or AST enumeration both work; AST matches how the other meta-tests
  here are built.
- Functions needing extra arguments can be given a documented default — skipping
  them defeats the purpose.
- A function that mutates its input is a bug to report, not to accommodate in
  the test.

#### test: assert every CLI subcommand accepts --json

A test asserting each subcommand accepts `--json` and emits parseable JSON on
both success and failure.

**Why this matters:** `--json` is documented as the consistent contract across
subcommands, and consistency is asserted per subcommand where someone
remembered. A new subcommand can ship without it and nothing fails.

**Good first issue.** Entry point: `cmd/soroauth/main_test.go`.

_Acceptance criteria_

- Iterates the dispatcher's subcommands rather than a hand-written list.
- Asserts parseable JSON on success and on an induced error.
- Subcommands for which `--json` is meaningless are excluded explicitly with a
  reason.
- Fails loudly if it finds no subcommands.

_Implementation guidance_

- `TestSpecsCoverTheUsageText` shows how to enumerate subcommands from the real
  source.
- Error output must stay on stdout in JSON mode with stderr empty — that is the
  existing contract, so assert it.
- Explicit exclusions, not silent ones.

#### test: assert the fuzz seed corpora are valid and non-empty

A test asserting each fuzz target's seed corpus exists, is non-empty, and parses
as the Go corpus format.

**Why this matters:** Go reads seeds only from `testdata/fuzz/<TargetName>/`,
and a misnamed directory or a malformed file is silently ignored. The fuzzer
then starts from nothing and still reports success, which is indistinguishable
from a working corpus.

**Good first issue.** Entry point: `testdata/fuzz/`.

_Acceptance criteria_

- Asserts a non-empty corpus directory for every fuzz target in the repository.
- Asserts each seed file parses as `go test fuzz v1`.
- Fails naming any target with no corpus, including one added later.
- A deliberately misnamed directory is demonstrated to fail, and not committed.

_Implementation guidance_

- Enumerate the targets from the source so a new one is covered automatically.
- `cmd/gencorpus` writes the corpus — reuse its understanding of the format
  rather than reimplementing the parser.
- `docs/fuzzing.md` lists the targets; verify that list is still accurate while
  you are here.

### `area:tooling`

#### chore: add the workflow's own path to every paths filter

Audit every workflow with a `paths:` filter and confirm each lists its own file,
adding it where missing.

**Why this matters:** Four workflows were fixed for this, which means the rule
exists and nothing enforces it. A workflow added later with a `paths:` filter
and no self-reference cannot validate its own edits — exactly how a new job once
reached main unexecuted.

**Good first issue.** Entry point: `.github/workflows/`.

_Acceptance criteria_

- Every `paths:`-filtered workflow lists its own path.
- A check or test that fails when one does not, so the rule holds without
  vigilance.
- The PR reports which workflows were missing it.
- CONTRIBUTING's 'Editing a workflow' section is accurate afterwards.

_Implementation guidance_

- CONTRIBUTING's 'Editing a workflow' section explains why; this makes it
  enforced rather than advisory.
- A small script or Go test over the workflow files is enough — no new CI job,
  given the check-count cap.
- If every workflow already complies, ship the check anyway; that is the
  deliverable.

#### chore: a make target that lists every check with its command

Extend `make help` to list every check the project runs and the exact command
for each.

**Why this matters:** `make help` lists the Makefile's targets. Several checks
CI runs are not targets — prettier, cspell, the link check — so the help output
is not a complete answer to 'what do I need to pass'.

**Good first issue.** Entry point: `Makefile`.

_Acceptance criteria_

- Lists every check with its command, including those not wrapped by a target.
- Says which gate a merge and which are advisory.
- Generated from one source, so a new check appears without a second edit.
- The output fits a terminal screen.

_Implementation guidance_

- Coordinate with the run-everything-CI-runs target so there is one list, not
  two.
- Distinguishing required from advisory is the useful part — the repo caps PR
  checks at three for a reason.
- Keep it readable: a wall of text is not help.

#### chore: .gitignore entries for the generated build outputs

Audit `.gitignore` against what the build and test targets actually produce, and
add anything missing.

**Why this matters:** The build produces `bin/`, wasm output, a parity venv,
Rust `target/` and a tools directory. Anything missing from `.gitignore` shows
up as untracked noise, and untracked noise is how a generated artifact gets
committed by accident.

**Good first issue.** Entry point: `.gitignore`.

_Acceptance criteria_

- A clean checkout stays clean after `make`, `make wasm`, `make parity` and
  `make e2e`.
- `git status` is empty after each, demonstrated in the PR.
- Nothing currently tracked is newly ignored.
- `node_modules` and every tool cache covered.

_Implementation guidance_

- Run each target and read `git status`; do not reason about what they might
  produce.
- Check `cspell.json`'s `ignorePaths` for a list of generated directories as a
  starting point.
- Take care not to ignore a committed generated artifact such as the vectors or
  the fuzz corpora.

#### chore: make the e2e suite report its skip reasons

Make every skip in the e2e suite state why, so a passing run with no scenarios
is distinguishable from a real pass.

**Why this matters:** The suite needs a reachable RPC, friendbot and a built
contract. A missing prerequisite that produces a silent skip makes the suite
report success for doing nothing, which is the worst possible outcome for the
only tests that touch a real network.

**Good first issue.** Entry point: `e2e/e2e_test.go`.

_Acceptance criteria_

- Every skip names the missing prerequisite.
- A summary line reports how many scenarios ran and how many skipped.
- A run where everything skipped is not reported as a pass.
- `e2e/README.md` states the prerequisites the suite checks.

_Implementation guidance_

- `golden_test.go` fails rather than skipping when it finds no vectors — the
  same reasoning applies here.
- The count summary is what makes a silent skip visible in CI logs.
- A skip is legitimate; a silent one is not.

#### chore: add a dependabot group for the adapter modules

Group the adapter modules' dependency updates so cloud SDK bumps arrive as one
pull request per module rather than several.

**Why this matters:** There are three adapter modules each depending on a large
cloud SDK. Ungrouped, a single SDK release produces a run of near-identical pull
requests, and a wave of those is how an auto-merging bot broke main twice.

**Good first issue.** Entry point: `.github/dependabot.yml`.

_Acceptance criteria_

- Updates grouped per module, with the grouping documented in the config.
- The pinned reference SDK's existing ignore rules are unchanged.
- A comment explaining why grouping matters here.
- The config validates and every existing ecosystem entry still works.

_Implementation guidance_

- `.github/dependabot.yml` already covers nine ecosystems and ignores the pinned
  JS SDK — do not disturb those rules.
- Each adapter has its own `go.mod`, which is why they are separate ecosystems
  today.
- Keep the pinned-generator ignores exactly as they are; they protect the
  correctness gate.

#### chore: assert the CLI prints no secret on any error path

A test that runs every subcommand's error paths with a recognisable secret in
the environment and asserts it appears in no output.

**Why this matters:** The rule that the CLI never prints a secret is stated in
`main.go`'s package comment and enforced by review. A test makes it enforced by
the build, and the error paths are where a value leaks into a message by
accident.

**Good first issue.** Entry point: `cmd/soroauth/main_test.go`.

_Acceptance criteria_

- Runs every subcommand with a distinctive seed in the environment and asserts
  it appears in neither stream.
- Covers usage errors, decode errors and signing refusals, not just the success
  path.
- Iterates the dispatcher's subcommands so a newly added one is covered
  automatically.
- Fails loudly if it finds no subcommands, so it cannot pass vacuously.

_Implementation guidance_

- `runCLIEnv` already injects a fake environment — use it rather than touching
  the real one.
- Iterating the dispatcher is what makes this durable; a hand-written list will
  go stale.
- Check the error value's text too, not only the streams, since `main` prints
  it.

#### chore: record the tool versions a CI run used

Print the resolved versions of Go, Node, Rust, stellar-cli and the pinned SDKs
at the start of each CI job.

**Why this matters:** Several pins are floors rather than exact versions, and
`check-latest` is set on the Go setup. When a job fails on a runner and passes
locally, the first question is which versions ran, and the logs do not say.

**Good first issue.** Entry point: `.github/workflows/`.

_Acceptance criteria_

- Each job logs the versions relevant to it, early enough to be visible before a
  failure.
- Covers the adapter modules' own toolchains, which may differ from the root's.
- Also surfaced in the job summary, not only the log.
- No secret or token is printed.

_Implementation guidance_

- A Dependabot bump once took an adapter to a newer Go floor than the root —
  that is the case this makes diagnosable.
- Keep it to a few lines per job; verbose output defeats the purpose.
- The job summary is where a reviewer will actually look.
