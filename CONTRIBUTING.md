# Contributing to soroauth

## Overview

## Your first contribution, in ten steps

The rest of this document is long because it carries the reasoning behind each
rule. This checklist is the short path to a green pull request; each step links
the section that explains it.

- [ ] **1. Pick an issue and get assigned.** Comment on it and wait. Complexity
      and area labels are what work is chosen from — see
      [Picking up an issue](#picking-up-an-issue).
- [ ] **2. Clone and run the suite before changing anything**, so you know a
      later failure is yours: `git clone … && cd soroauth-go && go test ./...`.
      Go 1.26.3 or later is the only requirement for the library and CLI — see
      [Setup](#setup).
- [ ] **3. Branch.** Name it after the work, not the issue number alone:
      `docs/161-onboarding-checklist`, `feat/entry-diff`.
- [ ] **4. Write the test first where you can.** A test that cannot fail reads
      as evidence and is worse than none; if you expect a failure, assert
      _which_ failure — see [What a change needs](#what-a-change-needs).
- [ ] **5. Cite anything you claim about the protocol.** A doc comment, README
      line or commit body that states host behaviour needs the CAP, the
      `rs-soroban-env` file and function, or the SDK file and line. Not memory.
- [ ] **6. Never hand-edit a golden vector.** If your change moves the bytes,
      regenerate with `make vectors` and say in the commit body which CAP
      requires the move — see [Golden vectors](#golden-vectors).
- [ ] **7. Run `make`** — that is `fmt`, `vet` and `test`. If you touched any
      Markdown, also run `npx prettier --write '**/*.md'`, because the build
      checks it. `golangci-lint run ./...` is a local gate worth running too —
      see [Make targets](#make-targets) and [Running Tests](#running-tests).
- [ ] **8. Commit in conventional form**, lowercase and imperative, one logical
      unit per commit, with the command you ran and its real output in the body
      — see [Commit format](#commit-format).
- [ ] **9. Open the pull request** with one `Closes #<n>` line per issue it
      resolves, what you changed, and how you verified it. A space-separated
      list (`Closes #1 #2`) links only the first issue, and a closing line added
      after the pull request is merged closes nothing, so write them before the
      merge — otherwise an issue the work delivered stays open. Two checks gate
      the merge: `vet and test` and `golden vectors are reproducible`.
- [ ] **10. If the work turned out larger than its complexity label**, say so on
      the issue rather than absorbing it silently.

One thing that is not on the list: do not report a signature-correctness or
key-handling bug in a public issue or pull request. See
[Security Issues](#security-issues).

## Picking up an issue

Issues carry a complexity label and an area label, and those two are how work is
chosen; complexity is also what an issue's Stellar Wave points are counted from.
What each label means, who applies it, and who has the final say on complexity
is documented in [docs/labels.md](docs/labels.md).

## Setup

```sh
git clone https://github.com/soroauth/soroauth-go
cd soroauth-go
go test ./...
```

That is the whole setup for the library and CLI. Go 1.26.3 or later.

The pinned `github.com/stellar/go-stellar-sdk` version and the policy for moving
it live in [docs/sdk-support.md](docs/sdk-support.md).

Two optional pieces need more:

- **Regenerating golden vectors** needs Node (>= 22.12.0, what
  `@stellar/stellar-sdk@17.1.0` declares).
- **Running the e2e tests** needs Rust 1.93.0 (pinned in
  `e2e/contracts/rust-toolchain.toml`, rustup will fetch it) and `stellar-cli`
  28.0.0 (pinned in `e2e/contracts/stellar-cli.version`). See
  [the fixture contract quickstart](docs/fixture-quickstart.md) for a
  step-by-step build and deploy guide from a clean checkout.
- **Working on the wallet SDK adapter** (`adapters/walletsdk`) needs nothing
  extra, but it is a module of its own with its own test loop; run
  `cd adapters/walletsdk && go test ./...`.
- **Running the Python parity harness** needs Python 3.10+ and the pinned SDK in
  `testdata/parity-python/requirements.txt`; `make parity` creates a venv and
  installs it. The differential fuzzing harness reuses the same venv and SDK:
  `make differential`.
- **Working on the WebAssembly core or the TypeScript wrapper** needs Node (the
  same 22+ the rest of the tooling uses). `make wasm-check` builds the module
  and proves it byte-identical to the golden vectors; `make ts-test` typechecks
  and tests the wrapper package.

### Dev container (optional)

If you would rather not install those toolchains, `.devcontainer` describes a
container with Go, Node, Rust and `stellar-cli` already installed, for VS Code's
Dev Containers or GitHub Codespaces. It is an option, not required: the local
instructions above stay the reference, and nothing here assumes you use it.

Its versions are never typed into the container's files. `go.mod`, the
`rust-toolchain.toml` files, `testdata/gen/package.json` (Node's `engines`) and
`e2e/contracts/stellar-cli.version` are read when the image is built, so
changing a pin changes the container, and every download is checked against a
published or committed checksum. When you bump `stellar-cli`, update
`e2e/contracts/stellar-cli.sha256` with the new release's sums for both Linux
architectures. `bash .devcontainer/verify.sh` inside the container checks that
every tool is the pinned version and that `make`, `make vectors-check` and the
build half of `make e2e` work from a clean start (the e2e scenarios themselves
need testnet). The `ci / devcontainer` workflow builds the container and runs
that script when a pin or the container changes, and weekly, so it cannot rot
silently.

## Make targets

The Makefile wraps the common tasks, so the commands below exist in one place
rather than across several documents. Run `make help` for the list.

| Target               | What it runs                                                                                          |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| `make` (default)     | `fmt`, `vet` and `test`                                                                               |
| `make fmt`           | fails if `gofmt -l .` reports anything                                                                |
| `make vet`           | `go vet ./...`                                                                                        |
| `make test`          | `go test ./...`                                                                                       |
| `make coverage`      | measures test coverage and enforces the per-package floors in `testdata/coverage/floors.json`         |
| `make ci-local`      | runs everything CI runs, in CI's order, with CI's commands; skips are reported with their reason      |
| `make soak`          | runs the long-running batch signing soak (race detector on, `SOAKTIME`, default 2m)                   |
| `make build`         | builds the CLI to `bin/soroauth`                                                                      |
| `make vectors`       | `cd testdata/gen && npm ci && node gen.mjs && node gen-passkey.mjs`                                   |
| `make vectors-check` | regenerates the vectors and fails if the committed files changed                                      |
| `make demo-check`    | checks the browser demo's logic against the pinned SDK (`node examples/browser-passkey/app.test.mjs`) |
| `make e2e`           | builds the test contract with `stellar-cli` and runs `go test -tags e2e -v ./e2e/...`                 |
| `make parity`        | installs the pinned Python SDK into `.venv-parity` and runs the parity harness and its tests          |
| `make parity-rust`   | runs the Rust stellar-xdr parity harness and its tests (needs Rust 1.93.0)                            |
| `make differential`  | regenerates the differential fuzzing corpus and checks it with the Go, JS and Python implementations  |
| `make wasm`          | builds the js/wasm signing core to `wasm/dist/`                                                       |
| `make wasm-check`    | builds the wasm core and replays every golden vector through it                                       |
| `make ts-test`       | typechecks and tests the `@soroauth/wasm` TypeScript package                                          |
| `make clean`         | removes `bin/`, the wasm build output and the parity venv                                             |

No target hides a failure. `make fmt` exits non-zero when a file needs
formatting instead of printing a warning, `make vectors-check` exits non-zero
when regeneration changes a committed vector, and `make e2e` refuses to run
without `stellar-cli` rather than failing later with an obscure test error.

`make` is the fast loop and stays that way. A branch can pass it and still fail
on push, because CI also runs the vector drift check, the adapter modules, the
parity suites, the wasm replay, prettier, cspell and the link check. Run
`make ci-local` before pushing to run all of it, in CI's order, with CI's
commands: it reads the `run:` steps out of `.github/workflows` and executes
them, so a step added to a workflow runs there without editing the Makefile. It
is slow and wants the optional toolchains. A job whose tool is missing, or that
cannot run on a laptop (publishing a release, live testnet, anything needing
secrets), is listed as skipped with the reason in the final summary and is never
passed silently; `make ci-local CI_LOCAL_FLAGS=-strict` turns any skip into a
failure, and `CI_LOCAL_FLAGS=-list` shows what would run. The CI steps are
classified in `scripts/cilocal/manifest.json`, and `go test ./scripts/cilocal`
(part of `make test` and of CI) fails when a workflow gains a job or step the
manifest does not account for, so add a new job there when you add it to a
workflow. `make ci-local-check` runs only that drift check.

## What a change needs

A change is ready for review when its behavior is covered by a test that would
fail without the change, exported APIs explain their purpose and constraints,
and protocol claims cite the source that supports them. Changes to authorization
entries must preserve caller input, and errors must be returned rather than
silently ignored.

Run the relevant checks in [Running Tests](#running-tests) and include the exact
commands and outcomes in the pull request. When editing a README example, update
both its source and its fenced block as described in
[Verifying README snippets compile](#verifying-readme-snippets-compile).

## Adding Recipes

When adding a new recipe to the README:

1. Create a new Go file in `internal/readmesnippets/` with a
   `// snippet:start <name>` / `// snippet:end <name>` marker pair.
2. The code between markers must be a complete, compiling program (not a
   fragment).
3. Add the snippet name and source file to `readme_test.go` in the
   `readmeSnippets` variable.
4. Add the ```go code block to `README.md` in the appropriate location (after
   the existing blocks, maintaining order).
5. Run `go test -run TestReadmeSnippetsMatchTheirSource -v` to verify all blocks
   match.

**Golden vector rule**: Never edit a vector by hand. If a golden vector needs
updating, regenerate it with `make vectors` and commit the new JSON. The CI
drift check (`make vectors-check`) will fail if the Go code produces different
output.

## Regenerating Golden Vectors

Vectors are generated in `testdata/vectors/` by `gen.mjs` using
`@stellar/stellar-sdk@17.1.0`.

```bash
# Install dependencies
cd testdata/gen && npm ci

A CI failure from the `bench` job is a `FAIL` line naming the operation and arm,
the measured value, and the committed baseline, with the benchmark path on the
following line:

```

FAIL verification/delegates allocs/op 49 > baseline 10 benchmark
BenchmarkVerifyEntry/delegates (143581 ns/op)

````

The two commands above, run from the repository root, reproduce it locally —
`checkbench` exits 1 exactly as CI does. Once you can see _which_ operation and
arm regressed, find out _where_ the allocations come from:

```sh
go test -run '^$' -bench BenchmarkXDRCopy -benchmem -count=1 -memprofile /tmp/mem.out .
go tool pprof -alloc_objects -top /tmp/mem.out   # rank by number of allocations
go tool pprof -alloc_space  -top /tmp/mem.out    # rank by bytes
````

The signing-path entries (`AuthorizeEntry`, `AuthorizeAll`) also include ed25519
signing and SHA-256; `BenchmarkXDRCopy` isolates the deep copy, so a regression
that moves both almost always starts in `internal/xdrcopy`.

The `BenchmarkXDRCopy` budgets are deliberately tighter than the ~40% policy:
they sit **below** what a copy cost before the round-trip buffers were pooled
(issue #108), so reverting that pooling fails this gate instead of only a local
run. If they fail after a change that never touched `internal/xdrcopy`, profile
with the commands above before moving the number, and if the new cost is
justified, raise it in the same commit with the measurement in the body.

## Verifying README snippets compile

The README's Go examples (Quickstart, Delegates, and the inline `AllowResign`
snippet) are not free-standing markdown text: each is extracted verbatim from a
real, compiling source file in `internal/readmesnippets/`, between a
`// snippet:start <name>` and `// snippet:end <name>` comment pair.
`TestReadmeSnippetsMatchTheirSource` in `readme_test.go` at the repository root
asserts the fenced code block in README.md is byte-identical (modulo
tabs-vs-spaces) to that marked region. The guides under `docs/` — `passkeys.md`,
`migrating.md` — are checked the same way by
`TestGuideSnippetsMatchTheirSource`.

This means two different things can fail, and the test names which:

- **The snippet source stops compiling.** It is an ordinary package with no
  build tag, so `go build ./...` and `go vet ./...` — which CI already runs on
  every push — catch this like any other compile error, naming the file and
  line.
- **The README drifts from its source**, for example a hand-edit to the fenced
  block without updating `internal/readmesnippets/`, or the reverse.
  `TestReadmeSnippetsMatchTheirSource` fails and prints both texts.

To reproduce either failure locally:

```sh
go build ./...                        # catches a snippet that no longer compiles
go test -run TestReadmeSnippets -v .  # catches README/source drift, naming the snippet
```

To change an example, edit the marked region in `internal/readmesnippets/*.go`
and copy it verbatim (as, or converted from, tabs) into the matching fenced
block in README.md. Never edit the fenced block alone: it is not the source of
truth, and the drift test will fail on the next run.

## Protocol version matrix

`ArmProtocolVersion` (`protocolmatrix.go`) and the README's "Protocol version
support" table both claim the same thing — which Stellar protocol version each
credential arm requires — sourced from each arm's CAP preamble (CAP-46-11 for
the source-account and legacy arms, CAP-71-01 and CAP-71-02 for V2 and the
delegates arm). `TestArmProtocolVersionMatchesTheReadme` in
`protocolmatrix_test.go` parses the README table and fails if its numbers
disagree with `ArmProtocolVersion`, and `TestArmProtocolVersionMatchesTheCAPs`
pins `ArmProtocolVersion` itself to the values read directly from the CAPs.

To reproduce a failure locally:

```sh
go test -run TestArmProtocolVersion -v .
```

Changing a protocol version claim means updating both `protocolmatrix.go` and
the README table together, in the same commit, and citing the CAP text that
justifies the change — never editing one side to make the test pass.

## GitHub Actions are pinned to commit SHAs

Every `uses:` in `.github/workflows/*.yml` names a full commit SHA with the
version in a trailing comment, e.g. `actions/checkout@3d3c42e… # v7`, never a
mutable tag like `@v7`. A major-version tag can be retagged to point at a
different commit; pinning to the SHA means a compromised or retagged action
cannot silently start running with this repository's CI permissions.

Dependabot (`.github/dependabot.yml`) watches the `github-actions` ecosystem and
opens a PR updating both the SHA and its version comment together when a new
release comes out, so the two can never drift apart. To pin a new action by
hand, resolve the tag to a commit first:

```sh
git ls-remote --tags https://github.com/<owner>/<repo> | grep 'refs/tags/v7$'
```

Use the first column's SHA (for an _annotated_ tag, `git ls-remote` also prints
a `refs/tags/v7^{}` line — use that dereferenced commit SHA, not the tag
object's own SHA).

## Editing a workflow

Two things about `.github/workflows/*.yml` that are easy to get wrong, because
neither produces an error.

**A `paths:` filter produces no check at all**, not a skipped one. A workflow
that does not match is simply absent from the pull request, so a failure in it
is invisible during review and is inherited by `main` on merge. That is how
`spellcheck` stayed red across three merges: #286 added a word to this file, the
workflow is `paths:`-filtered, and there was no row to look at. An `if:`-gated
_job_ still reports a row; a `paths:`-filtered _workflow_ does not.

So when you check whether a branch is green, list runs per workflow rather than
reading the pull request's checks:

```sh
for f in .github/workflows/*.yml; do
  gh run list --branch main --workflow "$(basename "$f")" --limit 1 \
    --json conclusion,headSha,displayTitle
done
```

**Every filtered workflow trigger must include its workflow's own path.** The
root Go test
[`TestPathFilteredWorkflowsIncludeTheirOwnPath`](workflow_paths_test.go) parses
each workflow and fails when any `paths:` list omits its own path. Without that
line a change to a workflow cannot validate itself: #294 changed only
`ci-adapters.yml`, matched nothing in that workflow's own filter, and landed on
`main` with its new job never having run once. If you add a workflow with a
`paths:` filter, include its own path in every filtered event.

### Release attestations and signatures

Every release artifact is attested and signed, and the way to check that is a
script rather than prose, so it can run in CI:

- `scripts/verify-release.sh` verifies a downloaded release: every binary
  against its `.sigstore.json` bundle (cosign, keyless) and its build provenance
  attestation (`gh attestation verify`), every attached `.spdx.json` SBOM
  against its SBOM attestation, and the container image digest the release
  names. `--tamper-demo` flips one byte in a verified binary and requires
  **both** paths to reject the copy, because a check nobody has seen reject
  something is not evidence.
- The `verify-release` job in `.github/workflows/release.yml` runs the script
  against the release it just published, so a release whose assets do not verify
  stays red instead of being announced.
- `.github/workflows/verify-release.yml` re-runs it weekly against the newest
  release that carries bundles (releases from before the scheme are skipped with
  a message, not failed). Its `self_test` dispatch input builds a throwaway
  binary from any ref and runs the same script plus the tamper demo on the run's
  own OIDC identity — that is the evidence to attach to a pull request that
  touches this scheme:

  ```sh
  gh workflow run verify-release.yml --repo <owner>/soroauth-go \
    --ref <branch> -f self_test=true
  ```

Signing is keyless: the certificate comes from the workflow's GitHub OIDC
identity, so no key exists in CI to leak or rotate. The flip side is that an
action added to a job that can mint an OIDC token in these workflows runs with
that identity and writes attestations under it, which is one more reason every
new action must be SHA-pinned as described above — and why the verification
commands in the README and in `scripts/verify-release.sh` pin the _identity_
(this repository's workflow at a tag), not a key.

## Golden vectors

`testdata/vectors/*.json` are generated, committed artefacts. They are the
evidence that soroauth agrees byte-for-byte with the reference implementation.

**Never edit a vector by hand.** Not to fix a failing test, not to adjust a
field, not for anything. A hand-edited vector is a test that has been made to
agree with the code instead of the other way round, which is precisely the
failure the vectors exist to prevent. CI regenerates them on every push and
fails if the committed files differ, so an edit will be caught — but the reason
not to do it is that it destroys the evidence, not that you will be caught.

There are two generators, because there are two things being proven:

- `gen.mjs` writes `testdata/vectors/*.json`, the authorization-entry vectors,
  against a pinned `@stellar/stellar-sdk`.
- `gen-passkey.mjs` writes `testdata/vectors/passkey/*.json`, the passkey
  signature-shape vectors, against a pinned `smart-account-kit`. The passkey
  shape is not protocol-defined — a custom account's `__check_auth` decides it —
  so there is no CAP to cite and the evidence is a real wallet library's output
  instead.

If you discover a vector discrepancy (e.g. the Go output does not match the JS
SDK), **do not edit the vector by hand**. Instead, open a new issue using the
"Vector discrepancy report" template at
`.github/ISSUE_TEMPLATE/vector-discrepancy.md`. This template collects both
encodings, both implementation versions, the vector name, and the command that
produced the disagreement. Prominently states that no vector may be edited by
hand. Route to maintainers at the appropriate severity.

To change them, change the generator:

```sh
cd testdata/gen
npm ci
node gen.mjs

# Run the drift check (compares Go output against vectors)
make vectors-check
```

**Important**: The generator refuses to run if the loaded SDK version is not
exactly `17.1.0`. The `sdk` field in each generated JSON records the actual
version loaded.

## Running Tests

```bash
# Run all unit tests (no network)
go test ./...

# Run the README snippet test specifically
go test -run TestReadmeSnippetsMatchTheirSource -v

# Run e2e tests (requires testnet RPC)
go test -tags e2e ./e2e/...

# Run the vet check
go vet ./...
```

## Running the E2E tests

E2E tests (build tag `e2e`) interact with Stellar testnet. Each scenario:

1. Funds accounts via friendbot
2. Reads the RPC URL from `SOROAUTH_RPC_URL` (default:
   `https://soroban-testnet.stellar.org`)
3. Verifies the RPC is reachable with a live call
4. Builds, signs, and submits a transaction
5. Polls until the transaction is done
6. Logs the transaction hash, ledger, credential arm, and explorer link
7. Appends results to `e2e/RESULTS.md`

**Scenarios**:

- **A**: Legacy arm signing accepted live
- **B**: V2 arm accepted live
- **C**: `AccountMultiSigner` accepted live
- **D**: Delegates arm accepted live
- **E**: Host rejects unregistered delegate
- **F-I**: Session keys and M-of-N delegation fixtures
- **J-Q**: Passkey signing scenarios
- **L-N**: Expiration and nonce replay scenarios

Results are stored in `e2e/RESULTS.md` with date and protocol version.

## Commit Format

Follow conventional commits, lowercase and imperative:

```
feat(authorize): add ForAddress option for delegate nodes
test(golden): add vector 9 byte-for-byte verification
docs(readme): add quickstart 20-line example
ci: add golden drift check job
chore: pin js reference SDK to 17.1.0
```

No force-pushes. Never commit secrets. Test keys are derived from public labels.

## Vector Generation Workflow

1. Run `make vectors` to regenerate `testdata/vectors/*.json`
2. Run `make vectors-check` to verify Go output matches vectors
3. If drift is detected, investigate the Go code change and update vectors if
   protocol-approved
4. Commit all changes (vectors, go.mod, go.sum, README.md, readme_test.go)

**Never edit a golden vector by hand** - it constitutes a wire-format
regression.

## License

This project is Apache-2.0 licensed. See `LICENSE` for details.

## No per-file license headers

The repository-wide [LICENSE](LICENSE) applies to source files. They do not
carry individual license headers by design.

## Security Issues

Report security issues via GitHub Security Advisories. Do not create public
issues for security bugs. The scope includes signature-correctness bugs
(critical), not documentation improvements or feature requests.

## Questions?

Open an issue or start a discussion in the GitHub repository.
