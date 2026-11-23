# soroauth verify GitHub Action

A composite action that runs [`soroauth inspect`](../../cmd/soroauth/inspect.go)
and [`soroauth verify`](../../cmd/soroauth/verify.go) over one entry or a file
of them, and turns every finding into a GitHub workflow annotation. It gates a
pull request on an authorization entry's structure and signatures without
installing a Go toolchain: the work runs inside the published
[soroauth container image](https://github.com/soroauth/soroauth-go/pkgs/container/soroauth-go).

```yaml
- uses: soroauth/soroauth-go/integrations/action@<commit-sha> # pin by SHA
  with:
    entry-file: fixtures/*.entries
    network: testnet
    expected-arm: address_v2
```

An entry that does not verify fails the step: the action exits non-zero and the
findings appear inline on the diff as `::error` annotations, so a reviewer sees
which node of which entry was `invalid`, `unsigned`, or `cannot_check` without
opening a log.

## Inputs

| Input            | Required | Default                               | Meaning                                                                                                                                                  |
| ---------------- | -------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `entry`          | one of   |                                       | A single base64 authorization entry. A full envelope is accepted for compatibility and handled as one. Mutually exclusive with the other inputs.         |
| `entry-file`     | one of   |                                       | A path or glob to a file of base64 entries, one per line; blank lines are skipped. Mutually exclusive with the other inputs.                             |
| `envelope`       | one of   |                                       | A full base64 transaction envelope. Every authorization entry in it is reported by operation and entry index. Mutually exclusive with the other inputs.  |
| `envelope-file`  | one of   |                                       | A path or glob to a file of base64 envelopes, one per line; blank lines are skipped. Mutually exclusive with the other inputs.                           |
| `network`        | yes      |                                       | `testnet`, `futurenet`, `public`, or a literal network passphrase. Passed to both `inspect` and `verify`.                                                |
| `expected-arm`   | no       | `''`                                  | When set, every entry must report this credential arm (`source_account`, `address`, `address_v2`, `address_with_delegates`). A mismatch fails the step.  |
| `allow-unsigned` | no       | `false`                               | Accept unsigned nodes, matching the CLI's `--allow-unsigned`. Under CAP-71-01 a delegates entry may legitimately leave its top-level node `Void`.        |
| `fail-on`        | no       | `any`                                 | Comma-separated verdicts that fail the step: `any`, `invalid`, `unsigned`, `cannot-check`, `unknown`, `verified`. Applied to every entry of an envelope. |
| `image`          | no       | `ghcr.io/soroauth/soroauth-go:latest` | The image providing the CLI. Pin it by digest for a reproducible review.                                                                                 |

Exactly one of `entry`, `entry-file`, `envelope` or `envelope-file` is required.
The file inputs accept a glob, so a repository can check every committed entry
or envelope with one step.

## Verifying an envelope

An envelope is what a reviewer usually has, and it is the unit the host checks.
Passing one reports every entry it carries, named by operation and entry index
and by address, in the job summary:

```yaml
- uses: soroauth/soroauth-go/integrations/action@<commit-sha>
  with:
    envelope: ${{ steps.simulate.outputs.envelope }}
    network: testnet
    fail-on: unsigned
```

The summary has one row per entry with its arm, address and each credential
node's verdict. An annotation names the same position, so a reviewer can go
straight from the diff to the entry that failed. A source-account entry is
legitimately unsigned — the transaction envelope authenticates it — so it is
reported but never a finding. `fail-on: unsigned` therefore means "any unsigned
address entry", which is the condition a review gate usually wants.

`expected-arm` is applied to each entry of an envelope rather than to the joined
list, so a mixed envelope can still be held to one arm per entry only when every
entry shares it. Leave it empty for an envelope that legitimately carries
several arms.

## No secret is ever an input

Authorization entries are public data: they carry signatures, never a seed. The
action has no input that could hold a seed, and it only ever calls `inspect` and
`verify`, which read public data and sign nothing. The one command that reads a
secret — `soroauth sign --secret-env` — is deliberately not exposed here. Do not
try to route a secret through `entry` or `entry-file`: it has nowhere to go and
the CLI would reject it as an undecodable entry.

## Outputs

| Output    | Meaning                                                                             |
| --------- | ----------------------------------------------------------------------------------- |
| `version` | The exact soroauth build identity (tag, commit, build timestamp, and Go toolchain). |

The action writes workflow annotations, prints a one-line summary per entry,
records its build identity to the job summary (`$GITHUB_STEP_SUMMARY`), and sets
the `version` action output. Gate on its exit status: a step is green only when
every entry decoded, matched `expected-arm` when given, and verified (or was
accepted as unsigned under `allow-unsigned`).

## Runtime and pinning

The action is composite and shells out to `docker run`; it never installs Go.
[`CONTRIBUTING.md`](../../CONTRIBUTING.md) asks this repository's own workflows
to pin every action by commit SHA, and that pin is what makes the action's
behavior fixed rather than moving with a tag. Use the same discipline from a
consuming repository: reference
`soroauth/soroauth-go/integrations/action@<full-commit-sha>`.

For full reproducibility of the CLI itself, pass `image` as a digest rather than
a tag, e.g. `ghcr.io/soroauth/soroauth-go@sha256:…`. The image is signed and
carries provenance; see
[Verifying a release](https://github.com/soroauth/soroauth-go#verifying-a-release).

Example pinning both the action ref and the image digest for reproducible
verification:

```yaml
- uses: soroauth/soroauth-go/integrations/action@3d3c42e5aac5ba805825da76410c181273ba90b1 # pin action by full commit SHA
  with:
    entry-file: fixtures/*.entries
    network: testnet
    expected-arm: address_v2
    image: ghcr.io/soroauth/soroauth-go@sha256:4f83b1c6d3e8e7a68e2f6942054a838be296e8555e1329bfbd03c347f3ff062a # pin image by digest
```
