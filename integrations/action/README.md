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

| Input            | Required | Default                               | Meaning                                                                                                                                                 |
| ---------------- | -------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `entry`          | one of   |                                       | A single base64 authorization entry or transaction envelope. Mutually exclusive with `entry-file`.                                                      |
| `entry-file`     | one of   |                                       | A path or glob to a file of base64 entries, one per line; blank lines are skipped. Mutually exclusive with `entry`.                                     |
| `network`        | yes      |                                       | `testnet`, `futurenet`, `public`, or a literal network passphrase. Passed to both `inspect` and `verify`.                                               |
| `expected-arm`   | no       | `''`                                  | When set, every entry must report this credential arm (`source_account`, `address`, `address_v2`, `address_with_delegates`). A mismatch fails the step. |
| `allow-unsigned` | no       | `false`                               | Accept unsigned nodes, matching the CLI's `--allow-unsigned`. Under CAP-71-01 a delegates entry may legitimately leave its top-level node `Void`.       |
| `image`          | no       | `ghcr.io/soroauth/soroauth-go:latest` | The image providing the CLI. Pin it by digest for a reproducible review.                                                                                |

Exactly one of `entry` or `entry-file` is required. `entry-file` accepts a glob,
so a repository can check every committed entry with one step.

## No secret is ever an input

Authorization entries are public data: they carry signatures, never a seed. The
action has no input that could hold a seed, and it only ever calls `inspect` and
`verify`, which read public data and sign nothing. The one command that reads a
secret — `soroauth sign --secret-env` — is deliberately not exposed here. Do not
try to route a secret through `entry` or `entry-file`: it has nowhere to go and
the CLI would reject it as an undecodable entry.

## Output

The action writes workflow annotations and prints a one-line summary per entry.
It declares no outputs; gate on its exit status. A step is green only when every
entry decoded, matched `expected-arm` when given, and verified (or was accepted
as unsigned under `allow-unsigned`).

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
