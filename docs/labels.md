# Issue labels

Contributors pick work by label. Two label families carry the meaning: a
**complexity** label, which says how much Soroban-specific knowledge an issue
needs and is what its points are counted from, and an **area** label, which says
which part of the tree the change lands in. A third family names the kind of
change, and one program label marks an issue as part of a Stellar Wave.

The values below are the ones the repository's own issue tooling creates and
accepts, so they are the source of truth rather than a description written after
the fact: `scripts/wave9_issues.py` (`LABELS`, lines 29-39) and
`scripts/create-issues.sh` (the `create_label` calls, lines 68-76).

## Complexity

Complexity is a rough guide to how much protocol or codebase knowledge an issue
needs, not how long it takes. It is also the value the points come from:
`scripts/wave9_issues.py` maps `high` to 200 points, `medium` to 150 and
`trivial` to 100 (line 27).

| Label                | Points | Means                                                                                              |
| -------------------- | ------ | -------------------------------------------------------------------------------------------------- |
| `complexity:trivial` | 100    | Small and self-contained; no protocol knowledge required.                                          |
| `complexity:medium`  | 150    | A standard feature or an involved fix; needs familiarity with the codebase or the auth flow.       |
| `complexity:high`    | 200    | A new subsystem, an integration, or a refactor; touches signing, the wire format, or cryptography. |

These three are the only values the backlog tooling accepts. Issue creation
aborts on anything else rather than guessing, because a missing or misspelt
complexity label would silently drop the issue out of the points accounting
(`scripts/create-issues.sh`, the `case "$complexity"` block).

## Area

The area label answers "where in this repository, and which reviewer". Each area
maps to the section of `docs/ISSUE_BACKLOG.md` its issues were written in.

| Label               | Covers                                             |
| ------------------- | -------------------------------------------------- |
| `area:signers`      | Signer implementations and the `Signer` interface. |
| `area:testing`      | Golden vectors, fuzzing, parity, benchmarks, e2e.  |
| `area:api`          | The exported library API.                          |
| `area:docs`         | Documentation and guides.                          |
| `area:tooling`      | The CLI, CI, scripts, release automation.          |
| `area:integrations` | WASM, browser, wallets, RPC, fixture contracts.    |
| `area:protocol`     | CAP support and protocol compatibility.            |

## Type

Type labels say what kind of report or change an issue is. The issue templates
apply them automatically, so a reporter does not choose one by hand:

| Label         | Applied by                            | Means                                                                                         |
| ------------- | ------------------------------------- | --------------------------------------------------------------------------------------------- |
| `bug`         | `.github/ISSUE_TEMPLATE/bug.yml`      | Something soroauth does that it should not, or fails to do.                                   |
| `enhancement` | `.github/ISSUE_TEMPLATE/feature.yml`  | Something soroauth should be able to do and cannot.                                           |
| `security`    | `.github/ISSUE_TEMPLATE/security.yml` | A request redirected to private reporting; the label marks that the public template was used. |

A signature-correctness or key-handling problem is not a public `bug`: it goes
through a private Security Advisory, per [SECURITY.md](../SECURITY.md).

## Program

`Stellar Wave` marks an issue as part of a Drips Stellar Wave, the program the
complexity points are counted by; the backlog tooling in `scripts/` exists to
publish the Wave's issues. It is applied to the issue when the Wave is
assembled.

## Good first issue

`good first issue` is GitHub's own newcomer label, carried on top of a
complexity label rather than instead of one. It means a contributor can finish
the issue without any Soroban background, and it is applied only when **both**
of these hold:

- the issue is `complexity:trivial`, and
- finishing it needs no understanding of the signing path — the preimage, the
  payload, the credential arms, the delegate model — or of cryptography. The
  change is confined to documentation, repository meta files, CI configuration,
  or test scaffolding.

A `complexity:trivial` issue that touches `preimage.go`, `authorize.go`,
`delegates.go`, `signer.go` or `batch.go` is small but is **not** a good first
issue, because even a one-line edit there means reading code that encodes the
protocol.

Every labelled issue also names its **entry point**: the one file (or file to
add) where the work starts, rendered into the issue body and written into the
backlog source. An issue with no single entry point is not a good first issue,
however small it is.

The pass is reviewed as the backlog grows. When an issue is added or its scope
changes, re-check its label: a `good first issue` on something that has come to
need the signing path is worse than no label at all.

## Who applies them

- The **maintainer** creates the labels and sets the complexity and area labels
  when an issue is written or triaged. The two label families are created and
  attached by `scripts/create-issues.sh` and `scripts/wave9_issues.py`, and by
  hand for issues that do not come from the backlog.
- The **`good first issue` label** is applied by the maintainer during a
  labelling pass over the backlog, not by the contributor. It is set from the
  `**Good first issue.**` and `**Entry point:**` lines in
  [ISSUE_BACKLOG.md](ISSUE_BACKLOG.md), and from the `good_first_issue` and
  `entry_point` fields in [`WAVE9_BACKLOG.json`](WAVE9_BACKLOG.json), so the
  label and its entry point cannot drift from the issue body.
- The **issue templates** apply the type label when a reporter files a `bug`,
  `enhancement` or `security` issue.
- **Contributors** do not need to set labels. If you think an issue is
  mislabelled, say so in a comment on the issue rather than relabelling it
  yourself.

**The maintainer has final say on complexity.** The label on an issue is the
maintainer's call, and it can be revised at triage. If, once you are in the
code, an issue turns out to be materially larger than its label suggests, say so
on the issue rather than absorbing the difference silently — that is the same
rule the Wave issue bodies carry, and it is how the label gets corrected.
