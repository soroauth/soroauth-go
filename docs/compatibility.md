# Compatibility and deprecation policy

This page describes what a release promises. The project is currently `v0.1.0`:
the pre-1.0 status is real, so consumers should pin a version and run the
frozen-vector and integration tests before upgrading.

## Compatibility surfaces

| Surface       | Promise                                                                                                        | How to detect a change                               |
| ------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Go API        | Exported Go names and their documented semantics remain source-compatible within a minor release.              | `go test`, `go vet`, and the package docs.           |
| Wire output   | Signed preimages, authorization-entry XDR, and assembled transaction bytes must not change accidentally.       | Frozen vectors, parity tests, and the release notes. |
| CLI flags     | Existing commands and flags keep their meaning; a renamed or removed flag is a breaking change.                | `soroauth man`, CLI tests, and the changelog.        |
| JSON          | Object names and documented fields are stable; new fields are additive unless the release notes say otherwise. | CLI JSON tests and the command reference.            |
| Vector schema | Vector files carry a schema version and loaders reject unknown versions.                                       | `make vectors-check` and the vector README.          |
| SDK support   | The supported `go-stellar-sdk` floor and pin are recorded in `docs/sdk-support.md`.                            | The compatibility table and `go.mod`.                |

An implementation detail is not a compatibility promise merely because it is
visible in a log. In contrast, anything a caller must parse, sign, store, or
reproduce is a public surface and must be reviewed as such.

## Versioning

Releases follow Semantic Versioning. Before 1.0, minor releases may still
contain intentional breaking changes, but they must be called out prominently in
`CHANGELOG.md`, with migration guidance when a caller has to change code or
stored data. Patch releases are for fixes that preserve the documented API and
wire behavior. A wire-format correction is treated as security-sensitive even
when its Go signature is unchanged.

The release version is the module tag and the CLI's `version` output. Generated
vectors and protocol references are versioned separately where their schema is
independent of the Go module.

## Deprecation and support

Deprecate an exported name or CLI flag before removing it. The deprecation must
say what replaces it, appear in Go documentation or `soroauth man`, and be
listed in the changelog. Keep the deprecated path working for at least the next
minor release when practical; security fixes may shorten that window, but the
reason must be documented.

The project supports the current release line and the immediately previous minor
line for fixes that affect security or make the documented workflow unusable.
Older lines are best-effort only. A release is not supported merely because its
tag remains downloadable. See `SUPPORT.md` for the reporting channel, and never
include secret seeds in a compatibility report.

## Upgrade checklist

1. Read the release's `CHANGELOG.md` and `docs/sdk-support.md`.
2. Run the frozen-vector, parity, CLI, and integration tests.
3. Compare JSON output and transaction bytes if your application stores either.
4. Re-check the signer and RPC operational assumptions after any adapter or
   verification-service change.
