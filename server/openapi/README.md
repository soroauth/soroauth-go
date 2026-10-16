# Verification service OpenAPI spec

The committed OpenAPI document for the verification service is
[`../openapi.yaml`](../openapi.yaml). It is the source of truth for the HTTP
surface — every endpoint, status code and error shape — and
[`docs/verification-service.md`](../../docs/verification-service.md) links it
rather than restating it.

This directory holds the tooling that proves the running service matches the
document:

| Path                   | What it is                                                                   |
| ---------------------- | ---------------------------------------------------------------------------- |
| `conformance_test.go`  | Starts the real server and validates every response against the spec.        |
| `client/client.gen.go` | The client generated from the spec. Never edited by hand.                    |
| `generate.sh`          | Regenerates `client/`; CI runs it and fails if the committed client differs. |
| `cfg.yaml`             | The `oapi-codegen` configuration for the client.                             |

## Why a module of its own

The OpenAPI toolchain and the validation library are dependencies the server
does not need to run. Keeping them in a nested module means the root module's
dependency graph — and the container image built from it — never carries them.
The root module's `go test ./...` therefore does not run these tests;
[`.github/workflows/ci-openapi.yml`](../../.github/workflows/ci-openapi.yml)
does, and `make openapi-test` runs them locally.

## What the conformance check is, and is not

It is not a YAML linter. It builds the server binary, starts it on an ephemeral
loopback port with an auth token and a single concurrency slot, then drives it
as a client would:

- every declared operation and error status is exercised, and each response is
  validated against the spec (`additionalProperties: false`, so a new or renamed
  field fails);
- the client generated from the spec is exercised against the live process, for
  both the single-entry object and the envelope array;
- at the end, every operation in the spec must have been visited, so a newly
  declared endpoint without a case fails rather than going untested;
- a test asserts the verdict enum still carries `cannot_check` as a distinct
  value, so the honesty boundary cannot be flattened to a boolean by a spec
  edit.

## Running it

```sh
cd server/openapi
./generate.sh   # regenerate client/ after editing ../openapi.yaml
go test ./...   # the conformance check
```

`make openapi-check` runs both the regeneration diff and the conformance test,
which is what CI runs.
