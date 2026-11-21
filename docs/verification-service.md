# Verification service

`server/` is a small HTTP service around `VerifyEntry` and `Analyze`, for
wallets and custody systems that want a pre-submission check without embedding
Go. `/verify` answers one question per entry — do the signatures on it verify
over the payload it commits to? — with the same verdicts and the same JSON shape
as `soroauth verify --json`. `/risk` returns the structural analyzer's findings
with their stable identifiers and severities, so a reviewer with an entry and a
browser can see what the analyzer sees without linking Go.

## The contract

The HTTP surface — every endpoint, status code, error shape and the exact JSON
schema of a report — is [`server/openapi.yaml`](../server/openapi.yaml). That
document is the source of truth; this page explains the deployment around it
rather than restating it.

The spec is not a description that can drift. The conformance check in
[`server/openapi/`](../server/openapi/README.md) starts the real service, drives
it as a client would, validates every response against the document, and
exercises the client generated from it. A handler change the spec does not
describe fails that check. In particular the verdict enum keeps `cannot_check`
as a distinct value, so a custom account's signature is reported as uncheckable
rather than flattened to a boolean.

## Risk analysis

`POST /risk` runs `soroauth.Analyze` with its documented defaults and returns
the findings, each with an exported `code` (for example
`LEGACY_CREDENTIALS_NOT_ADDRESS_BOUND`), a severity, and its prose. The codes
are the stable identifiers consumers match on; the library exports them and the
OpenAPI schema enumerates them. A single entry answers with one report, an
envelope with an array carrying one-based `operation_index` and `entry_index`.

Every report carries the analyzer's note: findings are heuristics, not a safety
guarantee, and a clean report means no heuristic fired. The limits — what the
analyzer cannot see — are in [`analyzer-heuristics.md`](analyzer-heuristics.md)
and are linked rather than restated. The endpoint does not imply approval.

`/risk` takes the same bearer token and concurrency bound as `/verify`, and its
body is subject to the same `MAX_BODY_BYTES` cap. It shares the request body cap
with verification but not its verdicts: a 200 with a critical finding is a
successful analysis, not a refused request.

## Configuration

Every bound has a default an operator does not have to set. Each is read from
the environment at startup, and a malformed value refuses to start rather than
falling back silently.

| Variable                  | Default           | Meaning                                                                                                                                                                                 |
| ------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ADDR`                    | `127.0.0.1:8080`  | API listen address. A non-loopback host requires `AUTH_TOKEN` (see below).                                                                                                              |
| `METRICS_ADDR`            | `127.0.0.1:9090`  | Prometheus listen address. `off`, `none` or `-` disables the metrics server entirely.                                                                                                   |
| `AUTH_TOKEN`              | unset             | Bearer token(s) `/verify` and `/risk` require. Commas separate tokens; each is a separate rate-limit identity. Unset means no authentication, which is only allowed on a loopback bind. |
| `READ_TIMEOUT`            | `5s`              | Whole-request read deadline.                                                                                                                                                            |
| `READ_HEADER_TIMEOUT`     | `5s`              | Header read deadline, the classic slowloris bound.                                                                                                                                      |
| `WRITE_TIMEOUT`           | `10s`             | Response write deadline.                                                                                                                                                                |
| `IDLE_TIMEOUT`            | `120s`            | Keep-alive idle timeout.                                                                                                                                                                |
| `MAX_BODY_BYTES`          | `1048576` (1 MiB) | Request body cap. An entry that decodes within the library's own depth limit fits well under it.                                                                                        |
| `MAX_CONCURRENT_REQUESTS` | `64`              | In-flight `/verify` handlers. A request over the bound is refused with `503` and `Retry-After`, never queued.                                                                           |
| `RATE_LIMIT_PER_SECOND`   | `50`              | Sustained requests per second per caller. A request over the rate is refused with `429` and `Retry-After` before its body is read.                                                      |
| `RATE_LIMIT_BURST`        | `100`             | Per-caller bucket depth: back-to-back requests allowed after an idle period. Must be at least `RATE_LIMIT_PER_SECOND`.                                                                  |

The graceful-shutdown deadline is fixed at 10s and is not configurable; a signal
drains the API before the metrics listener, so a final scrape still describes a
live process.

## Threat model

The service is hardened for untrusted exposure, but "hardened" is not the same
as "public internet, unexamined". What is now safe and what is still not:

**Safe by construction.**

- **No secret can reach it.** Verification needs public data only — the entry,
  the network passphrase, an optional expiration assertion — so there is no
  field that accepts a seed, nothing is stored, and no key is ever involved. The
  service verifies; it never signs.
- **Bounded input.** The body is capped by `MAX_BODY_BYTES`, and the library
  refuses entries past its own decode-depth and size limits, so a hostile entry
  cannot drive unbounded decoding.
- **Bounded concurrency.** At most `MAX_CONCURRENT_REQUESTS` verifications run
  at once; the rest are refused with `503` rather than piling up and slowing
  every request until the timeout.
- **Bounded request rate per caller.** Each bearer token (or peer host, when no
  token is configured) has its own bucket. A refusal is `429` with
  `Retry-After`, issued before the body is read, so a caller that is over its
  quota never starts a decode. Distinct clients should get distinct tokens; one
  shared token is one shared quota.
- **Bounded time.** Read, header, write and idle deadlines are all set, so a
  stalled or slow request cannot hold a connection open indefinitely.
- **No bytes in the logs.** One structured line is written per request, and it
  carries the method, the matched route, the status, the duration, the response
  size and the peer address — never the request body, the entry, the
  `Authorization` header or the token. A test asserts this.
- **Fail closed on the bind.** A non-loopback address with no `AUTH_TOKEN`
  refuses to start rather than accepting entries from anyone who can reach it. A
  warning nobody reads is how a service ends up on a public interface with no
  authentication.

**Still the operator's concern.**

- **Transport security.** The service speaks plain HTTP. Terminate TLS in front
  of it; a bearer token sent over an unencrypted hop is a bearer token someone
  else can read.
- **DDoS protection.** The per-caller limiter is an application-level fairness
  bound, not a network defense. A caller that changes source addresses or holds
  many credentials is still a job for a CDN or edge rate limiter. The service's
  own bound keeps one caller from starving the rest; it does not absorb a
  volumetric attack.
- **Token issuance, rotation and storage.** `AUTH_TOKEN` is a shared secret the
  service compares in constant time; how it is minted, rotated and delivered to
  callers belongs to the deployment.
- **Launch arguments and container inspection.** An environment variable is
  visible to anything that can inspect the process or container
  (`/proc/<pid>/environ`, `docker inspect`). Treat `AUTH_TOKEN` with the care
  any process environment deserves.

There is no authentication on `/healthz`, so a load balancer's check needs no
token. It reports liveness and the version only.

If signing is ever added to this service, authentication stops being optional:
the token check and its fail-closed bind already assume that, and the metrics
below already carry a signer-latency signal for when it arrives.

## Metrics

The service exposes Prometheus metrics on `METRICS_ADDR`, **separate from the
API port** so it can stay on loopback or a private network and does not have to
be reachable wherever `/verify` is. `off`/`none`/`-` disables the listener.

| Metric                                   | Type      | Labels                       | Meaning                                                                 |
| ---------------------------------------- | --------- | ---------------------------- | ----------------------------------------------------------------------- |
| `soroauth_http_requests_total`           | counter   | `method`, `route`, `status`  | HTTP requests handled.                                                  |
| `soroauth_http_request_duration_seconds` | histogram | `route`                      | Request latency, default buckets.                                       |
| `soroauth_verify_verdicts_total`         | counter   | `credential_type`, `verdict` | One per credential node, by arm and verdict.                            |
| `soroauth_verify_refusals_total`         | counter   | `reason`                     | Verification and transport refusals, by reason.                         |
| `soroauth_signer_duration_seconds`       | histogram | `phase`, `credential_type`   | Signing-phase latency, fed by `soroauth.Hook` events.                   |
| `soroauth_http_limit_rejections_total`   | counter   | `limit`                      | Requests shed by an availability bound (`rate`, `concurrency`, `body`). |

**Every label set is closed.** A value outside the set is clamped to a fallback
rather than creating a new series, so no label can carry an address, a nonce or
any other unbounded string — the usual way a metrics change takes down a
Prometheus. A test walks every gathered series and asserts each label name and
value is in the set the code declares.

- `method`: the standard methods; anything else is `other`.
- `route`: `/verify`, `/risk`, `/healthz`, or `unmatched` — the path is logged
  as the matched route template, so an arbitrary path cannot become a label or a
  log-injection vector.
- `status`: `200`, `400`, `401`, `404`, `405`, `413`, `429`, `500`, `503`;
  anything else is `other`.
- `credential_type`: `source_account`, `address`, `address_v2`,
  `address_with_delegates`, or `unknown`.
- `verdict`: `verified`, `unsigned`, `invalid`, `cannot_check`, or `unknown`.
- `reason`: `invalid`, `cannot_check`, `unsigned`, `expiration_mismatch`,
  `unauthorized`, `method_not_allowed`, `too_large`, `overloaded`, `internal`,
  `bad_request`, `not_found`, `rate_limited`, or `other`.
- `phase`: `preimage`, `sign`, `post_sign`, `write`, or `unknown`.
- `limit`: `rate`, `concurrency`, or `body`.

`cannot_check` is a distinct verdict and a distinct refusal reason: a custom
account whose signature only `__check_auth` can decide is visible as such, not
counted as a pass.

The signer histogram is the bridge to [`hooks.go`](../hooks.go): its only writer
is a `soroauth.Hook` adapter, so metric values come from the one event stream
rather than from instrumenting a signing path separately. The service verifies
rather than signs today, so the histogram is empty until signing is added; the
dashboard's panel says so.

A reference Grafana dashboard is committed at
[`docs/dashboards/soroauth-verification.json`](dashboards/soroauth-verification.json),
and [`docs/dashboards/example-metrics.txt`](dashboards/example-metrics.txt) is
an export from a real run of the endpoint, so the dashboard queries are known to
have data behind them. Import the JSON and point its `DS_PROMETHEUS` input at
the Prometheus scraping `METRICS_ADDR`.

## Running it

```sh
go run ./server                                   # loopback :8080, metrics on 127.0.0.1:9090
ADDR=0.0.0.0:8080 AUTH_TOKEN=$(openssl rand -hex 32) go run ./server   # exposed, authenticated
```

`make server` builds `bin/soroauth-server` with the release version stamped in
(reported by `/healthz` and `soroauth-server version`). The published container
image is CLI-only; serving this over a network is a deployment choice the image
does not make for you.

## Coverage

`server/main_test.go` serves the real routes over `httptest` and covers a signed
entry (verified), a partially signed delegates tree (one verified node, the rest
unsigned), malformed requests (missing fields, non-base64, base64-but-not-XDR,
non-JSON, wrong method), a tampered expiration (invalid), a contradicted
`valid_until_ledger` assertion, and an envelope input with its one-based
positions. The verdicts are asserted against the library's `Verdict*` constants
rather than string literals, so the tests fail if the service ever stops
speaking the CLI's verdicts.

`server/risk_test.go` covers a legacy entry with findings, a clean V2 report
that is an empty array rather than null, the analyzer's note on every report,
and the malformed-request and wrong-method paths. The finding code and severity
are asserted against the library's exported constants.

`server/hardening_test.go` covers the bounds and the fail-closed bind, and
asserts the request log carries no entry bytes or secret.
`server/metrics_test.go` asserts the metric label sets are closed and that the
committed dashboard and example scrape reference the metrics the service
actually emits.
