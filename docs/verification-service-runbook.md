# Verification service operator runbook

The verification service is stateless: it accepts public authorization-entry
data, performs offline checks, and returns a report. It does not hold signing
keys and it does not need an RPC endpoint. The service still needs operational
protection because an attacker can submit expensive or malformed input.

## Configuration

| Variable                  | Default          | Effect                                                                       |
| ------------------------- | ---------------- | ---------------------------------------------------------------------------- |
| `ADDR`                    | `127.0.0.1:8080` | API listen address. A non-loopback address requires `AUTH_TOKEN`.            |
| `METRICS_ADDR`            | `127.0.0.1:9090` | Prometheus endpoint; set `off`, `none`, or `-` to disable.                   |
| `AUTH_TOKEN`              | empty            | Bearer token required by `/verify`; never put it in logs or command history. |
| `READ_TIMEOUT`            | `5s`             | Maximum request read time.                                                   |
| `READ_HEADER_TIMEOUT`     | `5s`             | Maximum header read time.                                                    |
| `WRITE_TIMEOUT`           | `10s`            | Maximum response write time.                                                 |
| `IDLE_TIMEOUT`            | `120s`           | Keep-alive idle timeout.                                                     |
| `SHUTDOWN_TIMEOUT`        | `10s`            | Graceful shutdown deadline.                                                  |
| `MAX_BODY_BYTES`          | `1048576`        | Request body cap.                                                            |
| `MAX_CONCURRENT_REQUESTS` | `64`             | Simultaneous verification cap; excess requests receive 503.                  |

Health is `GET /healthz`; metrics are exposed on the metrics listener. The API
contract and response shapes are in `server/openapi.yaml`. Startup refuses a
public bind without authentication, which is an intentional fail-closed rule.

## Signals and alerts

Alert on process restarts, failure of `/healthz`, sustained 5xx responses, 503
responses from the concurrency limit, and a sharp increase in request latency.
Scrape the metrics listener from a trusted monitoring network only. Useful
dimensions include route, HTTP status, verdict, refusal reason, and
signer/verification duration. Do not use request bodies, bearer tokens, or full
entries as metric labels.

## If the service is wedged

1. Check `/healthz`, process memory/CPU, open connections, and the structured
   stderr logs. Confirm the metrics endpoint is still reachable.
2. If 503s are rising, inspect caller volume and concurrency saturation before
   raising `MAX_CONCURRENT_REQUESTS`; a larger limit increases CPU and memory
   exposure.
3. If requests are timing out, capture a redacted request shape and compare the
   verifier latency histogram. Do not copy authorization entries into a public
   ticket unless the entry is intentionally public.
4. Drain the instance with SIGTERM and allow the configured shutdown deadline.
   If it does not exit, terminate it using the supervisor's normal escalation
   policy and start a replacement from the same immutable build.

## If an RPC or signer is unreachable

The HTTP verification service itself does not call an RPC and does not use a
signer. An RPC or signer outage therefore belongs to a caller, the remote
signing example, or the gRPC/other integration that surrounds this service. Do
not add retries or credentials to the verification process to mask that outage.
Check the caller's endpoint, signer health, network policy, and timeout budget;
then re-run the offline `/verify` request separately to distinguish an
operational dependency failure from an invalid entry.

## Deployment assumptions and threat model

Run the API behind a process supervisor or container restart policy, bind it to
loopback unless an authenticated private network is required, and terminate TLS
at a trusted edge. If the API is exposed directly, set `AUTH_TOKEN` and protect
the secret with the deployment platform's secret store. The service limits body
size, timeouts, and concurrency, but it does not provide DDoS protection or
replace network policy.

Requests are untrusted and may be malformed; responses are advisory checks of
the supplied entry, not proof that a transaction will succeed on a particular
ledger. Keep the binary, configuration, and OpenAPI document versioned together.
During incident response, preserve logs and metrics while redacting tokens and
entry payloads.
