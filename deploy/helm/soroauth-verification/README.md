# soroauth-verification Helm chart

Deploys the soroauth verification service (`server/`) from the same signed image
that carries the CLI. The chart is a reference, not a policy engine: it wires
the service's existing readiness, limits, and metrics endpoints; it does not add
an RPC, a signer, or any secret of its own.

## Fail-closed rules

- `auth.existingSecret` is required. The chart refuses to render without it,
  because the service binds a non-loopback address in the pod and its
  configuration refuses that without a bearer token.
- The token is read with `secretKeyRef`. It is never placed in `values.yaml`, a
  ConfigMap, an annotation, or a rendered manifest.
- The API and metrics listeners are separate Services. Metrics are not exposed
  on the API port.

Create the Secret out of band:

```sh
kubectl create namespace soroauth
kubectl -n soroauth create secret generic soroauth-auth \
  --from-literal=auth-token="$(openssl rand -hex 32)"
```

## Install

```sh
helm install soroauth deploy/helm/soroauth-verification \
  --namespace soroauth \
  --set auth.existingSecret=soroauth-auth
```

Pin `image.digest` in production rather than accepting `latest`.

## Values

| Value                            | Default                                            | Meaning                                                           |
| -------------------------------- | -------------------------------------------------- | ----------------------------------------------------------------- |
| `auth.existingSecret`            | `""` (required)                                    | Secret carrying the bearer token.                                 |
| `auth.secretKey`                 | `auth-token`                                       | Key inside that Secret.                                           |
| `service.port`                   | `8080`                                             | API port.                                                         |
| `metrics.enabled`                | `true`                                             | Start the separate metrics listener and Service.                  |
| `metrics.port`                   | `9090`                                             | Metrics port.                                                     |
| `metrics.serviceMonitor.enabled` | `false`                                            | Render a Prometheus Operator `ServiceMonitor`. Requires its CRDs. |
| `config.maxBodyBytes`            | `1048576`                                          | Request body cap.                                                 |
| `config.maxConcurrentRequests`   | `64`                                               | In-flight request cap; excess gets `503`.                         |
| `config.rateLimitPerSecond`      | `50`                                               | Sustained per-caller rate; excess gets `429` with `Retry-After`.  |
| `config.rateLimitBurst`          | `100`                                              | Per-caller bucket depth.                                          |
| `probes.*`                       | see `values.yaml`                                  | Readiness, liveness, and startup probes against `/healthz`.       |
| `resources`                      | 100m/128Mi requests                                | Requests and limits.                                              |
| `podDisruptionBudget.enabled`    | `true`                                             | Keep one replica available during drains.                         |
| `autoscaling.enabled`            | `false`                                            | CPU-based HPA.                                                    |
| `securityContext`                | non-root, read-only root, all capabilities dropped | Container hardening.                                              |

The `config` values map directly to the environment variables in
[`docs/verification-service.md`](../../../docs/verification-service.md); that
page is the contract for their meaning and defaults.

## Validate

```sh
helm lint deploy/helm/soroauth-verification --set auth.existingSecret=soroauth-auth
helm template soroauth deploy/helm/soroauth-verification \
  --set auth.existingSecret=soroauth-auth > /tmp/soroauth.yaml
kubectl apply --dry-run=client -f /tmp/soroauth.yaml
```

The second command without `--set auth.existingSecret=...` must fail; that
refusal is checked in CI.

The smoke test in
[`.github/workflows/ci-deploy.yml`](../../../.github/workflows/ci-deploy.yml)
builds the image, installs this chart into a kind cluster, calls `/healthz`, and
sends one real `/verify` request from a golden vector.
