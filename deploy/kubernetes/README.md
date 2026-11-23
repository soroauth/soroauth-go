# Plain Kubernetes manifests

The Helm chart in
[`../helm/soroauth-verification`](../helm/soroauth-verification) is the
reference deployment. These manifests are the same workload in plain YAML, for
an environment that does not use Helm: a Deployment, two Services, a ConfigMap,
and a PodDisruptionBudget.

The bearer token is a reference, never a value. Create the Secret first:

```sh
kubectl create namespace soroauth
kubectl -n soroauth create secret generic soroauth-auth \
  --from-literal=auth-token="$(openssl rand -hex 32)"
kubectl apply -k deploy/kubernetes
```

The Deployment runs `/usr/local/bin/soroauth-server` from the published image,
binds `:8080`, and reads `AUTH_TOKEN` from `soroauth-auth`. The service refuses
to start a non-loopback bind without that token, so a missing or empty Secret is
a failing pod rather than an open service.

`/healthz` is the readiness and liveness endpoint. It needs no token, so a probe
never spends a caller's rate budget. The metrics listener is `:9090` and its
Service is separate from the API.
