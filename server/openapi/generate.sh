#!/usr/bin/env bash
# Regenerates client/client.gen.go from ../openapi.yaml.
#
# The generator version is pinned so the output is reproducible; CI runs this
# and fails if the committed client changed, which is what stops the client from
# drifting from the spec.
set -euo pipefail
cd "$(dirname "$0")"

OAPI_CODEGEN_VERSION=v2.5.1
go run "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" \
  -config cfg.yaml ../openapi.yaml
