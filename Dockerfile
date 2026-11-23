# syntax=docker/dockerfile:1

# Builds the soroauth CLI and the verification service. The image entrypoint is
# the CLI; a deployment that wants the HTTP service overrides the command with
# /usr/local/bin/soroauth-server (the Helm chart does this). Both binaries share
# one image so the image the release signs and attests is the image the chart
# deploys.
#
# This image never bakes in a key: soroauth sign reads a secret seed from a
# named environment variable at run time (--secret-env), the same as running the
# binary directly, and the seed should be injected by whatever starts the
# container (e.g. `docker run -e`, a CI secret, or an orchestrator's secret
# store) rather than baked into the image or this Dockerfile.
FROM golang:1.26.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/soroauth ./cmd/soroauth \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/soroauth-server ./server

# distroless/static has no shell, no package manager, and nothing beyond the
# CA certificates and the binary itself — nothing to attack besides
# soroauth's own code, which is the point of a minimal release image.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/soroauth /usr/local/bin/soroauth
COPY --from=build /out/soroauth-server /usr/local/bin/soroauth-server
ENTRYPOINT ["/usr/local/bin/soroauth"]
