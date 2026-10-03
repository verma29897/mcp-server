# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage
#
# The tag is pinned to a patched Go release, not to a floating minor version.
# Most of what govulncheck reports against a server like this one is in the
# standard library, so the toolchain version is a security control and belongs
# under the same review as any dependency bump. go.mod pins it too, so a local
# build and a container build agree.
# ---------------------------------------------------------------------------
FROM golang:1.26.6-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download modules.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG VERSION=1.0.0
ARG TARGETOS=linux
ARG TARGETARCH=amd64

# CGO is off so the result is a static binary that runs on scratch.
# -trimpath keeps build paths out of the binary; -s -w drop the symbol table.
# The build is reproducible: no timestamps, no host paths, no VCS stamping.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/mcp-server ./cmd/server

# VERSION is recorded as an image label rather than baked into the binary: the
# identity an MCP client sees comes from MCP_SERVER_VERSION at runtime, and
# having two sources of truth for it is how they end up disagreeing.

# ---------------------------------------------------------------------------
# Runtime stage
#
# scratch, because the server needs no shell, no package manager and no libc.
# The absence of a shell is a control in its own right: an attacker who reaches
# command execution inside this container has nothing to execute.
#
# CA certificates are copied in for the HTTPS backend and the JWKS endpoint.
# ---------------------------------------------------------------------------
FROM scratch

ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="company-mcp-server" \
      org.opencontainers.image.description="MCP server exposing customer and order data as tools, resources and prompts." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Proprietary"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/mcp-server /mcp-server

# Non-root by numeric UID: scratch has no /etc/passwd to name a user in.
# 65532 is the conventional "nonroot" id, which matches distroless if this
# image is ever rebased.
USER 65532:65532

# Defaults suit a remote deployment. Override MCP_TRANSPORT=stdio and run with
# `docker run -i` for a stdio client such as Claude Desktop.
#
# Authentication is deliberately NOT defaulted on: an image that shipped a
# built-in token would ship the same token to every deployment. The server
# refuses to start on HTTP with MCP_AUTH_MODE=none unless the operator sets
# MCP_ALLOW_INSECURE_HTTP=true, so a misconfiguration fails loudly at start.
ENV MCP_TRANSPORT=http \
    MCP_HTTP_ADDR=:8080 \
    MCP_HTTP_PATH=/mcp \
    BACKEND_MODE=memory \
    LOG_LEVEL=info \
    LOG_FORMAT=json

EXPOSE 8080

# No HEALTHCHECK: scratch has no curl or wget. The server serves GET /healthz
# for liveness and GET /readyz for readiness, so configure both probes in your
# orchestrator (see docs/DEPLOYMENT.md).

ENTRYPOINT ["/mcp-server"]
