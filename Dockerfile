# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Ryvex control plane image (issue #35).
#
# Build:  docker build -t ryvex .
# Run:    docker run -p 8080:8080 ryvex                      # memory store
#         (the docker-compose.yml wires the postgres store for you)
#
# Stage 1 builds BOTH binaries (ryvexd control plane + ryvex CLI) with
# CGO_ENABLED=0 so they are fully static: the runtime stage needs no
# libc at all. Stage 2 ships alpine:3.21 rather than distroless because
# busybox already provides wget, which powers the /healthz probe below
# with zero extra packages.
# ---------------------------------------------------------------------------

# ---- Stage 1: build --------------------------------------------------------
# golang:1.24-alpine matches the `go 1.24` directive in go.mod; the alpine
# variant keeps the build stage small. CI can stamp a release version by
# appending -X main.Version=<ref> to the ldflags.
FROM golang:1.24-alpine AS build

WORKDIR /src

# Cache module downloads independently of source changes: editing Go
# files does not invalidate the module layer.
COPY go.mod go.sum ./
RUN go mod download

# Only the Go workspace reaches the builder — .dockerignore keeps
# console/, agent/, sdk/, docs/, .git and local env files out.
COPY . .

# -trimpath strips absolute paths (reproducible builds); -s -w drops the
# symbol table and DWARF (smaller images).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
        -o /out/ryvexd ./cmd/ryvexd && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
        -o /out/ryvex ./cmd/ryvex

# ---- Stage 2: runtime -------------------------------------------------------
FROM alpine:3.21

# ca-certificates: outbound TLS (postgres sslmode=verify-full, NATS TLS,
# webhook egress). wget is already present via busybox.
RUN apk add --no-cache ca-certificates && \
    addgroup -S ryvex -g 10001 && \
    adduser -S -H -u 10001 -G ryvex -s /sbin/nologin ryvex

COPY --from=build /out/ryvexd /usr/local/bin/ryvexd
COPY --from=build /out/ryvex  /usr/local/bin/ryvex

# ryvexd writes nothing to local disk (state lives in postgres, logs to
# stderr), so the process needs no writable home and no volumes here.
USER ryvex

# ryvexd listens on :8080 by default (override with RYVEX_HTTP_ADDR);
# `serve` is the default subcommand so a bare `docker run` just works.
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ryvexd"]
CMD ["serve"]

# Probe the unauthenticated /healthz endpoint every 10s (start-period
# covers postgres migrations on first boot). Busybox wget varies across
# versions, so write the body to /dev/null instead of relying on
# --spider. NOTE: if you override RYVEX_HTTP_ADDR to change the port,
# override this probe too (docker run --health-cmd ...).
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
