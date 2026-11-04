# syntax=docker/dockerfile:1
#
# Hedioum Pool Tunnel — minimal, static, multi-arch image.
#
# Build (single arch, host arch):
#   docker build -t ghcr.io/hedioum/pool-tunnel:latest .
#
# Build (multi-arch, requires buildx):
#   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
#       -t ghcr.io/hedioum/pool-tunnel:latest --push .
#
# Run the Iran hub with TUN mode (needs NET_ADMIN + the tun device):
#   docker run -d --name hedioum --restart unless-stopped \
#       --cap-add NET_ADMIN --device /dev/net/tun \
#       -v /etc/hedioum:/etc/hedioum \
#       -p 127.0.0.1:40001:40001 ghcr.io/hedioum/pool-tunnel:latest
#
# SOCKS-only (no TUN) needs neither the cap nor the device.
# One-off config, writing into the mounted volume:
#   docker run --rm -v /etc/hedioum:/etc/hedioum ghcr.io/hedioum/pool-tunnel:latest \
#       setup-iran --alias FR --token <pairing-token> --socks-port 40001 --tun --dns

# ---- build stage ----
FROM --platform=$BUILDPLATFORM golang:1.26.10 AS build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# GOARM is only consulted for arm/v7; harmless otherwise.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    GOARM=$(echo "${TARGETVARIANT}" | tr -d 'v') \
    go build -trimpath -ldflags="-s -w -X main.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        -o /out/hedioum-tunnel ./cmd/hedioum

# ---- runtime stage ----
FROM scratch
# CA roots so the TLS mimic / egress can validate real certificates.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/hedioum-tunnel /usr/local/bin/hedioum-tunnel
VOLUME ["/etc/hedioum"]
ENTRYPOINT ["/usr/local/bin/hedioum-tunnel"]
