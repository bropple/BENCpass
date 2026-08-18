# bencpass-server.
#
# The final stage is `scratch` — no shell, no libc, no package manager, nothing
# to patch. That is only possible because the server is pure Go with no cgo,
# makes no outbound TLS calls (so it needs no CA bundle) and uses UnixMilli
# throughout (so it needs no tzdata).

# --platform=$BUILDPLATFORM pins the build stage to the machine doing the
# building, and Go then cross-compiles to $TARGETARCH. Without it, buildx runs
# the whole compiler under qemu emulation for the foreign architecture, which is
# both far slower and an extra dependency to install.
# Pinned to the patch, not the minor. govulncheck found four standard-library
# advisories -- crypto/tls, net/http, html/template, encoding/asn1 -- all fixed
# in 1.26.6, and a floating `golang:1.26-alpine` had been quietly building the
# published image against a toolchain that carried them.
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src

COPY go.mod ./
COPY *.go ./
COPY static/ ./static/

# CGO_ENABLED=0 is what makes the binary static. Lose it and the scratch image
# starts, fails to find a dynamic loader, and exits with nothing in the log
# worth reading.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /bencpass-server .

FROM scratch
COPY --from=build /bencpass-server /bencpass-server

LABEL org.opencontainers.image.title="BENCpass" \
      org.opencontainers.image.description="Self-hosted end-to-end encrypted password sync" \
      org.opencontainers.image.vendor="BENCO Holdings" \
      org.opencontainers.image.licenses="MIT"

# Numeric because scratch has no /etc/passwd to resolve a name against. 568 is
# the `apps` user on TrueNAS SCALE; change it to match whoever owns the dataset
# you mount. A mismatch here is the usual cause of a first run that dies with a
# permission error on /data and nothing else.
USER 568:568

EXPOSE 8788
VOLUME /data
ENTRYPOINT ["/bencpass-server", "-addr", "0.0.0.0:8788", "-dir", "/data"]
