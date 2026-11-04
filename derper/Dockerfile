# Standalone DERP relay for recasaos-relay: Tailscale's own derper, built from source (Tailscale
# publishes no derper image). Every client is checked against Headscale's /verify, fail-closed.
#
# Checked in the tailscale.com@v1.104.5 source before writing the config (headscale@v0.29.7 for /verify):
# - go.mod:3 `go 1.27.3`: the official golang images set GOTOOLCHAIN=local, so the build stage must be
#   Go 1.27.3 (golang:1.26.10, as in the root Dockerfile, refuses to build it).
# - cmd/derper/derper.go:60,192,438-445: `-a :8090` serves plain HTTP; TLS only on port 443 or with
#   -certmode manual. TLS stays at the operator's proxy, as for the rest of the relay.
# - cmd/derper/derper.go:61,62,84,85: -http-port, -stun-port, -verify-client-url and
#   -verify-client-url-fail-open exist; fail-open DEFAULTS TO TRUE, so compose.yaml sets it false.
# - cmd/derper/derper.go:122-127: without -c, a non-root derper exits ("-c <config path> not specified").
#   Hence -c below and a /var/lib/derper owned by the nonroot user; the server key is regenerated when
#   the container is recreated (clients do not pin it).
# - tsweb/tsweb.go:104-111,129-141: debug pages (/debug/, cmd/derper/derper.go:307 /debug/clients/) open
#   to a GET whose ?debugkey= equals the trimmed content of the file at TS_DEBUG_KEY_PATH (empty key or
#   unset path: never). Without the key, any X-Forwarded-For header is refused, else only loopback,
#   Tailscale IPs, TS_ALLOW_DEBUG_IP and TS_DEBUG_TRUSTED_CIDRS. The front Caddy also answers /debug 404.
# - derp/derpserver/derpserver.go:1141-1152,1200: the server sends its key, reads the client's, runs
#   verifyClient and closes on error, all before ServerInfo. verifyClient (:1789-1821) POSTs to the URL:
#   transport error -> refused unless fail-open, non-200 -> refused, Allow:false -> refused.
# - derp/derp_client.go:128-153: the client handshake ends after sending its key, so Connect succeeds even
#   for a refused key; e2e/derpcheck waits for ServerInfo instead.
# - headscale hscontrol/app.go:591, handlers.go:150-164: POST /verify answers Allow = node key registered.

# Pinned by digest (multi-arch index); bump tag and digest together.
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS build
RUN CGO_ENABLED=0 go install tailscale.com/cmd/derper@v1.104.5
RUN mkdir /state

# :nonroot runs as uid/gid 65532 (same digest as the root Dockerfile).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /go/bin/derper /derper
COPY --from=build --chown=65532:65532 /state /var/lib/derper
EXPOSE 8090 3478/udp
ENTRYPOINT ["/derper", "-c", "/var/lib/derper/derper.key"]
