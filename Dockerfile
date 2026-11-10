# Pinned by digest (multi-arch index); bump tag and digest together.
FROM golang:1.26.10@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
# CMD picks the binary: enrolment (default) or share.
ARG CMD=enrolment
RUN CGO_ENABLED=0 go build -o /app ./cmd/${CMD}
# The store directory: SQLite in WAL mode needs to create relay.db-wal and -shm next to the file.
RUN mkdir /data

# :nonroot runs as uid/gid 65532. A fresh named volume mounted on /data takes this directory's owner.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /app /app
COPY --from=build --chown=65532:65532 /data /data
EXPOSE 8081
ENTRYPOINT ["/app"]
