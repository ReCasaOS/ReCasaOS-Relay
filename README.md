# recasaos-relay

Open-source relay for [ReCasaOS](https://github.com/ReCasaOS) fleets: [Headscale](https://headscale.net) + a DERP relay + a small Go enrolment service that creates an isolated private network per fleet of boxes.

Licence: Apache 2.0.

## Run

```
docker compose up -d
```

Set `server_url` in `headscale/config.yaml` to your public https URL. Port 8080 is served by the `front` Caddy service, which forwards to Headscale but answers 404 on `/api/` (Headscale's admin REST API shares its control-plane port); the gRPC API (50443) is never published. Only the enrolment service reaches the admin APIs, directly on the compose network.

`front` (8080) and the enrolment service (8081) speak plain HTTP: put a TLS reverse proxy in front of both. Keep `/api/` unreachable from outside if you route to Headscale some other way.

## Configuration (enrolment service, environment)

| Variable | Default | Meaning |
|---|---|---|
| `NODES_PER_FLEET` | `50` | max boxes per fleet |
| `CREATE_RATE_PER_HOUR` | `5` | fleet creations per hour per IP |
| `KEY_RATE_PER_HOUR` | `30` | join-key requests per hour per fleet |
| `JOIN_KEY_TTL` | `24h` | validity of a join key |
| `IDLE_AFTER` | `720h` | an idle fleet is deleted after this long |
| `LOGIN_SERVER` | empty | login server URL handed to boxes |
| `LISTEN_ADDR` | `:8081` | listen address |

## Development

```
go vet ./... && go test ./... && docker compose config -q
```
