# recasaos-relay

Open-source relay for [ReCasaOS](https://github.com/ReCasaOS) fleets: [Headscale](https://headscale.net) + a DERP relay + a small Go enrolment service that creates an isolated private network per fleet of boxes.

Licence: Apache 2.0.

## Run

```
docker compose up -d
```

Set `server_url` in `headscale/config.yaml` to your public https URL (TLS terminated by a reverse proxy in front of port 8080). Headscale's admin API is never published; only the enrolment service reaches it.

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
