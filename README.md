# recasaos-relay

Open-source relay for [ReCasaOS](https://github.com/ReCasaOS) fleets: [Headscale](https://headscale.net) + a DERP relay + a small Go enrolment service that creates an isolated private network per fleet of boxes.

Licence: Apache 2.0.

## Run

```
docker compose up -d
```

Set `server_url` in `headscale/config.yaml` to your public https URL. Port 8080 is served by the `front` Caddy service, which forwards to Headscale but answers 404 on `/api/` (Headscale's admin REST API shares its control-plane port); the gRPC API (50443) is never published. Only the enrolment service reaches the admin APIs, directly on the compose network.

`front` (8080) speaks plain HTTP and serves both Headscale and the enrolment API (`/v1/*`): put a TLS reverse proxy in front of it (the enrolment service's own port 8081 is not published). Keep `/api/` unreachable from outside if you route to Headscale some other way.

### Headscale API key

The enrolment service talks to Headscale's REST API with an API key you create once, after Headscale is up:

```
docker compose up -d headscale
docker compose exec headscale headscale apikeys create
```

Put the printed key in a `.env` file next to `compose.yaml` as `HEADSCALE_API_KEY=...` (keep it secret; Headscale API keys expire after 90 days by default: rotate with `headscale apikeys create` and `apikeys expire`), then `docker compose up -d`.

### Rate limits and the proxy header

Fleet creation is limited per client IP (per /64 for IPv6). The enrolment service (port 8081) is **never published**: the `front` Caddy forwards `/v1/*` to it and sets `X-Client-IP` from its own view of the connection (`header_up` replaces whatever the client sent), and compose sets `TRUSTED_PROXY_HEADER=X-Client-IP`. A client can therefore neither choose its own bucket nor fill someone else's. Do not add a `ports:` entry for `enrolment`, and do not route to it any other way, unless that route also sets the header.

- With `TRUSTED_PROXY_HEADER` empty the TCP peer address is used, which is safe from spoofing but only right when clients connect directly.
- If you put **another** TLS proxy in front of Caddy, Caddy would see that proxy's address for everyone. Tell Caddy to trust it so `{client_ip}` becomes the real client, in the `Caddyfile` global options: `servers { trusted_proxies static <proxy-ip-or-cidr> }` (and make that proxy send `X-Forwarded-For`). Use only the addresses of proxies you control.
- `/healthz` of the enrolment service is internal only (not routed by `front`).

## Configuration (enrolment service, environment)

| Variable | Default | Meaning |
|---|---|---|
| `NODES_PER_FLEET` | `50` | max boxes per fleet |
| `CREATE_RATE_PER_HOUR` | `5` | fleet creations per hour per IP |
| `KEY_RATE_PER_HOUR` | `30` | join-key requests per hour per fleet |
| `JOIN_KEY_TTL` | `24h` | validity of a join key |
| `IDLE_AFTER` | `720h` | an idle fleet is deleted after this long |
| `LOGIN_SERVER` | empty | login server URL handed to boxes |
| `HEADSCALE_URL` | `http://headscale:8080` | Headscale REST API, reachable only on the compose network |
| `HEADSCALE_API_KEY` | none, required | Headscale API key (see below) |
| `STORE_PATH` | `/data/relay.db` | SQLite file (a volume in compose) |
| `TRUSTED_PROXY_HEADER` | empty (compose: `X-Client-IP`) | header set by the trusted proxy in front of the service; its last value is the client IP used for rate limits. Empty: the TCP peer address is used |
| `LISTEN_ADDR` | `:8081` | listen address |

## Development

```
go vet ./... && go test ./... && docker compose config -q
```
