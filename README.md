# recasaos-relay

Open-source relay for [ReCasaOS](https://github.com/ReCasaOS) fleets: [Headscale](https://headscale.net) + a DERP relay + a small Go enrolment service that creates an isolated private network per fleet of boxes.

Licence: Apache 2.0.

## Run

Full guide for an operator (requirements, TLS, settings, upgrades, backups, pointing boxes at it): **[docs/self-hosting.md](docs/self-hosting.md)**. The server must be reachable by the member boxes from the Internet; a relay behind CGNAT cannot be self-hosted.

```
docker compose up -d headscale
docker compose exec headscale headscale apikeys create   # then .env: HEADSCALE_API_KEY=... and LOGIN_SERVER=https://<your domain>
docker compose up -d
curl -fs localhost:8080/health      # Headscale's health endpoint, through `front`: {"status":"pass"}
```

The enrolment service exits until `HEADSCALE_API_KEY` and `LOGIN_SERVER` are set, so create the key first (see "Headscale API key" below); a plain `docker compose up -d` before that leaves `enrolment` restarting until the next `up -d`. Set your public https URL as `HEADSCALE_SERVER_URL` on the `headscale` service in a Compose override rather than editing `server_url` in `headscale/config.yaml` (the variable overrides it and `git pull` stays clean: [docs/self-hosting.md](docs/self-hosting.md#2-first-start)), and the same URL as `LOGIN_SERVER`. Port 8080 is served by the `front` Caddy service, which forwards to Headscale but answers 404 on `/api/` (Headscale's admin REST API shares its control-plane port); the gRPC API (50443) is never published. Only the enrolment service reaches the admin APIs, directly on the compose network.

`front` (8080) speaks plain HTTP and serves both Headscale and the enrolment API (`/v1/*`): put a TLS reverse proxy in front of it (the enrolment service's own port 8081 is not published), or let `front` do TLS itself with Caddy automatic HTTPS (a validated Caddyfile and Compose override are in [docs/self-hosting.md](docs/self-hosting.md#3-tls)). Keep `/api/` unreachable from outside if you route to Headscale some other way.

### Headscale API key

The enrolment service talks to Headscale's REST API with an API key you create once, after Headscale is up:

```
docker compose up -d headscale
docker compose exec headscale headscale apikeys create
```

Put the printed key in a `.env` file next to `compose.yaml` as `HEADSCALE_API_KEY=...`, with `LOGIN_SERVER=https://<your domain>` (keep the key secret; Headscale API keys expire after 90 days by default: rotate with `headscale apikeys create` and `apikeys expire`), then `docker compose up -d`.

### Rate limits and the proxy header

Fleet creation is limited per client IP (per /64 for IPv6, and in addition per /48 at 10 times `CREATE_RATE_PER_HOUR`, so a subscriber holding many /64s cannot multiply the limit freely). The enrolment service (port 8081) is **never published**: the `front` Caddy forwards `/v1/*` to it and sets `X-Client-IP` from its own view of the connection (`header_up` replaces whatever the client sent), and compose sets `TRUSTED_PROXY_HEADER=X-Client-IP`. A client can therefore neither choose its own bucket nor fill someone else's. Do not add a `ports:` entry for `enrolment`, and do not route to it any other way, unless that route also sets the header.

- With `TRUSTED_PROXY_HEADER` empty the TCP peer address is used, which is safe from spoofing but only right when clients connect directly.
- If you put **another** TLS proxy in front of Caddy, Caddy sees that proxy's address for everybody until you tell it to trust it, and trusting it is only safe if the client cannot choose the address. Checked with Caddy 2.10.0 (throwaway container, `{client_ip}` echoed back):
  - Without `trusted_proxies`, `X-Forwarded-For` is ignored: `{client_ip}` is the proxy's address for every client (one shared bucket).
  - With `trusted_proxies static` covering the sender, `X-Forwarded-For: 9.9.9.9, 8.8.8.8` gives the LEFTMOST value, `9.9.9.9`. If the outer proxy appends to the header, that value is client-controlled and the rate limit can be bypassed. (nginx's `$proxy_add_x_forwarded_for` appends; that nginx behaviour was not run here.)
  - With `trusted_proxies static` plus `trusted_proxies_strict`, the same header gives `8.8.8.8`, the rightmost value not belonging to a trusted proxy (also for `9.9.9.9, 8.8.8.8, <trusted>`).
  - With `trusted_proxies static` and a header holding a single value, that value is used.

  So use one of these setups, and in both cases Caddy needs `trusted_proxies` listing the outer proxy:

  1. The outer proxy **overwrites** `X-Forwarded-For` with the real client address (it must not append), and Caddy has `trusted_proxies static <outer-proxy-ip-or-cidr>`. For nginx this should be `proxy_set_header X-Forwarded-For $remote_addr;` (not run here; check it against your proxy).
  2. Caddy parses the header right to left. In the global options block of the `Caddyfile` (next to `auto_https off`):

     ```
     {
     	auto_https off
     	servers {
     		trusted_proxies static <outer-proxy-ip-or-cidr>
     		trusted_proxies_strict
     	}
     }
     ```

     (This block, with a CIDR in place of the placeholder, was validated and adapted by `caddy validate` / `caddy adapt` on 2.10.0 together with this repository's `Caddyfile`.)

  List only the addresses of proxies you control.
- Known limit (reported, not verified here): published ports reached over IPv6 may arrive at Caddy through Docker's userland proxy on Linux (always on Docker Desktop), so `{client_ip}` would be the proxy's address for every such client and they would share one rate-limit bucket. A possible workaround, equally untested here: terminate IPv6 at the outer proxy and have it reach `front` over IPv4 with one of the setups above.
- `/healthz` of the enrolment service is internal only (not routed by `front`).

## Configuration (enrolment service, environment)

| Variable | Default | Meaning |
|---|---|---|
| `NODES_PER_FLEET` | `50` | max boxes per fleet; a join key is refused (409) when enrolled nodes plus unused, unexpired join keys reach it |
| `MAX_FLEETS` | `1000` | fleets the relay holds at most; beyond it fleet creation answers `503` without calling Headscale (sizing: see "Capacity" below) |
| `MAX_PENDING_KEYS` | `5` | unused, unexpired join keys a fleet may hold at once, whatever `NODES_PER_FLEET` leaves: one more is refused (409). A key request also deletes the fleet's used and expired keys (sizing: see "Capacity") |
| `CREATE_RATE_PER_HOUR` | `5` | fleet creations per hour per IP (IPv6: per /64); an IPv6 /48 also gets at most 10 times this in all (fixed factor) |
| `KEY_RATE_PER_HOUR` | `30` | join-key requests per hour per fleet (counted once the fleet secret is verified) |
| `AUTH_RATE_PER_HOUR` | `60` | authenticated fleet requests (join key, status, node and fleet deletion) per hour per client IP, counted BEFORE the secret is checked, wrong or right; boxes behind one NAT share it |
| `JOIN_KEY_TTL` | `24h` | validity of a join key |
| `IDLE_AFTER` | `720h` | a fleet with no online node for this long is deleted by the janitor |
| `GC_INTERVAL` | `10m` | how often the janitor runs (see below) |
| `LOGIN_SERVER` | none, **required** | login server URL handed to boxes: your public `https://` URL with no path, the same as Headscale's `server_url`. The service refuses to start if it is empty or not such a URL |
| `HEADSCALE_URL` | `http://headscale:8080` | Headscale REST API, reachable only on the compose network |
| `HEADSCALE_API_KEY` | none, required | Headscale API key (see below) |
| `STORE_PATH` | `/data/relay.db` | SQLite file (a volume in compose) |
| `TRUSTED_PROXY_HEADER` | empty (compose: `X-Client-IP`) | header set by the trusted proxy in front of the service; its last value is the client IP used for rate limits. Empty: the TCP peer address is used |
| `LISTEN_ADDR` | `:8081` | listen address |

### Capacity

Two things Headscale handles in one piece grow with the number of fleets, and both pass through its gRPC layer, which refuses a message over 4 MiB (measured by the review: a policy for 25,000 fleets was refused; 15,000 fleets made a 3.3 MB policy whose `PUT` took 7.8 s, against a 10 s policy-hook timeout):

- the **pre-auth key list**: `GET /api/v1/preauthkey` has no user filter, so every quota check reads every fleet's keys, about 400 B of JSON each. A fleet holds at most `MAX_PENDING_KEYS` keys in that list: unused unexpired keys are capped there, and each key request deletes the fleet's used and expired ones (the janitor also does every `GC_INTERVAL`). Worst case `MAX_FLEETS` x `MAX_PENDING_KEYS` x 400 B = 1000 x 5 x 400 B = **2,000,000 B (1.9 MiB)** with the defaults;
- the **access policy**: about 207 B per fleet, 207 kB for 1000 fleets (`TestDefaultsKeepHeadscaleMessagesUnder3MiB` builds it), pushed whole after every creation and deletion.

The defaults keep both under 3 MiB (the test above fails otherwise). They were chosen against the alternatives: 5000 fleets would allow only 1 pending key per fleet (5000 x 1 x 400 B = 2 MB), so a box owner whose join failed once could not add a box for a day; 2000 x 5 x 400 B = 4 MB (3.8 MiB) is too close to it. With 5, an owner adding boxes one at a time (each key is used within minutes, and lives 24 h otherwise) can lose four joins in a day and still go on. If you raise one, lower the other: keep `MAX_FLEETS` x `MAX_PENDING_KEYS` x 400 B well under 4 MiB. Pre-auth keys created by hand for users that are not fleets also count towards that list.

The fleet cap is exact for one enrolment service: creations in flight count against it, so concurrent requests cannot overshoot. Two services sharing one store are not supported.

## Removing nodes and fleets

Both calls take the fleet secret (`Authorization: Bearer ...`) and answer `204` with no body; `401` is a wrong secret, `404` an unknown fleet, `429` the per-IP throttle (`Retry-After`), `502` a Headscale failure, `503` (fleet deletion) the deletion did not finish in time, for instance behind a request for the same fleet: retry.

- `DELETE /v1/fleets/{id}/nodes/{hostname}` removes one node. The hostname is 1 to 63 of `[A-Za-z0-9-]` (else `400`). A hostname that is not a node of the fleet is a success (`204`).
- `DELETE /v1/fleets/{id}` deletes the fleet: its nodes, its Headscale user and keys, then its row, then the policy is rewritten. The secret is only forgotten at the end, so after a `502` the same call can simply be repeated. Once the deletion has completed there is nothing left to authenticate against and a repeat answers `404`: **treat `404` as "already deleted"**.

### Janitor

Every `GC_INTERVAL` the service (1) marks every fleet that has an online node as seen, (2) deletes, with the routine behind `DELETE /v1/fleets/{id}`, the fleets that have had no online node for longer than `IDLE_AFTER` (a fleet whose nodes could not be read in that pass is never deleted), (3) deletes the used and the expired pre-auth keys of all fleets (Headscale never prunes them, and the key quota reads them all), (4) deletes the fleets that have no node at all, were created more than twice `JOIN_KEY_TTL` ago (48 h by default) and hold no unused, unexpired join key, however recently they asked for a key (a key request refreshes the row the `IDLE_AFTER` rule reads, so without this an owner who keeps asking for keys but never enrols a box would keep the fleet forever), and (5) rewrites the access policy, which also repairs a hand edit. Deletions re-check, under the fleet's lock, that the fleet is still idle (or still empty and untouched since the pass began). A failure for one fleet is logged and the pass goes on; a panic in a pass is logged and the next pass runs.

## Fleet isolation

Each fleet is a Headscale user `f-<fleet id>`. The enrolment service owns Headscale's access policy and rewrites it from **all** fleets in its store after every fleet creation and deletion and on every janitor pass: one group per fleet holding only that user, and one rule per group, `accept group:u -> group:u:*`. No wildcard, no autogroup, no rule naming two groups. With zero fleets the policy is an explicit empty `acls` list (a missing policy would allow everything). It is applied, with retries, **before** the service starts listening, and the service exits if it cannot. Do not edit the policy in Headscale by hand: the next sync overwrites it.

## Relayed traffic and quotas

Relayed (DERP) traffic goes through a standalone `derper` and is metered per box and per fleet: set `DERPER_DEBUG_KEY` and read it on `/admin` (observed, not capped). A per-fleet monthly quota that cuts a fleet off is a planned follow-up; the investigation and design are in [docs/metering.md](docs/metering.md).

## Releases

Pushing a tag `v*` runs `.github/workflows/release.yml`: `go vet` and `go test`, then the `enrolment` and `derper` images are built and pushed to `ghcr.io/<owner>/<repository>-enrolment` and `-derper` (lowercased; `ghcr.io/recasaos/recasaos-relay-enrolment` here) tagged with the version and, unless the tag has a `-` suffix (a pre-release), `latest`. It uses only the built-in `GITHUB_TOKEN`. To run the published image instead of building it, see [docs/self-hosting.md](docs/self-hosting.md#using-the-published-image).

## Development

```
go vet ./... && go test ./... && docker compose config -q
```

The isolation proof needs Docker (it starts the stack from `compose.yaml` plus `e2e/compose.e2e.yaml`, a TLS front for `relay.test`, and one tailscaled container per node) and is not part of `go test ./...`:

```
go test -tags e2e ./e2e -run TestFleetsAreIsolated -v -timeout 15m
```

Set `E2E_NEUTRALISE_POLICY=allow-all` to replace the policy mid-test: the test must then fail.
