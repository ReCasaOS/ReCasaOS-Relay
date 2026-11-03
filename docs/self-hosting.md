# Self-hosting a recasaos-relay

This is for an operator who wants to run their own relay and point ReCasaOS boxes at it, instead of using the official one. Everything below was checked against the files of this repository (`compose.yaml`, `Caddyfile`, `headscale/config.yaml`, the Go code); what was run for real is said, what was not is marked "not verified".

## 1. What you need

- A host with Docker and Docker Compose v2.24.4 or later (not verified; older versions may reject `!override` and `!reset`, which the examples use; the repository's own e2e override already uses `!override`).
- **A public IP address with a domain name pointing at it, reachable by every member box.** The boxes connect to your server at enrolment time and afterwards (control plane over HTTPS, relayed traffic over the same port). That is the whole point of a relay: it lets boxes that cannot reach each other find each other. A relay that is itself behind CGNAT, or on a connection with no inbound port, **cannot be self-hosted**: the boxes could never reach it.
- Open to the Internet:
  - `443/tcp` (control plane, enrolment API, embedded DERP relay over HTTPS),
  - `80/tcp` if you use the Caddy automatic HTTPS setup below (certificate issuance and redirect),
  - `3478/udp` (STUN of the embedded DERP; already published by `compose.yaml`).
- Never open `8081` (enrolment service) or `50443` (Headscale gRPC). `compose.yaml` publishes neither.

## 2. First start

```
git clone https://github.com/ReCasaOS/recasaos-relay && cd recasaos-relay
```

(address taken from the Go module path)

1. Set your public URL with the environment variable `HEADSCALE_SERVER_URL=https://relay.example.org` on the `headscale` service, in a Compose override you pass with `-f` (section 3a puts it in `compose.tls.yaml`). It must be the https URL boxes will use. The variable overrides `server_url` of `headscale/config.yaml`, as `e2e/compose.e2e.yaml` does (not run here with a real domain), so the tracked file stays untouched and `git pull` does not conflict. Editing `server_url` in that file works too, but then every `git pull` has to merge your change.
2. Set up TLS (section 3).
3. Start Headscale, create its API key (section 5) and put it in `.env`, together with `LOGIN_SERVER` (section 4).
4. `docker compose up -d` (with the TLS override of section 3 if you use it).

Health check through the front. This is Headscale's own endpoint: the enrolment service's `/healthz` is internal and not routed by `front`, so `/healthz` on `front` answers 404.

```
curl -fs https://relay.example.org/health      # {"status":"pass"}
```

## 3. TLS

The shipped `front` (Caddy) listens on plain `:8080` with `auto_https off`. Boxes need HTTPS (`headscale/config.yaml`: "https is required by the embedded DERP"; the e2e override notes that the tailscale client insists on a TLS control connection). Two ways:

### a) Caddy automatic HTTPS in `front` (simplest)

Create `Caddyfile.tls` next to `compose.yaml`: the shipped `Caddyfile` with `auto_https off` removed and the site address `:8080` replaced by your domain. Replace `relay.example.org`; the e-mail is optional and only used by Let's Encrypt for expiry notices.

<!-- file: Caddyfile.tls -->
```
{
	email admin@example.org
}

relay.example.org {
	@api path /api /api/*
	handle @api {
		respond 404
	}

	handle /v1/* {
		reverse_proxy enrolment:8081 {
			header_up X-Client-IP {client_ip}
		}
	}

	handle {
		reverse_proxy headscale:8080
	}
}
```

and `compose.tls.yaml`, a Compose override that sets the public URL of Headscale, swaps the Caddyfile, publishes 80 and 443 instead of 8080, and keeps the certificates in a volume so they survive a restart (replace `relay.example.org` here too):

<!-- file: compose.tls.yaml -->
```yaml
services:
  headscale:
    environment:
      HEADSCALE_SERVER_URL: https://relay.example.org

  front:
    volumes:
      - ./Caddyfile.tls:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
    ports: !override
      - "80:80"
      - "443:443"

volumes:
  caddy-data:
```

Every Compose command then takes both files:

```
docker compose -f compose.yaml -f compose.tls.yaml up -d
```

Verified: this Caddyfile passes `caddy validate` in a throwaway `caddy:2.10.0-alpine` container (the image of `front`), and the override passes `docker compose -f compose.yaml -f compose.tls.yaml config -q`. **Not verified:** an actual certificate issuance (it needs a real domain pointing at a public host) and a box enrolling through this setup. Here `front` faces the clients directly, so `{client_ip}` is the real TCP peer and no `trusted_proxies` is needed; the IPv6 / Docker userland proxy caveat in the README still applies.

### b) Your own reverse proxy in front of `front`

Point it at host port `8080` (plain HTTP) and have it pass WebSocket / HTTP upgrades through (Headscale's requirement; only Caddy was tried here). Then read ["Rate limits and the proxy header"](../README.md#rate-limits-and-the-proxy-header): Caddy must be told to trust your proxy (`trusted_proxies`) or every client shares one rate-limit bucket, and trusting a proxy that appends to `X-Forwarded-For` lets clients choose their own bucket. Never route `/api/` through it.

## 4. Settings

Put them in a `.env` file next to `compose.yaml` (Compose substitutes them). An unset or empty value takes the default, except `TRUSTED_PROXY_HEADER` (an empty value really is empty); a non-positive number or duration makes the service refuse to start. `.env` is listed in `.gitignore`: never commit it.

| Variable | Default | In `.env`? | Notes |
|---|---|---|---|
| `HEADSCALE_API_KEY` | none, **required** | yes | the service exits without it (section 5) |
| `LOGIN_SERVER` | empty | yes | **set it to your public URL**, the same as `server_url`: it is the `login_server` returned to boxes when a fleet is created. The e2e override sets both to the same URL. Left empty, boxes receive an empty value |
| `NODES_PER_FLEET` | `50` | yes | boxes per fleet |
| `MAX_FLEETS` | `1000` | yes | fleets the relay holds; creation answers 503 beyond. Do not raise it without reading "Capacity" in the README |
| `MAX_PENDING_KEYS` | `5` | yes | unused join keys per fleet at once (409 beyond). Raising it or `MAX_FLEETS`: README, "Capacity" |
| `CREATE_RATE_PER_HOUR` | `5` | yes | fleet creations per hour per client IP (IPv6: per /64, plus 10 times this per /48) |
| `KEY_RATE_PER_HOUR` | `30` | yes | join keys per hour per fleet |
| `AUTH_RATE_PER_HOUR` | `60` | yes | authenticated fleet requests per hour per client IP (boxes behind one NAT share it) |
| `JOIN_KEY_TTL` | `24h` | yes | validity of a join key |
| `IDLE_AFTER` | `720h` (30 days) | yes | a fleet with no online node for this long is deleted |
| `GC_INTERVAL` | `10m` | yes | janitor period |
| `TRUSTED_PROXY_HEADER` | `X-Client-IP` in compose (empty in the binary) | yes | header set by `front`. An empty value in `.env` makes the service use the TCP peer address, which is wrong behind `front`: keep the default |
| `HEADSCALE_URL` | `http://headscale:8080` | no, fixed in `compose.yaml` | Headscale REST API, compose network only |
| `STORE_PATH` | `/data/relay.db` | no, fixed in `compose.yaml` | SQLite file, in the `enrolment-data` volume |
| `LISTEN_ADDR` | `:8081` | no, not passed by `compose.yaml` | never publish it |

What each one does: [README](../README.md#configuration-enrolment-service-environment).

## 5. The Headscale API key

The enrolment service calls Headscale's REST API with an API key you create once:

```
docker compose up -d headscale
docker compose exec headscale headscale apikeys create
```

Put the printed key in `.env` as `HEADSCALE_API_KEY=...` (it is shown only once), then `docker compose up -d`, which recreates `enrolment` with the new value.

The key expires: `apikeys create` defaults to `--expiration 90d` (checked with `headscale apikeys create --help` on the pinned image; pass `--expiration` to choose). Rotate before it expires:

```
docker compose exec headscale headscale apikeys create      # new key: put it in .env
docker compose up -d
docker compose exec headscale headscale apikeys list
docker compose exec headscale headscale apikeys expire --prefix <old prefix>
```

The service applies its access policy at startup, retrying, and exits if it cannot (`cmd/enrolment/main.go`), so a missing or invalid key keeps it from starting. How an expired key shows up on a running service was not exercised.

## 6. Upgrading

Headscale is pinned in `compose.yaml` (`headscale/headscale:v0.29.7`), and the enrolment service's Headscale client was written and checked against that version only; other versions are not verified. To move to another one:

1. Read the Headscale release notes for the versions in between.
2. Back up (section 7). Headscale migrates its database when it starts, and going back to an older version afterwards may not work (general Headscale behaviour, not tested here): the backup is your way back.
3. Change the tag in `compose.yaml`. If you can, run the e2e isolation test on the new tag first; it starts the stack from `compose.yaml`: `go test -tags e2e ./e2e -run TestFleetsAreIsolated -v -timeout 15m`.
4. `docker compose pull && docker compose up -d` (with your `-f` options if any).

The enrolment service is built from this repository: `git pull && docker compose up -d --build`, or use the published image below. `front` is pinned to `caddy:2.10.0-alpine`; the README's proxy-header checks were made with that version.

### Using the published image

Pushing a tag `vX.Y.Z` of this repository publishes `ghcr.io/recasaos/recasaos-relay-enrolment:vX.Y.Z` (and `latest` for a final release, not for a `-rc` tag) through `.github/workflows/release.yml`. To run it instead of building, add `compose.image.yaml`:

<!-- file: compose.image.yaml -->
```yaml
services:
  enrolment:
    image: ghcr.io/recasaos/recasaos-relay-enrolment:v0.1.0 # a tag that has been published
    build: !reset null
```

and pass it as one more `-f compose.image.yaml`; the default `compose.yaml` still builds locally. Nothing is published yet at the time of writing: check that the tag exists. The first GHCR package is private by default (not verified): set it to public in the package settings before operators can `docker pull` it. Validated with `docker compose -f compose.yaml -f compose.image.yaml config`; pulling the image was not tried.

## 7. Backups and restore

State lives in two named volumes (Compose prefixes them with the project name, by default the directory name, e.g. `recasaos-relay_headscale-data`):

- `headscale-data` (`/var/lib/headscale`): `db.sqlite` (users, nodes, access policy, API keys), `noise_private.key`, `derp_server_private.key`. Losing the keys or the database means every box must enrol again.
- `enrolment-data` (`/data`): `relay.db`, the fleets and the hashes of the fleet secrets.

Both SQLite databases run in WAL mode (`*-wal` and `*-shm` files sit next to them), so **stop the services before copying**. This works whatever the project name is, through `--volumes-from`:

```
mkdir -p "$HOME/relay-backup" && chmod 700 "$HOME/relay-backup"      # outside the repository checkout
docker compose stop
docker run --rm --volumes-from "$(docker compose ps -aq headscale)" -v "$HOME/relay-backup:/backup" alpine tar czf /backup/headscale-data.tgz -C /var/lib/headscale .
docker run --rm --volumes-from "$(docker compose ps -aq enrolment)" -v "$HOME/relay-backup:/backup" alpine tar czf /backup/enrolment-data.tgz -C /data .
docker compose start
```

(Use your `-f` options with `docker compose` here too, if any.)

Restore on a fresh host (repository cloned, `.env` and `headscale/config.yaml` in place; they are not in the volumes, so back them up too):

```
docker compose create
docker run --rm --volumes-from "$(docker compose ps -aq headscale)" -v "$HOME/relay-backup:/backup" alpine tar xzf /backup/headscale-data.tgz -C /var/lib/headscale
docker run --rm --volumes-from "$(docker compose ps -aq enrolment)" -v "$HOME/relay-backup:/backup" alpine tar xzf /backup/enrolment-data.tgz -C /data
docker compose up -d
```

Run `create` and `up -d` with your `-f` options (e.g. `-f compose.yaml -f compose.tls.yaml`), otherwise `front` is recreated without TLS. Also back up `Caddyfile.tls` and `compose.tls.yaml` if you use them.

Restore both volumes from the same backup: they describe the same fleets. This cycle was run for real (Docker Desktop, Git Bash): a fleet created through the API, backup, `docker compose down -v`, restore, `up -d`; the fleet's status then answered 200 with its secret and its Headscale user was listed. The backups hold the control plane's private keys: keep them as private as `.env`, and keep them out of the repository checkout (`.gitignore` also lists `*.tgz` as a safety net). **`docker compose down -v` destroys both state volumes** (Headscale database and keys, enrolment SQLite): never run it on a relay without a backup.

## 8. Pointing boxes at it

In ReCasaOS, enter your public URL (`https://relay.example.org`, no path) in the relay URL setting in the Fleet settings (the "Serveur de relais" field of the Fleet dialog). That setting is delivered with the ReCasaOS release that ships the relay support; it is not available before. Changing relay later means the master re-issues its enrolment codes and every member enrols again: there is no migration between relays.

## 9. Operating notes

- **Quotas and limits** (defaults, section 4): 1000 fleets per relay (creation answers 503 beyond), 50 boxes per fleet (a join key is refused with 409 when enrolled nodes plus unused, unexpired keys reach it), at most 5 unused join keys per fleet at once, 5 fleet creations per hour per IP (and 50 per IPv6 /48), 30 join-key requests per hour per fleet, 60 authenticated requests per hour per IP, join keys valid 24 h. Boxes behind one NAT share the per-IP budgets: raise `CREATE_RATE_PER_HOUR` / `AUTH_RATE_PER_HOUR` if one address serves many boxes.
- **Idle deletion:** every `GC_INTERVAL` the janitor deletes fleets with no online node for `IDLE_AFTER` (30 days by default), deletes used and expired pre-auth keys, deletes fleets that never got a node within twice `JOIN_KEY_TTL` (48 h) and hold no pending join key, and rewrites the access policy (README, "Janitor").
- **Isolation:** each fleet is its own Headscale user and the service owns the access policy (deny by default, one rule per fleet).
- **When the relay is down:** new enrolments fail, because the enrolment API and the control plane are both behind `front`. Boxes that already enrolled and have a direct peer-to-peer path do not send that traffic through the server, so those links are expected to keep working for a while; links that go through the relay stop, because the embedded DERP runs inside Headscale. Not verified: no test takes the relay down, so how long existing links last is not measured.
- **Relayed traffic is not capped:** the embedded DERP cannot be metered, so there is no per-fleet traffic quota in this version. What is limited is the number of boxes, the enrolment rate and idle fleets. Watch your host's bandwidth. The investigation and the planned follow-up (a standalone `derper`) are in [metering.md](metering.md).

## 10. Security checklist

- TLS in front of everything. The enrolment API relies on it: a box signature is bearer-like within its ±120 s validity window. While the service runs, each signature is accepted once (replay is refused); a restart forgets which signatures were seen, so a signature captured on the wire can be replayed within the window after a restart.
- Do not add a `ports:` entry for `enrolment` (8081) or Headscale's gRPC (50443). The rate limiter trusts `X-Client-IP`, which only `front` sets, and the admin API has no other protection. `/api/` must stay unreachable from outside (`front` answers 404).
- `X-Client-IP` and `trusted_proxies`: read the README section on the proxy header before putting another proxy in front of `front`.
- Keep `.env` (the API key) out of version control; rotate the key (section 5).
- Do not edit the access policy in Headscale by hand: the next sync overwrites it.
