# Self-hosting a recasaos-relay

This is for an operator who wants to run their own relay and point ReCasaOS boxes at it, instead of using the official one. Everything below was checked against the files of this repository (`compose.yaml`, `Caddyfile`, `headscale/config.yaml`, the Go code); what was run for real is said, what was not is marked "not verified".

## 1. What you need

- A host with Docker and Docker Compose v2.24.4 or later (not verified; older versions may reject `!override` and `!reset`, which the examples use; the repository's own e2e override already uses `!override`).
- **A public IP address with a domain name pointing at it, reachable by every member box.** The boxes connect to your server at enrolment time and afterwards (control plane over HTTPS, relayed traffic over the same port). That is the whole point of a relay: it lets boxes that cannot reach each other find each other. A relay that is itself behind CGNAT, or on a connection with no inbound port, **cannot be self-hosted**: the boxes could never reach it.
- Open to the Internet:
  - `443/tcp` (control plane, enrolment API, DERP relay over HTTPS),
  - `80/tcp` if you use the Caddy automatic HTTPS setup below (certificate issuance and redirect),
  - `3478/udp` (STUN, now served by the `derper` service; `compose.yaml` publishes it).
- Never open `8081` (enrolment service) or `50443` (Headscale gRPC). `compose.yaml` publishes neither.
- Public sharing (section 14, optional) also needs `53/udp` and `53/tcp` on the public IP, and moves `80` and `443` from `front` to `share`.

## 2. First start

```
git clone https://github.com/ReCasaOS/recasaos-relay && cd recasaos-relay
```

(address taken from the Go module path)

1. Set your public URL with the environment variable `HEADSCALE_SERVER_URL=https://relay.example.org` on the `headscale` service, in a Compose override you pass with `-f` (section 3a puts it in `compose.tls.yaml`). It must be the https URL boxes will use. The variable overrides `server_url` of `headscale/config.yaml`, as `e2e/compose.e2e.yaml` does (not run here with a real domain), so the tracked file stays untouched and `git pull` does not conflict. Editing `server_url` in that file works too, but then every `git pull` has to merge your change.
2. Set the relay host of the DERP map the same way: write `derp.local.yaml` (section 3a gives it) with your public relay host, and mount it over `/etc/headscale/derp.yaml` in the same override (`compose.tls.yaml` in section 3a has the line). Every box is told to relay through that host; the tracked `headscale/derp.yaml` ships with `relay.example.org` and stays untouched, so `git pull` does not conflict.
3. Set up TLS (section 3).
4. Start Headscale, create its API key (section 5) and put it in `.env`, together with `LOGIN_SERVER` (section 4).
5. `docker compose -f compose.yaml -f compose.tls.yaml up -d` (your override of steps 1 and 2). Every `docker compose` command in this document takes those `-f` options, or Headscale is recreated with `relay.example.org`.

Health check through the front. This is Headscale's own endpoint: the enrolment service's `/healthz` is internal and not routed by `front`, so `/healthz` on `front` answers 404.

```
curl -fs https://relay.example.org/health      # {"status":"pass"}
```

## 3. TLS

The shipped `front` (Caddy) listens on plain `:8080` with `auto_https off`. Boxes need HTTPS (`headscale/config.yaml`: "https is required: the control plane and DERP run over TLS"; the e2e override notes that the tailscale client insists on a TLS control connection). Two ways:

### a) Caddy automatic HTTPS in `front` (simplest)

Create `Caddyfile.tls` next to `compose.yaml`: the shipped `Caddyfile` with `auto_https off` removed and the site address `:8080` replaced by your domain. Replace `relay.example.org`; the e-mail is optional and only used by Let's Encrypt for expiry notices.

<!-- file: Caddyfile.tls -->
```
{
	email admin@example.org
}

# Only for public sharing (section 14); harmless without `share`. It makes the port-80 server explicit, which
# the `proxy_protocol` wrapper of section 14 needs; Caddy's own HTTP-to-HTTPS redirect answers the shared names.
http://*.box.example.org {
	redir https://{host}{uri} 301
}

relay.example.org {
	@debug path /debug /debug/*
	handle @debug {
		respond 404
	}

	# /internal/* (the enrolment service's share routes) is deliberately not routed either: it falls through
	# to Headscale and answers 404, like /api. Only services on the compose network reach it.
	@api path /api /api/*
	handle @api {
		respond 404
	}

	@tunnel path /v1/share/tunnel
	handle @tunnel {
		reverse_proxy share:8082 {
			header_up X-Client-IP {client_ip}
		}
	}

	@enrolment path /v1/* /admin /admin/*
	handle @enrolment {
		reverse_proxy enrolment:8081 {
			header_up X-Client-IP {client_ip}
		}
	}

	@login path /register/*
	handle @login {
		reverse_proxy enrolment:8081 {
			header_up X-Client-IP {client_ip}
		}
	}

	@derp path /derp /derp/* /generate_204
	handle @derp {
		reverse_proxy derper:8090
	}

	handle {
		reverse_proxy headscale:8080
	}
}
```

and `derp.local.yaml`, the DERP map Headscale gives to boxes: the tracked `headscale/derp.yaml` with your relay host (replace `relay.example.org`, host only, no scheme):

<!-- file: derp.local.yaml -->
```yaml
regions:
  999:
    regionid: 999
    regioncode: relay
    regionname: ReCasaOS relay
    nodes:
      - name: 999a
        regionid: 999
        hostname: relay.example.org
        derpport: 443
        stunport: 3478
```

and `compose.tls.yaml`, a Compose override that sets the public URL of Headscale, mounts `derp.local.yaml` over the shipped DERP map, swaps the Caddyfile, publishes 80 and 443 instead of 8080, and keeps the certificates in a volume so they survive a restart (replace `relay.example.org` here too):

<!-- file: compose.tls.yaml -->
```yaml
services:
  headscale:
    environment:
      HEADSCALE_SERVER_URL: https://relay.example.org
    volumes:
      - ./derp.local.yaml:/etc/headscale/derp.yaml:ro

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

Verified: this Caddyfile, before its `@login` block (copied from the shipped `Caddyfile`) was added, passes `caddy validate` in a throwaway `caddy:2.10.0-alpine` container (the image of `front`), and the override passes `docker compose -f compose.yaml -f compose.tls.yaml config -q`; its `derp.local.yaml` mount replaces the shipped one (Compose merges `volumes` by container path, checked in the rendered config). **Not verified:** an actual certificate issuance (it needs a real domain pointing at a public host) and a box enrolling through this setup. Here `front` faces the clients directly, so `{client_ip}` is the real TCP peer and no `trusted_proxies` is needed; the IPv6 / Docker userland proxy caveat in the README still applies.

### b) Your own reverse proxy in front of `front`

You still need an override for steps 1 and 2 of section 2: `compose.tls.yaml` above with only its `headscale` service (drop `front` and the top-level `volumes:`), and `derp.local.yaml`. Point your proxy at host port `8080` (plain HTTP) and have it pass WebSocket / HTTP upgrades through (Headscale's requirement; only Caddy was tried here). Then read ["Rate limits and the proxy header"](../README.md#rate-limits-and-the-proxy-header): Caddy must be told to trust your proxy (`trusted_proxies`) or every client shares one rate-limit bucket, and trusting a proxy that appends to `X-Forwarded-For` lets clients choose their own bucket. Never route `/api/` through it.

## 4. Settings

Put them in a `.env` file next to `compose.yaml` (Compose substitutes them). An unset or empty value takes the default, except `TRUSTED_PROXY_HEADER` (an empty value really is empty) and the two required ones; a non-positive number or duration, or a missing or invalid `LOGIN_SERVER`, makes the service refuse to start. `.env` is listed in `.gitignore`: never commit it.

| Variable | Default | In `.env`? | Notes |
|---|---|---|---|
| `HEADSCALE_API_KEY` | none, **required** | yes | the service exits without it (section 5) |
| `LOGIN_SERVER` | none, **required** | yes | **your public URL** (`https://relay.example.org`, no path), the same as `server_url`: it is the `login_server` returned to boxes when a fleet is created. The e2e override sets both to the same URL. The service exits at startup if it is empty or not an `https://` URL without a path |
| `NODES_PER_FLEET` | `50` | yes | boxes per fleet |
| `MAX_FLEETS` | `1000` | yes | fleets the relay holds; creation answers 503 beyond. Do not raise it without reading "Capacity" in the README |
| `MAX_FLEETS_PER_ORIGIN` | `10` | yes | fleets one network (an IPv4 address, an IPv6 /64) holds at once; creation answers 429 beyond, until one of its fleets goes. Homes behind one shared IPv4 address share these places. It counts the address `TRUSTED_PROXY_HEADER` gives: without that header every client is the proxy, and all share them |
| `MAX_FLEETS_PER_PREFIX48` | `30` | yes | the same for an IPv6 /48, across its /64s |
| `MAX_PENDING_KEYS` | `5` | yes | unused join keys per fleet at once (409 beyond). Raising it or `MAX_FLEETS`: README, "Capacity" |
| `CREATE_RATE_PER_HOUR` | `5` | yes | fleet creations per hour per client IP (IPv6: per /64, plus 10 times this per /48) |
| `KEY_RATE_PER_HOUR` | `30` | yes | join keys per hour per fleet |
| `AUTH_RATE_PER_HOUR` | `60` | yes | authenticated fleet requests (join key, status, deletions, device code, device list, device removal) per hour per client IP, one shared budget (boxes behind one NAT share it) |
| `DEVICE_CODE_TTL` | `10m` | yes | validity of a device code (remote access, section 13) |
| `MAX_PENDING_DEVICE_CODES` | `5` | yes | unused device codes per fleet at once (409 beyond) |
| `MAX_DEVICES_PER_FLEET` | `50` | yes | phones and PCs per fleet (a device code is refused, 409, beyond) |
| `LOGIN_RATE_PER_HOUR` | `20` | yes | device-login form submissions per hour per client IP (IPv6: per /64, plus 10 times this per /48) |
| `JOIN_KEY_TTL` | `24h` | yes | validity of a join key |
| `IDLE_AFTER` | `720h` (30 days) | yes | a fleet with no online node for this long is deleted |
| `GC_INTERVAL` | `10m` | yes | janitor period |
| `TRUSTED_PROXY_HEADER` | `X-Client-IP` in compose (empty in the binary) | yes | header set by `front`. An empty value in `.env` makes the service use the TCP peer address, which is wrong behind `front`: keep the default |
| `ADMIN_TOKEN` | none (page disabled) | yes | 24 characters or more. Turns on the operator page (section 11) |
| `DERPER_DEBUG_KEY` | none (metering off) | yes | secret that lets `enrolment` read `derper`'s byte counters; create it with `openssl rand -hex 32` (section 12). Unset: metering is off and `/admin` shows "metering unavailable". After setting or changing it, also run `docker compose up -d --force-recreate derper` (section 12). The key file given to `derper` is never empty and `/debug` stays closed either way |
| `MONTHLY_TRAFFIC_REFERENCE` | none (no reference) | yes | monthly relayed-traffic budget shown on `/admin`, e.g. `100G`, `100GB` or `2t` (K, M, G, T are decimal, any case). A yardstick, not a limit |
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

The enrolment service is built from this repository: `git pull && docker compose up -d --build`, or use the published image below. When a release changes `Caddyfile` or `headscale/config.yaml` (v0.5.0 does: section 13, "Upgrading to v0.5.0"), also run `docker compose up -d --force-recreate front headscale`: both files are bind-mounted, so Compose does not recreate those containers by itself. **Upgrading from a build before the non-root image** (the enrolment image used to run as root, so the `enrolment-data` volume and `relay.db` belong to root): give them to uid 65532 once before starting the new image, `docker compose stop enrolment && docker run --rm --volumes-from "$(docker compose ps -aq enrolment)" alpine chown -R 65532:65532 /data && docker compose up -d --build enrolment` (not run here on an old volume). `front` is pinned to `caddy:2.10.0-alpine`; the README's proxy-header checks were made with that version.

### Upgrading from v0.3.x: standalone `derper` and metering

From v0.4.0 the relay no longer uses Headscale's embedded DERP: a standalone `derper` service carries relayed traffic (so its bytes can be counted), `front` routes `/derp` to it and `3478/udp` (STUN) moves to it. Boxes keep their enrolment; nothing is re-enrolled.

Steps 1 to 3 only touch untracked files, so do them on the v0.3 checkout, before `git pull`; nothing restarts until step 4.

1. **Write `derp.local.yaml` with your public relay host** (the file of section 3a; the host of `HEADSCALE_SERVER_URL` / `LOGIN_SERVER`, without scheme) **and mount it in your Compose override**: the `volumes:` line under `headscale` in the `compose.tls.yaml` of section 3a. Without an override yet (you edited `server_url` in `headscale/config.yaml`), create one with just that `headscale` part and pass it with `-f` from now on. The shipped `headscale/derp.yaml` names `relay.example.org`: started without your map, the new version points every box at that host and they lose their relay path.
2. If you use the TLS setup of section 3a, add the `@debug` and `@derp` blocks of the new `Caddyfile.tls` example (the shipped `Caddyfile` already has them). If you mount your own `Caddyfile` or `headscale/config.yaml`, merge the new ones after the pull.
3. Optional, to meter relayed traffic: put `DERPER_DEBUG_KEY=<output of openssl rand -hex 32>` in `.env`, and `MONTHLY_TRAFFIC_REFERENCE` if you want a budget on `/admin` (section 12). `derper` does not exist yet, so the next step creates it with the key.
4. `git pull`, then `docker compose up -d --build` with your `-f` options (or the published images below). This is one switch: relayed traffic drops for a few seconds while `derper` and Headscale restart, then boxes reconnect by themselves. No re-enrolment, no action on the boxes. Direct (peer-to-peer) links are not affected.
5. Check (not verified: this upgrade was not run here): `docker compose exec headscale cat /etc/headscale/derp.yaml` shows your host; `/admin` lists every box online within a minute; with `DERPER_DEBUG_KEY` set, a box forced through DERP shows a rate; `https://your-relay/debug/clients/` answers 404; `tailscale netcheck` on a box reports `UDP: true` and a latency for region `relay`. If `https://your-relay/derp` answers 404, `front` is still running the Caddyfile it started with (which sent `/derp` to Headscale): `docker compose up -d --force-recreate front`.

**Known difference: `/bootstrap-dns`.** Headscale served `/bootstrap-dns` only with its embedded DERP; from v0.4.0 it answers 404. Boxes keep resolving the relay through their normal DNS; what they lose is that fallback for when their own DNS fails. Routing it to `derper` is a follow-up.

**Rollback:** check out the previous release (`git checkout v0.3.0`) and run `docker compose up -d --remove-orphans` with your `-f` options. `--remove-orphans` removes the `derper` container, which the old `compose.yaml` no longer lists: left running, it keeps `3478/udp`, and the recreated Headscale (whose embedded DERP binds STUN on that port) fails with "port is already allocated", taking the control plane down. If you use the TLS setup of section 3a, also revert `Caddyfile.tls`: remove its `@debug` and `@derp` blocks, or `/derp` would point at a `derper` service that no longer exists and the restored embedded DERP would be unreachable. The `derp.local.yaml` mount can stay: the old `headscale/config.yaml` reads no DERP map file (`derp.paths: []`). The usage tables that v0.4.0 added to `relay.db` stay and are ignored by the old version. Not verified either.

### Using the published image

Pushing a tag `vX.Y.Z` of this repository publishes three images, `ghcr.io/recasaos/recasaos-relay-enrolment:vX.Y.Z`, `ghcr.io/recasaos/recasaos-relay-derper:vX.Y.Z` and `ghcr.io/recasaos/recasaos-relay-share:vX.Y.Z` (and `latest` for a final release, not for a `-rc` tag) through `.github/workflows/release.yml`. To run them instead of building, add `compose.image.yaml`. Without the `derper` entry, `build: ./derper` compiles Tailscale's derper on your server:

<!-- file: compose.image.yaml -->
```yaml
services:
  enrolment:
    image: ghcr.io/recasaos/recasaos-relay-enrolment:v0.4.0 # a tag that has been published
    build: !reset null

  derper:
    image: ghcr.io/recasaos/recasaos-relay-derper:v0.4.0
    build: !reset null

  share: # only with public sharing (section 14); first published with v0.6.0
    image: ghcr.io/recasaos/recasaos-relay-share:v0.6.0
    build: !reset null
```

`compose.yaml` hands `derper` its debug key through `configs.content`, which needs Docker Compose 2.23.1 or later.

and pass it as one more `-f compose.image.yaml`; the default `compose.yaml` still builds locally. The published image is **linux/amd64 only** (the release workflow runs a plain `docker build` on an amd64 runner): on an arm64 host, build locally with the default `compose.yaml`. Nothing is published yet at the time of writing: check that the tag exists. The first GHCR package is private by default (not verified): set it to public in the package settings before operators can `docker pull` it. Validated with `docker compose -f compose.yaml -f compose.image.yaml config`; pulling the image was not tried.

## 7. Backups and restore

State lives in two named volumes (Compose prefixes them with the project name, by default the directory name, e.g. `recasaos-relay_headscale-data`):

- `headscale-data` (`/var/lib/headscale`): `db.sqlite` (users, nodes, access policy, API keys), `noise_private.key` (and `derp_server_private.key`, unused since v0.4.0: `derper` makes its own key, which clients do not pin). Losing the keys or the database means every box must enrol again.
- `enrolment-data` (`/data`): `relay.db`, the fleets and the hashes of the fleet secrets. Each fleet also carries the network it was created from (the IPv4 address, or the IPv6 /64 and /48), kept while the fleet exists and used only to count the fleets of one network (`MAX_FLEETS_PER_ORIGIN`): say so where you tell your users what your relay keeps.

The enrolment image runs as the unprivileged uid/gid `65532` (distroless `:nonroot`) and its `/data` belongs to that user, so a fresh named volume does too. If you mount a host directory on `/data` instead of the named volume, `chown 65532:65532` it first, or the service cannot create `relay.db` and its WAL files. Verified: `docker compose build enrolment`, then a one-shot `docker run` of that image on a fresh named volume created `relay.db` owned by 65532, in WAL mode.

Both SQLite databases run in WAL mode (`*-wal` and `*-shm` files sit next to them), so **stop the services before copying**. This works whatever the project name is, through `--volumes-from`:

```
mkdir -p "$HOME/relay-backup" && chmod 700 "$HOME/relay-backup"      # outside the repository checkout
docker compose stop
docker run --rm --volumes-from "$(docker compose ps -aq headscale)" -v "$HOME/relay-backup:/backup" alpine tar czf /backup/headscale-data.tgz -C /var/lib/headscale .
docker run --rm --volumes-from "$(docker compose ps -aq enrolment)" -v "$HOME/relay-backup:/backup" alpine tar czf /backup/enrolment-data.tgz -C /data .
docker compose start
```

(Use your `-f` options with `docker compose` here too, if any.)

Restore on a fresh host (repository cloned, `.env`, your Compose override, `derp.local.yaml` and `headscale/config.yaml` in place; they are not in the volumes, so back them up too):

```
docker compose create
docker run --rm --volumes-from "$(docker compose ps -aq headscale)" -v "$HOME/relay-backup:/backup" alpine tar xzf /backup/headscale-data.tgz -C /var/lib/headscale
docker run --rm --volumes-from "$(docker compose ps -aq enrolment)" -v "$HOME/relay-backup:/backup" alpine tar xzf /backup/enrolment-data.tgz -C /data
docker compose up -d
```

Run `create` and `up -d` with your `-f` options (e.g. `-f compose.yaml -f compose.tls.yaml`), otherwise `front` is recreated without TLS and Headscale with the shipped DERP map. Also back up `Caddyfile.tls`, `compose.tls.yaml` and `derp.local.yaml`.

Restore both volumes from the same backup: they describe the same fleets. This cycle was run for real (Docker Desktop, Git Bash): a fleet created through the API, backup, `docker compose down -v`, restore, `up -d`; the fleet's status then answered 200 with its secret and its Headscale user was listed. The backups hold the control plane's private keys: keep them as private as `.env`, and keep them out of the repository checkout (`.gitignore` also lists `*.tgz` as a safety net). **`docker compose down -v` destroys both state volumes** (Headscale database and keys, enrolment SQLite): never run it on a relay without a backup.

## 8. Pointing boxes at it

In ReCasaOS, enter your public URL (`https://relay.example.org`, no path) in the relay URL setting in the Fleet settings (the "Serveur de relais" field of the Fleet dialog). That setting is delivered with the ReCasaOS release that ships the relay support; it is not available before. Changing relay later means the master re-issues its enrolment codes and every member enrols again: there is no migration between relays.

## 9. Operating notes

- **Quotas and limits** (defaults, section 4): 1000 fleets per relay (creation answers 503 beyond), 50 boxes per fleet (a join key is refused with 409 when enrolled nodes plus unused, unexpired keys reach it), at most 5 unused join keys per fleet at once, 5 fleet creations per hour per IP (and 50 per IPv6 /48), 30 join-key requests per hour per fleet, 60 authenticated requests per hour per IP, join keys valid 24 h. Boxes behind one NAT share the per-IP budgets: raise `CREATE_RATE_PER_HOUR` / `AUTH_RATE_PER_HOUR` if one address serves many boxes.
- **Idle deletion:** every `GC_INTERVAL` the janitor deletes fleets with no online node for `IDLE_AFTER` (30 days by default), deletes used and expired pre-auth keys, deletes fleets that never got a node within twice `JOIN_KEY_TTL` (48 h) and hold no pending join key, and rewrites the access policy (README, "Janitor").
- **Isolation:** each fleet is its own Headscale user and the service owns the access policy (deny by default, one rule per fleet).
- **When the relay is down:** new enrolments fail, because the enrolment API and the control plane are both behind `front`. Boxes that already enrolled and have a direct peer-to-peer path do not send that traffic through the server, so those links are expected to keep working for a while; links that go through the relay stop, because `derper` sits behind the same `front` (and it verifies every box against Headscale, refusing everyone while Headscale is down). Observed with tailscale 1.104.4 against Headscale v0.29.7 (stopping all four services of the stack, sampling the client at 10, 40 and 90 s): the client stays `Running` with its address and reports itself offline (`Self.Online: false`); started again, it is online within 15 s with no action on the box. Not measured: whether traffic between two peers keeps flowing during the outage, or for how long.
- **Expired node key:** a node whose key was expired at the server (`headscale nodes expire`) reports `NeedsLogin` with `Self.Expired: true` but keeps its login server, and `tailscale up --login-server=… --authkey=… --hostname=…` with a fresh join key brings it back with the same address. ReCasaOS reads such a box as being in a network, not as free.
- **Relayed traffic is observed, not capped:** `derper`'s byte counters are read and shown on `/admin` (section 12), but there is no per-fleet quota or cut-off in this version. What is limited is the number of boxes, the enrolment rate and idle fleets. Watch your host's bandwidth. The investigation and the planned quota are in [metering.md](metering.md).

## 10. Security checklist

- TLS in front of everything. The enrolment API relies on it: a box signature is bearer-like within its ±120 s validity window. While the service runs, each signature is accepted once (replay is refused); a restart forgets which signatures were seen, so a signature captured on the wire can be replayed within the window after a restart.
- `ADMIN_TOKEN` opens `/admin` to the Internet: long random token, HTTPS only (section 11).
- Do not add a `ports:` entry for `enrolment` (8081) or Headscale's gRPC (50443). The rate limiter trusts `X-Client-IP`, which only `front` sets, and the admin API has no other protection. `/api/` must stay unreachable from outside (`front` answers 404).
- `X-Client-IP` and `trusted_proxies`: read the README section on the proxy header before putting another proxy in front of `front`.
- Keep `.env` (the API key) out of version control; rotate the key (section 5).
- Do not edit the access policy in Headscale by hand: the next sync overwrites it.
- Public sharing (section 14): the `proxy_protocol` wrapper belongs to share mode only (`front` unpublished); never leave it in `Caddyfile.tls` with `front` published, and `allow` should be narrowed to the compose subnet (`docker network inspect` gives it): any host that can reach `front` from an allowed address can forge `X-Client-IP` and evade the per-IP limits. Never publish `8082` (the `share` tunnel listener; only `front` reaches it) and publish `53` only on the public IP (`<ip>:53:53`), never `0.0.0.0`. Trust model: the relay holds the DNS zone, so its operator could obtain a certificate for any box name; Certificate Transparency logs make every such certificate public, which is the check boxes and users have.

## 11. Admin page

A small page at `https://your-relay/admin/` lists the fleets and their nodes (online or not, activity, quotas) and can delete a fleet or remove a node. It is off, and `/admin` answers 404, until you set `ADMIN_TOKEN` in `.env` (24 characters or more, for example `openssl rand -hex 16`) and run `docker compose up -d`.

The browser asks for a login: any user name, the token as the password. Use it over HTTPS only (section 3), since the token travels with every request. After 120 failed logins from one client address within an hour it answers 429 to that address, even with the right token, until the window frees up; this makes guessing the token impractical, and a long random token is still what protects it. The page shows no fleet secret and no join key: the relay does not keep them. Deleting a fleet takes its boxes off the relay, and each box notices the next time it asks for its state.

If you would rather not expose it, remove `/admin /admin/*` from the `@enrolment` line of your Caddyfile.

## 12. Metering relayed traffic

`enrolment` reads `derper`'s per-connection byte counters every 15 s (`DERPER_URL`, default `http://derper:8090`, compose network only), attributes them to boxes and fleets through the node keys Headscale knows, and keeps minute and hour buckets in `relay.db`. `/admin` shows, per fleet and box, the relayed rate, the volume this month (UTC calendar month) and a per-node chart; with `MONTHLY_TRAFFIC_REFERENCE` set it also shows each fleet against that budget. The figure is what a box sends into the relay: about 1.07 times the payload (measured with 20 and 50 MiB transfers).

- **Turning it on:** put `DERPER_DEBUG_KEY` in `.env` (`openssl rand -hex 32`), then run `docker compose up -d` and `docker compose up -d --force-recreate derper` (with your `-f` options). Do both every time you set or change the key: Compose recreates `enrolment` with the new key but not `derper`, whose key file is written when its container is created (a change of `configs` content does not trigger a recreate), so `derper` would refuse the new key (403) and `/admin` would show "metering unavailable". Recreating `derper` cuts relayed traffic for a few seconds; boxes reconnect by themselves. Unset, metering is off and `/admin` shows "metering unavailable". The key file given to `derper` is never empty, so `/debug` stays closed to everybody else either way, and `front` answers 404 for `/debug` regardless.
- **First deployment:** on the first scrape, the lifetime counters of connections that are already open are counted in full, so the first month can include some traffic from before metering started.
- **A box seen for the first time** is counted once Headscale's node list (refreshed at most every 60 s) knows its key, so its first traffic can take a minute or so to appear.
- **Not metered:** a connection that opens and closes within one 15 s scrape interval, and direct peer-to-peer traffic (which does not cost you bandwidth).
- **Large relays:** metering needs Headscale's full node list in one reply, which its gRPC layer caps at 4 MiB: beyond roughly 8,000 nodes (an estimate, not measured; the defaults allow 50,000) `/admin` shows "metering unavailable". A per-fleet fallback is a planned follow-up (README, "Capacity").
- **Observed, not enforced:** nothing is refused or cut when a budget is exceeded.

## 13. Remote access (phone login)

A phone joins a fleet with the official Tailscale app, using your relay as its login server. The box asks `POST /v1/fleets/{id}/device-codes` for a one-time code (valid `DEVICE_CODE_TTL`, 10 minutes by default); the app opens `https://your-relay/register/<auth id>` and the user types the code. The API is in the README ("Remote access"). Three things matter to an operator:

- **Route `/register/*` to `enrolment`.** The shipped `Caddyfile` and the `Caddyfile.tls` of section 3a have it. If your Caddyfile predates v0.5.0 (a `Caddyfile.tls` copied from section 3a before then, or your own), add this block next to the `@enrolment` one, or the app lands on Headscale's own page, which cannot approve anything:

  ```
  	@login path /register/*
  	handle @login {
  		reverse_proxy enrolment:8081 {
  			header_up X-Client-IP {client_ip}
  		}
  	}
  ```

  Behind your own proxy: send `/register/*` to host port `8080` like the rest, and keep the `X-Client-IP` rule of section 3b, since `LOGIN_RATE_PER_HOUR` counts per client address.
- **Devices never expire.** `headscale/config.yaml` pins `node.expiry: 0`, so a phone is not logged out after 180 days. If you replaced that file, keep the setting; without it, phones drop off the network and must register again.
- **Limits** (section 4): `DEVICE_CODE_TTL` `10m`, `MAX_PENDING_DEVICE_CODES` `5` unused codes per fleet, `LOGIN_RATE_PER_HOUR` `20` form submissions per hour per client address, `MAX_DEVICES_PER_FLEET` `50` devices per fleet. Devices do not count in `NODES_PER_FLEET`.
- **Upgrading to v0.5.0.** `git pull`, then `docker compose up -d --build` with your `-f` options (or `COMPOSE_FILE`), so `enrolment` gets the new code and variables. That is not enough for `front` and `headscale`: the `Caddyfile` (or your `Caddyfile.tls`) and `headscale/config.yaml` are bind-mounted, so Compose does not see their change and keeps the containers running with the old files (no `/register/*` route, no `node.expiry: 0`). Recreate both, with the same `-f` options:

  ```
  docker compose up -d --force-recreate front headscale
  ```

  Restarting Headscale interrupts the control plane for a few seconds (boxes reconnect by themselves; established peer-to-peer links are not affected). Then check that `/register/*` reaches `enrolment` (not verified here: this upgrade was not run):

  ```
  curl -s https://your-relay/register/hskey-authreq-AAAAAAAAAAAAAAAAAAAAAAAA | grep recasaos-device-login
  ```

  No output means the app would land on Headscale's own page: `front` still runs the old Caddyfile, or the `@login` block is missing.

## 14. Public sharing

A box can publish a web app of its own under `https://<app>.<box>.box.example.org` (`box.example.org` is the sharing domain, `SHARE_DOMAIN`; `<box>` is the name the box claimed on the relay). The relay forwards the TLS connection by SNI without decrypting it (a shared box's traffic goes into its tunnel, everything else to `front`), and the boxes' certificates are obtained by DNS-01, answered by the relay's own DNS zone for `box.example.org`. The API and the box side are in the README ("Public sharing"); this section is what an operator sets up. It adds a third process, `share`, and moves ports 80 and 443 from `front` to it. It is optional: without `compose.share.yaml` below, none of this exists and the relay behaves as in sections 1 to 13.

Examples use `relay.example.org` (the relay, as in section 3a) and `box.example.org` (the sharing domain, a sub-domain of a domain you control).

### Delegation at the registrar

The relay must be the authoritative DNS server of `box.example.org`. At the registrar (or wherever `example.org` is served), create two records:

```
box.example.org.     NS   ns.box.example.org.
ns.box.example.org.  A    <relay public IPv4>          ; the glue: the name server lives inside the zone it serves
```

(plus an `AAAA` glue record if you set `SHARE_PUBLIC_IP6`). Some registrars call the glue a "child name server" or "host record" and want it entered in a dedicated form. The relay's zone answers `A` / `AAAA` for every name of one or two labels under `box.example.org` (`test.box...`, `app.test.box...`) with `SHARE_PUBLIC_IP` / `SHARE_PUBLIC_IP6`, `NS` and `SOA` at its apex, and `TXT` only for `_acme-challenge.<box>.box.example.org` while that box has a challenge pending. No recursion, no zone transfer.

### Public Suffix List (owner action, takes weeks)

Ask for `box.example.org` to be added to the PRIVATE section of the [Public Suffix List](https://publicsuffix.org/submit/) (a pull request on `publicsuffix/list`). Two reasons: Let's Encrypt's rate limit counts certificates per registered domain (50 new ones a week), so without the entry every box shares one budget and sharing stops working at a few dozen boxes; and browsers isolate cookies per registered domain, so without it one box's apps could set cookies that another box's apps receive. The review takes weeks; the system works without the entry for a small number of boxes. The maintainers ask for proof of control as a TXT record at `_psl.box.example.org` whose value is the URL of your pull request: once it is open, set `SHARE_PSL_TXT=<that URL>` in `.env` (and pass it to `enrolment`, below); the zone then answers it (TTL 300). **Not verified** against the maintainers' current requirements: read their instructions before filing.

### Ports

| Port | Who | Notes |
|---|---|---|
| `80/tcp`, `443/tcp` | `share` (moved from `front`) | `share` reads the TLS server name (or the HTTP `Host`) and forwards to `front`, or into the box's tunnel for a shared name |
| `53/udp`, `53/tcp` | `enrolment` (the DNS zone) | publish **on the public IP explicitly** (`<ip>:53:53/udp`, `<ip>:53:53/tcp`), never `0.0.0.0`: on a typical Linux host `systemd-resolved` already holds `127.0.0.53:53` and `127.0.0.54:53`, so a wildcard bind can fail, and a DNS server should not answer on every interface anyway |
| `8082/tcp` | `share` tunnel listener | never published: only `front` reaches it (`/v1/share/tunnel`; the block is already in the `Caddyfile.tls` of section 3a) |
| `443/udp` | none | HTTP/3 is lost, see below |

Open `53/udp` and `53/tcp` in the host firewall or cloud security group too. Behind the SNI front, **Caddy loses HTTP/3** on the relay name: `share` forwards TCP only, so `443/udp` is no longer reachable. Boxes and Tailscale clients do not use it; browsers fall back to HTTP/2.

**Client address.** `share` starts every connection to `front` with a [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) v2 header carrying the visitor's address (`FRONT_PROXY_PROTOCOL`, default `true`; `false` forwards the bytes untouched, as before). The `Caddyfile.tls` of section 3a does not read it; the additions below do, with Caddy's `proxy_protocol` listener wrapper, placed before `tls` because the header precedes the TLS handshake; `{client_ip}` is then the visitor, `header_up X-Client-IP {client_ip}` hands it to `enrolment` unchanged, and the per-IP limits of section 4 (`CREATE_RATE_PER_HOUR`, `AUTH_RATE_PER_HOUR`, `LOGIN_RATE_PER_HOUR`) count per visitor again. Without the header every visitor would be the `share` container and those limits one budget for the whole Internet.

The wrapper only trusts headers from `allow`: put your compose network's subnet there (`docker network inspect <project>_default` gives it; the private ranges of the Caddyfile are only a fallback). **The wrapper belongs to share mode only: have it in `Caddyfile.tls` only while `front` is unpublished (with `compose.share.yaml`), and remove it again on rollback.** With `front` published (section 3a alone), a client arriving through Docker's userland proxy (IPv6 publishing, hairpin) shows up with the bridge gateway as source, inside the compose subnet and so trusted, and could forge `X-Client-IP`. `allow` should also be as narrow as the compose subnet: any host that can reach `front` from an allowed address can forge `X-Client-IP` and evade the per-IP limits. Choice of policy: no `fallback_policy` line, so Caddy's default `ignore` applies to every other address (a header from outside is not believed, which stops a visitor from forging its address), and a connection from an allowed address **without** a header still works (Caddy's `use` for `allow`: header used if present). That is what makes the migration a one-way, no-flag-day change: `front` can run the new `Caddyfile.tls` while `share` still forwards headerless. Recreate `front` with the wrapper no later than `share` (the migration below does both in one command); the other order is safe only with `FRONT_PROXY_PROTOCOL=false`. Ordering to avoid: `share` with `FRONT_PROXY_PROTOCOL=true` against a `front` whose Caddyfile has no wrapper, which breaks every connection (Caddy reads the header as garbage); so recreate them together, in step 3 of the migration below. Set `FRONT_PROXY_PROTOCOL=false` only when your Caddy is not configured for it.

### Settings

In `.env`, next to the ones of section 4:

| Variable | Default | Process | Notes |
|---|---|---|---|
| `SHARE_DOMAIN` | none, **required** | both | the sharing domain, lowercased (`box.example.org`): a bare DNS name, no scheme, port or trailing dot (both processes refuse to start otherwise). Empty on `enrolment`: sharing is off (every `/v1/share*` answers 503) |
| `SHARE_PUBLIC_IP` | none, **required** | `enrolment` | IPv4 the zone answers with, and the IP port 53 is published on: the relay's public address |
| `SHARE_PUBLIC_IP6` | none | `enrolment` | IPv6 address for `AAAA`; empty: no `AAAA` |
| `RELAY_HOST` | none, **required** | `share` | the relay's own name (`relay.example.org`), a bare DNS name not under `SHARE_DOMAIN`: traffic for it goes to `front`, any other name is looked up as a box |
| `SHARE_ACME_TTL` | `10m` | `enrolment` | validity of an `_acme-challenge` TXT value |
| `SHARE_ACME_RATE_PER_HOUR` | `20` | `enrolment` | ACME TXT writes per hour per box |
| `PEEK_TIMEOUT` | `5s` | `share` | how long a new connection has to send its TLS hello / HTTP request line |
| `TUNNEL_RATE_PER_HOUR` | `60` | `share` | tunnel dials (`/v1/share/tunnel`) per hour per client IP (`X-Client-IP`, set by `front`), counted before the signature check; `429` with `Retry-After` beyond |
| `CONNS_PER_IP` | `256` | both | open connections per client IP (IPv6: per /64) on 80 and 443 together, boxes' own control and DERP connections included (about 3 per box, 2 per phone: one carrier-NAT address fills it near 85 boxes); past it a new connection is closed before any byte is read |
| `CONNS_PER_IP_PER_BOX` | `64` | both | visitor connections one client IP may hold into one box's tunnel (256 at most per tunnel), so one address cannot lock the other visitors out; past it the connection is closed. `share` enforces both caps; `enrolment` only shows them on `/admin`, so one value in `.env` serves both |
| `LISTEN_TLS`, `LISTEN_HTTP`, `LISTEN_TUNNEL` | `:443`, `:80`, `:8082` | `share` | listen addresses inside the container |
| `FRONT_TLS`, `FRONT_HTTP` | `front:443`, `front:80` | `share` | where non-box traffic goes |
| `FRONT_PROXY_PROTOCOL` | `true` | `share` | send a PROXY v2 header (the visitor's address) to `FRONT_TLS` and `FRONT_HTTP`; see "Client address" |
| `SHARE_PSL_TXT` | empty | `enrolment` | value of `_psl.<SHARE_DOMAIN>` TXT (Public Suffix List ownership proof), at most 255 bytes; empty: no such record |
| `ENROLMENT_URL` | `http://enrolment:8081` | `share` | name lookups and usage posts, compose network only |
| `LISTEN_DNS` | `:53` | `enrolment` | DNS listen address inside the container |
| `PROTECT_RATE_PER_HOUR` | `600` | `enrolment` | protection requests of the boxes (`PUT /v1/share/protection`, `POST /v1/share/bans`, `GET /v1/share/refusals`) per hour per client IP, counted before the signature check, on a budget of their own: they never use up `AUTH_RATE_PER_HOUR`; `429` with `Retry-After` beyond |
| `FILTER_MAX_ENTRIES` | `1000000` | `enrolment` | entries of all enabled block lists together ("Protection of shared apps" below); a list that would take the total past it is refused whole and its last good copy stays |
| `COMMUNITY_MIN_FLEET_AGE` | `168h` (7 days) | `enrolment` | how old a fleet must be before its boxes' ban reports count. **For tests only**: keep the default on a relay open to the public |

The rows from `PEEK_TIMEOUT` on are the processes' own defaults (`compose.yaml` passes `LISTEN_TLS`, `LISTEN_HTTP`, `LISTEN_TUNNEL`, `FRONT_TLS`, `FRONT_HTTP`, `ENROLMENT_URL`, `PEEK_TIMEOUT`, `FRONT_PROXY_PROTOCOL`, `TUNNEL_RATE_PER_HOUR`, `CONNS_PER_IP` and `CONNS_PER_IP_PER_BOX` to `share`; neither cap counts loopback, private or link-local sources, which is what Docker's userland proxy and boxes on the relay's own LAN arrive from, and `SHARE_PSL_TXT`, `PROTECT_RATE_PER_HOUR`, `FILTER_MAX_ENTRIES`, `COMMUNITY_MIN_FLEET_AGE`, `CONNS_PER_IP` and `CONNS_PER_IP_PER_BOX` to `enrolment`, as shown there); none needs changing except `SHARE_PSL_TXT` once you have a PSL request.

### Compose override

`compose.share.yaml` starts `share` for good (the `share` profile of `compose.yaml` is for tests), gives it 80 and 443, takes both away from `front` (which keeps listening on them inside the compose network, where `share` reaches it) and turns the zone on in `enrolment`. Put `SHARE_DOMAIN`, `SHARE_PUBLIC_IP` and `RELAY_HOST` in `.env`.

<!-- file: compose.share.yaml -->
```yaml
services:
  share:
    profiles: !reset []
    ports:
      - "80:80"
      - "443:443"
    environment:
      RELAY_HOST: ${RELAY_HOST:?set RELAY_HOST in .env}
      SHARE_DOMAIN: ${SHARE_DOMAIN:?set SHARE_DOMAIN in .env}

  front:
    ports: !override []

  enrolment:
    environment:
      SHARE_DOMAIN: ${SHARE_DOMAIN:?set SHARE_DOMAIN in .env}
      SHARE_PUBLIC_IP: ${SHARE_PUBLIC_IP:?set SHARE_PUBLIC_IP in .env}
      SHARE_PUBLIC_IP6: ${SHARE_PUBLIC_IP6:-}
      SHARE_ACME_TTL: ${SHARE_ACME_TTL:-10m}
      SHARE_ACME_RATE_PER_HOUR: ${SHARE_ACME_RATE_PER_HOUR:-20}
      SHARE_PSL_TXT: ${SHARE_PSL_TXT:-}
    ports:
      - "${SHARE_PUBLIC_IP:?set SHARE_PUBLIC_IP in .env}:53:53/udp"
      - "${SHARE_PUBLIC_IP:?set SHARE_PUBLIC_IP in .env}:53:53/tcp"
```

`!reset` and `!override` need Docker Compose 2.24.4 or later on the host (`docker compose version`); an older one refuses the file or ignores the tags.

Pass it after the others, on every `docker compose` command of this document from now on: `docker compose -f compose.yaml -f compose.tls.yaml -f compose.share.yaml ...`. For an IPv6 address also publish `"[${SHARE_PUBLIC_IP6}]:53:53/udp"` and `/tcp` (not verified). It builds on section 3a: with the plain `compose.yaml`, `front` publishes 8080 and has no TLS for `share` to forward to.

Verified: the file passes `docker compose -f compose.yaml -f compose.tls.yaml -f compose.share.yaml config -q` with `SHARE_DOMAIN`, `SHARE_PUBLIC_IP` and `RELAY_HOST` set (and without them it stops with the messages above). **Not verified:** a run on a real host (no public IP and no registrar here). The e2e tests `TestShareFrontKeepsRelayWorking`, `TestShareRoutesBySNIAndIsolates` and `TestShareCertificateViaDNS01` run the same three processes on a private network with a test CA.

### Caddyfile.tls

Additions to the `Caddyfile.tls` of section 3a, for share mode:

0. replace the global options block (`{ email ... }`) with the one below, which adds the two `listener_wrappers` blocks (the visitor's address, see "Client address"). Put your compose subnet in `allow` (`docker network inspect <project>_default`); the private ranges are only a fallback. Keep them only while `front` is unpublished, and take them out again on rollback:

<!-- file: Caddyfile.tls (global options in share mode) -->
```
{
	email admin@example.org

	# Reads the PROXY protocol header that `share` (section 14) puts in front of each connection, so that
	# {client_ip} is the visitor and not the `share` container. Must stay before `tls`; :80 gets its own
	# block without `tls`, and it only reaches a server defined by an explicit `http://` site (the
	# `http://*.box...` site of the base file), not the redirect server Caddy adds by itself.
	servers :443 {
		listener_wrappers {
			proxy_protocol {
				allow <compose subnet> # fallback: 172.16.0.0/12 192.168.0.0/16 10.0.0.0/8
			}
			tls
		}
		# 443/udp no longer reaches `front`: do not advertise HTTP/3.
		protocols h1 h2
	}
	servers :80 {
		listener_wrappers {
			proxy_protocol {
				allow <compose subnet> # fallback: 172.16.0.0/12 192.168.0.0/16 10.0.0.0/8
			}
		}
	}
}
```

   Do not recreate `front` with this block before the switch below: until `share` takes over, `front` is still published.
1. the `/v1/share/tunnel` block (`@tunnel`, to `share:8082`, with `header_up X-Client-IP {client_ip}`: `share` rate-limits tunnel dials per client IP) is in the base file of section 3a; make sure it is there, with the `header_up` line;
2. the `http://*.box.example.org` site is in the base file of section 3a too; make sure it is there, once (Caddy refuses a file that defines the same site twice). It exists to make the port-80 server explicit: Caddy applies the `servers :80` wrapper of item 0 to a server defined by an explicit `http://` site, not to the redirect server it adds by itself (measured: without such a site, a PROXY header on port 80 is answered `400`, your own HTTP-01 renewals included). A plain-HTTP request for `<app>.<box>.box.example.org` is answered by Caddy's catch-all HTTP-to-HTTPS redirect, not by this site's `redir`.

The file passes `caddy validate` in `caddy:2.10.0-alpine` (the image of `front`). Run with Caddy's internal CA in a throwaway container, a plain-HTTP request for `app.test.box.example.org` was redirected to HTTPS with a **308**, with or without the `http://*.box...` site (Caddy's own redirect answers first). `Caddyfile.tls` is bind-mounted: recreate `front` after changing it (the migration below does).

### Migrating the production relay

For `relay.recasaos.org` (Scaleway host, observed 2026-11-09): `front` publishes `80/tcp` and `443/tcp` and exposes `443/udp`; a `watchtower` container updates images by itself; `systemd-resolved` holds `127.0.0.53:53` and `127.0.0.54:53` only, so port 53 is free on the public IP. **`watchtower` does not do this switch**: `share` is a new service and `front`'s ports change only through the override, so the operator applies it by hand, once.

1. Owner, first: the delegation at the registrar, the Scaleway security group (`53/udp` and `53/tcp` in), the PSL request (it can wait).
2. On the host: `git pull`; add `SHARE_DOMAIN`, `SHARE_PUBLIC_IP` (and `SHARE_PUBLIC_IP6`) and `RELAY_HOST` to `.env`; write `compose.share.yaml`; make sure `Caddyfile.tls` has the `http://*.box...` site and the `/v1/share/tunnel` block of section 3a (items 1 and 2 above; do not add the site a second time); replace the global options of `Caddyfile.tls` with the share-mode block above (it takes effect when `front` is recreated in step 3, together with `share`: do not restart `front` in between).
   Then check the files before the switch (a Caddyfile that does not parse would leave `front` down during it):

   ```
   docker compose version   # 2.24.4 or later, for !reset / !override
   docker compose -f compose.yaml -f compose.tls.yaml -f compose.share.yaml run --rm front caddy validate --config /etc/caddy/Caddyfile
   ```

3. The switch:

   ```
   docker compose -f compose.yaml -f compose.tls.yaml -f compose.share.yaml up -d --build share enrolment front
   ```

   One command: `front` is recreated without its ports, `share` starts on 80 and 443, `enrolment` restarts with the zone. Seconds of downtime for the relay; boxes reconnect by themselves, no re-enrolment, nothing to do on the boxes. HTTP/3 is gone (above).
4. Keep the three `-f` options from now on: without the override, the next `up -d` hands 80 and 443 back to `front` while `share` still holds them.

Check (replace `<ip>` with the relay's public IP):

```
dig @<ip> app.test.box.example.org A                            # the relay IP
dig @<ip> _acme-challenge.test.box.example.org TXT              # status NOERROR, no answer
openssl s_client -servername relay.example.org -connect <ip>:443 </dev/null | openssl x509 -noout -issuer -dates   # still Caddy's certificate for the relay
curl -I http://relay.example.org/.well-known/acme-challenge/x   # an HTTP answer from Caddy (404 or a 308 to https), not a connection error
curl -I http://app.test.box.example.org                         # a 301 or 308 redirect to https://app.test.box.example.org/
docker compose -f compose.yaml -f compose.tls.yaml -f compose.share.yaml logs front | grep -i -E "certificate|acme"   # a renewal attempt succeeding
```

Then `dig NS box.example.org` without `@` shows the delegation from outside once it has propagated: box names resolve from the Internet only after that, while `dig @<relay ip>` answers at once. A box that claims a name (README, "Public sharing") shows under **Shared names** on `/admin`.

**Rollback:** stop `share` first (it holds 80 and 443), then bring the stack up without the override:

```
docker compose -f compose.yaml -f compose.tls.yaml -f compose.share.yaml rm -sf share
docker compose -f compose.yaml -f compose.tls.yaml up -d
```

Between the two commands, take the `listener_wrappers` blocks out of the global options of `Caddyfile.tls` (back to the `{ email ... }` of section 3a): the second command publishes `front` again, and with the wrapper still there the PROXY header trust would apply to clients reaching `front` directly. The second command recreates `front`, which reads the file.

`front` takes 80 and 443 back, and `enrolment` restarts without the zone and without port 53. Nothing else to undo: claimed names and TXT rows stay in `relay.db` and do no harm (the share API answers 503 until `SHARE_DOMAIN` is set again). Boxes lose their public address meanwhile; their tunnels reconnect when `share` is back.

### Operating it

On `/admin` (section 11): **Shared names** lists every claimed name with a Revoke button, and **Forbidden names** is your own deny list on top of the built-in reserved words (`www relay admin api mail ns ns1 box tunnel recasaos casaos localhost`). Revoking a name frees it from its box and forbids it; the box's tunnel closes within a minute. Details: README, "Public sharing". A box whose node no longer exists in Headscale (for instance after `tailscale logout`) loses its box key at the next janitor pass and its name goes to quarantine. The quarantine lasts 125 days (fixed: Let's Encrypt reuses a DNS-01 authorization for up to 30 days, so a former holder could still get a 90-day certificate for the name that long after); the box that released a name may take it back meanwhile, nobody else may. Removing a box from `/admin` drops its box key at once. Unbanning a name (Forbidden names, Remove) also lifts its quarantine: it undoes a misclicked Revoke.

### Protection of shared apps

`enrolment` can cut known bad addresses before they reach a box. It only ever uses what the relay sees of a visitor: its address and the name it asks for. Filtering applies **only to connections for a share name** (`<label>.<box>.<SHARE_DOMAIN>` on 443), checked once the name is read; connections to the relay's own name (enrolment, Headscale, `/admin`) and to port 80 are never filtered, so no ban can cut a box off from its own relay. A refused connection is closed without an answer: the certificate is on the box, the relay cannot show a page. The connection caps (`CONNS_PER_IP`, `CONNS_PER_IP_PER_BOX`) apply as before.

It runs only with sharing on (`SHARE_DOMAIN` set). **A fresh relay filters nothing**: every list is added disabled, and the community list and the manual bans start empty. Everything is managed on `/admin` (section 11), page **Protection**.

| Source | Applies to |
|---|---|
| Relay allow list (addresses and ranges, each with a note) | everyone: never cut, whatever the other sources say |
| Manual bans (address, range, AS number, country; for a set time or until removed) | every share name, whatever the box's settings |
| Suspended name | every connection for that name (the name stays with its box; resume it on `/admin`) |
| External block lists | boxes whose owner kept **relay filtering** on |
| Community list | boxes with relay filtering on **that also share their own bans** |

Each box has two settings, pushed by its ReCasaOS core and signed with its box key: **relay filtering** (on by default on an up-to-date box) and **share my bans** (off until the owner accepts it on the dashboard, never pre-ticked). A box whose core predates them has neither, and only the allow list, the caps and the manual bans apply to it. The community list is give and take: it protects only the boxes that feed it.

`share` fetches the compiled filter from `enrolment` every 30 seconds (the body only when it changed). A `share` that starts before it ever got one lets connections through rather than cutting every shared app, and says so once in its log.

**External block lists.** Add one from a preset or by hand: name, `https` URL, optional authentication header for keyed lists, text or CSV (with the address column), refresh interval (one hour or more), maximum entries (default 100 000). A failed download keeps the last good copy and `/admin` shows the error. A list over its own maximum, or over `FILTER_MAX_ENTRIES` with the other enabled lists, is refused whole, never cut short. Entries broader than a /8 (IPv4) or /19 (IPv6) are skipped. Copies are kept in `/data/feeds/` and never handed to boxes. You choose the lists and follow their terms:

| Preset | Refresh | Terms and notes |
|---|---|---|
| FireHOL level 1 | 1 h | an aggregate (DShield, Feodo, full bogons, Spamhaus DROP): each source's own license applies |
| Spamhaus DROP | 24 h | Spamhaus asks for at most one download a day; free for non-commercial use |
| blocklist.de (all) | 1 h | regenerated every 30 minutes |
| Emerging Threats compromised | 24 h | |
| Tor exit nodes | 1 h | blocking it cuts every Tor visitor, including people who only want privacy |
| AbuseIPDB (subscription) | 1 h | needs your API key; `confidenceMinimum=90` needs a paid plan; check your plan's daily download limit |
| AbuseIPDB (free) | 6 h | needs your API key; the free plan returns at most 10 000 addresses, all at 100 % confidence, and allows 5 downloads a day, hence 4 a day here |
| CrowdSec blocklist | 1 h | a "raw IP list" integration of the CrowdSec console: replace `<integration id>` in the URL and enter its user and password (shown once in the console) |

Keys are kept in `relay.db` and shown masked on `/admin`.

**Community list.** A box that shares its bans sends, for each ban its own Gateway started, the address (an IPv4 address or an IPv6 /64), the reason (`waf`, `scan`, `rate`, `code`), the app and the start time, nothing else. An address enters the list when boxes of **two different fleets** report it within 24 hours. It is banned for 24 hours; for 7 days if it comes back within 30 days of the end of its previous ban; **for good** the third time, until you lift it. When 5 addresses of one /24 (IPv4) or /48 (IPv6) are banned at once, the whole range is banned, with its own count and the same steps. When 10 banned ranges belong to one network (AS), `/admin` flags it with a button to ban it; networks and countries are never banned automatically. The allow list always wins, and private, loopback, link-local and carrier-grade NAT (100.64.0.0/10) addresses are never kept.

Anyone can create a fleet on a public relay, so a report counts only when all of these hold; otherwise it is dropped without telling the box:

- the address really reached **that box through this relay**, from 24 hours before the ban started;
- the box's fleet is **at least 7 days old** and holds at least one share name;
- the box has share my bans on.

A fleet's reports count once per address, and reports during a running ban neither extend nor raise it.

**Personal data.** Visitor addresses are personal data: say so where you tell your users what your relay keeps. The relay keeps the following, and deletes it on time even after sharing is turned off:

- each accepted connection (address and box) for **24 hours**, only to check reports as above;
- the raw reports for **30 days**, deleted at once for a box that turns share my bans off;
- refusal counts (hour, name, address, reason, source) for 7 days, shown on `/admin` and to the box that owns the name, never to another box;
- community bans until they end, then deleted (an address's count of past bans is kept 30 days after its last ban ends);
- your timed manual bans until they end, then deleted;
- **permanent bans** until you lift them, listed apart on `/admin` with their date and reasons. Home addresses change hands: review that list from time to time.

**Countries and networks.** Country and AS bans, and the networks shown on `/admin`, use DB-IP Lite (country and ASN), which `enrolment` downloads into `/data/geo/`, checks daily and replaces when the month changes. Until the files are there, country and AS bans match nothing and `/admin` says so. [IP Geolocation by DB-IP](https://db-ip.com), under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): keep that attribution wherever you show its data. `/data/geo/` and `/data/feeds/` are downloaded again if lost; a backup of `/data` (section 7) carries them anyway.
