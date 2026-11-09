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
| `MAX_PENDING_KEYS` | `5` | yes | unused join keys per fleet at once (409 beyond). Raising it or `MAX_FLEETS`: README, "Capacity" |
| `CREATE_RATE_PER_HOUR` | `5` | yes | fleet creations per hour per client IP (IPv6: per /64, plus 10 times this per /48) |
| `KEY_RATE_PER_HOUR` | `30` | yes | join keys per hour per fleet |
| `AUTH_RATE_PER_HOUR` | `60` | yes | authenticated fleet requests (join key, status, deletions, device code, device list, device removal) per hour per client IP, one shared budget (boxes behind one NAT share it) |
| `DEVICE_CODE_TTL` | `10m` | yes | validity of a device code (remote access, section 13) |
| `MAX_PENDING_DEVICE_CODES` | `5` | yes | unused device codes per fleet at once (409 beyond) |
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

Pushing a tag `vX.Y.Z` of this repository publishes two images, `ghcr.io/recasaos/recasaos-relay-enrolment:vX.Y.Z` and `ghcr.io/recasaos/recasaos-relay-derper:vX.Y.Z` (and `latest` for a final release, not for a `-rc` tag) through `.github/workflows/release.yml`. To run them instead of building, add `compose.image.yaml`. Without the `derper` entry, `build: ./derper` compiles Tailscale's derper on your server:

<!-- file: compose.image.yaml -->
```yaml
services:
  enrolment:
    image: ghcr.io/recasaos/recasaos-relay-enrolment:v0.4.0 # a tag that has been published
    build: !reset null

  derper:
    image: ghcr.io/recasaos/recasaos-relay-derper:v0.4.0
    build: !reset null
```

`compose.yaml` hands `derper` its debug key through `configs.content`, which needs Docker Compose 2.23.1 or later.

and pass it as one more `-f compose.image.yaml`; the default `compose.yaml` still builds locally. The published image is **linux/amd64 only** (the release workflow runs a plain `docker build` on an amd64 runner): on an arm64 host, build locally with the default `compose.yaml`. Nothing is published yet at the time of writing: check that the tag exists. The first GHCR package is private by default (not verified): set it to public in the package settings before operators can `docker pull` it. Validated with `docker compose -f compose.yaml -f compose.image.yaml config`; pulling the image was not tried.

## 7. Backups and restore

State lives in two named volumes (Compose prefixes them with the project name, by default the directory name, e.g. `recasaos-relay_headscale-data`):

- `headscale-data` (`/var/lib/headscale`): `db.sqlite` (users, nodes, access policy, API keys), `noise_private.key` (and `derp_server_private.key`, unused since v0.4.0: `derper` makes its own key, which clients do not pin). Losing the keys or the database means every box must enrol again.
- `enrolment-data` (`/data`): `relay.db`, the fleets and the hashes of the fleet secrets.

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
- **Limits** (section 4): `DEVICE_CODE_TTL` `10m`, `MAX_PENDING_DEVICE_CODES` `5` unused codes per fleet, `LOGIN_RATE_PER_HOUR` `20` form submissions per hour per client address. Devices do not count in `NODES_PER_FLEET`.
- **Upgrading to v0.5.0.** `git pull`, then `docker compose up -d --build` with your `-f` options (or `COMPOSE_FILE`), so `enrolment` gets the new code and variables. That is not enough for `front` and `headscale`: the `Caddyfile` (or your `Caddyfile.tls`) and `headscale/config.yaml` are bind-mounted, so Compose does not see their change and keeps the containers running with the old files (no `/register/*` route, no `node.expiry: 0`). Recreate both, with the same `-f` options:

  ```
  docker compose up -d --force-recreate front headscale
  ```

  Restarting Headscale interrupts the control plane for a few seconds (boxes reconnect by themselves; established peer-to-peer links are not affected). Then check that `/register/*` reaches `enrolment` (not verified here: this upgrade was not run):

  ```
  curl -s https://your-relay/register/hskey-authreq-AAAAAAAAAAAAAAAAAAAAAAAA | grep recasaos-device-login
  ```

  No output means the app would land on Headscale's own page: `front` still runs the old Caddyfile, or the `@login` block is missing.
