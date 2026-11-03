# Metering relayed (DERP) traffic: spike result

Status: spike, measured on 2026-11-03. It does not block v1. Nothing here is implemented yet except what is stated in "What changed in this repository".

## Question

Boxes talk peer to peer when they can; only traffic that falls back to the DERP relay costs the operator bandwidth. Can we measure relayed traffic per box and per fleet, well enough to cap abuse (for example a monthly relayed-traffic quota per fleet), with Headscale and DERP as deployed? Can a quota be **enforced** (a fleet cut off), not only observed? And should DERP stay Headscale's embedded server or become a standalone `derper`?

## Method

Throwaway rig, deleted afterwards: the repository's e2e harness (`e2e/`: real `tailscale/tailscale:stable` containers, version 1.104.4, a test-only TLS front for `relay.test`) with two fleets of two nodes (A: a1, a2; B: b1, b2) and `TS_DEBUG_ALWAYS_USE_DERP=1` on every node. Each run first checked the path: `tailscale ping` answered `via DERP(relay)` and `direct connection not established`; `tailscale status` showed `active; relay "relay"`.

Known volume: `dd if=/dev/zero bs=1M count=50 | nc <peer> 9100` from a1 to a2 (50 MiB = 52,428,800 bytes), and 20 MiB from b1 to b2; the receiver counted `wc -c` and got exactly 52,428,800 and 20,971,520 bytes. Every counter below was read before and after, from inside the compose network (nothing was published).

Two stacks were measured:

1. As deployed: Headscale 0.29.7 with its embedded DERP (the metrics listener was switched on with `HEADSCALE_METRICS_LISTEN_ADDR=0.0.0.0:9090`, compose network only).
2. Standalone: Headscale with `derp.server.enabled: false` and a DERP map file pointing at `derp.test`; `derper` v1.104.5 (built with `go install tailscale.com/cmd/derper@latest`; Tailscale publishes no derper image) behind a Caddy TLS front that reverse-proxies to `derper:8090` over plain HTTP, started with `-verify-client-url http://headscale:8080/verify`.

## Results

Overhead: 50 MiB of payload is 56.0 MB on the DERP leg (1.068 times, measured; the cause, WireGuard, IP and DERP framing, is inferred); the ratio was identical for the 20 MiB transfer (22.4 MB).

| # | Source | What it exposes | Granularity | Verdict |
|---|---|---|---|---|
| a | Headscale `/metrics` (Prometheus) | `headscale_*` (nodestore, mapresponse, batcher), `http_requests_*`, `process_network_{receive,transmit}_bytes_total` of the whole Headscale process. For DERP only `http_request_*{endpoint="GET /derp/latency-check"}`. No DERP byte counter. | none for relay traffic | not usable |
| b | Embedded DERP, Headscale `/debug/varz` and `/debug/vars` | Only `derp_bytes_dropped`, `derp_packets_dropped` (by reason and kind) and `derp_websocket_accepts`. After 70 MiB relayed (about 80 MB on the wire) the only non-zero counter was `derp_bytes_dropped{reason="queue_head",kind="other"}` = 10496 (8 packets); nothing counted the forwarded bytes. The `/debug/` index does not list `/debug/clients/` or `/debug/traffic`; the paths probed (`/debug/derp/traffic`, `/debug/derpvarz`, `/derp`, `/derp/probe`) answered 404; `/debug/derp` only prints the DERP map. The contents of `/debug/vars` were not captured: that it carries no forwarded-byte counter is inferred (not measured). | none | not usable |
| c | Standalone `derper` `/debug/varz` and `/debug/clients/` | Totals `derp_bytes_received`, `derp_bytes_sent`, `derp_packets_received`, `derp_packets_sent`, `derp_current_connections`, `derp_clients_total`; and, **per connected node key**, `rxBytes`/`txBytes`/`rxPkts`/`txPkts`, `connNum`, `connectedAt`, `remote` (`/debug/clients/?all=1&format=json`, paginated, `limit` up to 1000, `sort=` and `after=`). | per node key | usable |
| d | Client side, `tailscale metrics print` | `tailscaled_inbound_bytes_total{path="derp"}`, `tailscaled_outbound_bytes_total{path="derp"}` (also `direct_ipv4`, `direct_ipv6`, `peer_relay_*`). a1 reported 56,019,588 bytes out via DERP; derper counted 56,015,868 from the same node. | per node, split relayed vs direct | accurate, but reported by the box, which an abuser controls: monitoring only, never enforcement |
| e | Network level, `/proc/net/dev` of the containers (what `docker stats` shows) | Totals per container. Headscale eth0 grew by 86.5 MB received and 87.5 MB sent for about 80.3 MB of client DERP output (about 8 % over the client output; the cause, framing, TCP and control-plane traffic, is inferred). Measured: every DERP connection reaches Headscale (`172.19.0.4`, the front Caddy) or `derper` (`172.19.0.5`, the TLS proxy) from the proxy's address. | one number per container; no node, no fleet; source address is the proxy, so per-IP counting (the brief's fallback b) is impossible behind a proxy | totals and alerts only |

Standalone derper, per-key readings after the controlled transfers (node keys matched to nodes and fleets through Headscale's `GET /api/v1/node`, which returns `nodeKey` and `user.name` = `f-<fleet id>` for every node):

| node (fleet) | `rxBytes` (sent into the relay) | `txBytes` (delivered to it) |
|---|---|---|
| a1 (A) | 56,015,868 | 1,357,560 |
| a2 (A) | 1,357,560 | 56,015,868 |
| b1 (B) | 22,406,596 | 532,940 |
| b2 (B) | 532,940 | 22,406,596 |

So fleet A relayed 57,373,428 bytes and fleet B 22,939,536 (sum of `rxBytes` of its nodes; each relayed byte is counted once at ingress and once as `txBytes` at the destination). A second run (50 MiB, a1 to a2) moved `rxBytes` of a1 by 56,018,192, again 1.068 times the payload.

Other measurements on the standalone stack:

- **A reconnect resets the counters.** After `docker restart` of a2 its key came back with a new `connNum` and `rxBytes`/`txBytes` of 0. A meter must therefore accumulate per connection; whatever flowed between the last scrape and the disconnect is lost (bounded by the scrape interval). `connNum` is a per-process counter (a2 came back with 5): after a `derper` restart it starts again at 1, so `(key, connNum)` alone is not a safe identity (see the follow-up design).
- **Admission is checked once, at connect.** `derper -verify-client-url` POSTs `{"NodePublic","Source"}` to Headscale's `/verify` (no local tailscaled needed, unlike `-verify-clients`). Headscale answered `{"Allow":true}` for a registered node key and `{"Allow":false}` for an unknown one, and `http_requests_total{endpoint="POST /verify"}` counted the calls. In `derp/derpserver` the check is called only when a connection is accepted (code reading of v1.104.5). Likewise from the code, not exercised: only a transport error is "fail open" (default `-verify-client-url-fail-open=true`), a non-200 answer or `Allow:false` refuses. The spike called `/verify` directly; no run had `derper` refuse a client on `Allow:false`.
- **No way to disconnect a client.** The `/debug/*` endpoints are read-only. Deleting a node in Headscale made the stock tailscale container exit (containerboot stopping when the node is logged out is the inferred cause) and its DERP connection vanished from `/debug/clients/` within 20 s; a modified client that keeps its already accepted connection is not shown to be cut, and by the code it would not be.
- **A per-connection bandwidth cap exists.** `derper -rate-config file.json` with `{"PerClientRateLimitBytesPerSec": 1048576}` limited a node to about 1 MiB/s (10 MiB took 10.7 s; 50 MiB took 2.7 s without a cap); `{}` plus `SIGHUP` removed the cap live. It is per connection, not per fleet, and not a quota.
- **Debug endpoints are closed by default.** `/debug/*` answered `403` from other containers on Headscale (its `/debug` is on the 9090 metrics listener, not behind a proxy) and on `derper`, also through the TLS proxy; `TS_ALLOW_DEBUG_IP=<scraper ip>` on `derper` opened it for that address only. The proxy must still route only `/derp`, `/derp/probe`, `/derp/latency-check` and `/generate_204`.
- **Cost.** `derper` with four connected clients, after the transfers: 15.8 MiB resident and 0.00 % CPU; Headscale 29.9 MiB. The listing of four clients is a few hundred bytes of JSON per client.

Not established (do not rely on it): refusal of a client at connect by `derper` on `Allow:false`, and the fail-open rule above (code reading only); behaviour of `-verify-client-url-fail-open=false` when Headscale is down; STUN on the standalone `derper` (disabled in the spike, `stunport: -1`); DERP over WebSocket; several `derper` instances (mesh); `/debug/clients/` cost with thousands of connections; throughput limits; a hostile client that keeps a connection open after its fleet is over quota.

## Decision

**(a) A per-fleet monthly relayed-traffic quota is implementable, but only with a standalone `derper`.** Headscale's embedded DERP exposes no per-client or even total forwarded-byte counter, and nothing at network level can tell fleets apart. A standalone `derper` gives per-node-key byte counters, Headscale gives node key to fleet, and `-verify-client-url` gives an enforcement hook at connect time.

**DERP choice: standalone `derper` for the quota; embedded DERP for v1.** The compose file is left unchanged for v1, because the embedded server is what the isolation e2e proves, nothing in v1 needs metering, and moving DERP also needs a derper image build, a proxy route, a DERP map file and a re-run of the e2e. The cost of switching later is small and the spike validated per-key counting and connect-time admission, not the follow-up enforcement path (designed, not built).

### Follow-up design (task "relayed-traffic quota")

The `derper` command line used in the spike is not preserved in the repository (the spike artifacts were throwaway), so the flags below are indicative and must be re-checked when implementing.

1. **DERP service.** Add `derper` to `compose.yaml` (image built from a Dockerfile that pins `tailscale.com/cmd/derper@v1.104.5` or newer; keep it close to the client version), flags `-a :8090 -http-port -1 -verify-client-url http://enrolment:8081/internal/derp/admit -verify-client-url-fail-open=false`, a volume for the server key (not verified: the flag list has no `-c` path, so which path derper persists its key to, and whether `/var/lib/derper` holds anything, must be confirmed; clients do not pin the DERP key, so this is a stability nicety, not a requirement), `expose` only, `3478/udp` published for STUN (default on; the spike ran with STUN off, so it is untested standalone). In `headscale/config.yaml`: `derp.server.enabled: false`, `derp.paths` pointing at a DERP map file with one region and node `hostname: <relay host>` (port 443). In the `front` Caddy route `/derp*` and `/generate_204` to `derper:8090`, never `/debug/*`. TLS stays at the operator's proxy, as today.
2. **Counter.** A goroutine in `enrolment` (or a small `meter` service) reads `/debug/clients/?all=1&format=json` of `derper` every 15 to 30 s (allow its address with `TS_ALLOW_DEBUG_IP`, or run the reader in the same network namespace). Identify a connection by `(key, connNum, connectedAt)` (`connNum` restarts at 1 after a `derper` restart, which the restart-to-cut below triggers), or treat a decreasing `rxBytes` as a new connection. Per connection it adds `rxBytes - lastSeen` (the full value for a new one; forget entries that disappear). `lastSeen` must be persisted: after an enrolment restart with an empty map, the full values of live connections would be added again (double count, which could cut legitimate fleets). A client that connects, sends and disconnects between two scrapes is never seen, and doing so faster than the scrape interval evades the meter. Reconcile: compare the global `derp_bytes_received` with the sum of attributed bytes, and alert on the unattributed remainder.
3. **Node key to fleet.** `GET /api/v1/node` through the `internal/headscale` client, which must be extended: its `hsNode` struct has no `nodeKey` field today. The Headscale user `f-<fleet id>` is the fleet. Refresh each pass. A refresh on an unknown key is reachable by anyone who can open a DERP connection (`/verify` runs after the handshake, with random keys), so it needs a negative cache and a rate limit, or a cheap per-key Headscale `/verify` lookup instead. Unknown keys are not attributed and get refused at admission.
4. **Storage and period.** A table `usage(fleet_id, period, relayed_bytes)` in the existing store, period = UTC calendar month (`2026-11`); the reset is the key changing, with no job. Quota in an environment variable (`RELAY_QUOTA_BYTES_PER_MONTH`, default 0 = unlimited), later per fleet.
5. **Enforcement.** `POST /internal/derp/admit` on the enrolment service (port 8081 is not published; it stays internal only because the Caddyfile routes `/v1/*` to enrolment and everything else to Headscale: that is an invariant, and a test must assert that `/internal/*` through `front` returns 404): `Allow` only for a node key that Headscale knows and whose fleet is under its quota; the same answer Headscale's `/verify` gives, plus the quota. This stops reconnects of an over-quota fleet. To cut connections that are already open, which `derper` cannot do, something restarts `derper` when a fleet crosses its quota: all boxes reconnect within seconds, direct paths are unaffected, the over-quota fleet is refused. Two hazards. First, a tenant can trigger it: one burning its own quota, or creating several fleets, makes every box on the relay reconnect once per period, while other over-quota connections stay open in between; the collateral hits all other fleets. So make the restart edge-triggered, once per fleet per period (not a timer). Second, the restarter needs privileges: the Docker socket is root-equivalent on the host and must not go to enrolment or a sidecar; the zero-socket alternative is a flag file on a shared volume that makes `derper` exit, with `restart: unless-stopped`. Alternatives: delete the fleet's nodes (works for stock clients, shown above), or a small patch to `derper` adding a kick-by-key endpoint (maintenance cost).
6. **Hazards.**
   - Fail-closed (`-verify-client-url-fail-open=false`) makes enrolment plus Headscale a single point of failure for every relay connect; after a `derper` restart all boxes hit admit at once.
   - Headscale's `/verify` is already reachable through `front` today (the Caddyfile only blocks `/api`): a registered-node-key oracle, low impact.
   - `TS_ALLOW_DEBUG_IP` pins one IP, so pin the scraper's address in the compose network.
   - `/debug/clients` exposes node keys and remote addresses: keep it unpublished and unrouted.
7. **Observability.** Expose the per-fleet counters on a loopback or internal-only Prometheus endpoint, so the operator can alert at 80 % of a quota.
8. **Tests.** Reuse `e2e/`: extend the harness so the stack runs with `derper`, assert `usage` after a known transfer (within the 1.07 overhead), assert refusal after the quota, and re-run `TestFleetsAreIsolated` on that topology.

### Until then (v1): coarse protection and what stays uncovered

- Cap total relay bandwidth at the host or at the operator's proxy, and alert on the container's byte counters (`docker stats`, cAdvisor, or `/proc/net/dev` of `headscale` and `front`): a spike in `headscale` sent bytes is relayed traffic plus control plane, which is mostly relay.
- The Headscale metrics listener could be enabled on the compose network (`metrics_listen_addr: 0.0.0.0:9090`, never published) for control-plane alerts; it carries no relay traffic, so it was not enabled.
- Uncovered until the quota ships: which fleet or box is responsible for a spike, and any per-fleet limit. The existing limits (nodes per fleet, key and fleet creation rates, idle-fleet janitor) bound the number of abusers but not what each relays.
- Per-box relayed bytes can be read from the box itself (`tailscale metrics print`) for support cases, never as proof.

## What changed in this repository

The documentation only (this file, a README link, and comments in `compose.yaml` and `headscale/config.yaml` that now point here). The spike rig, its compose override, the derper image and all containers, networks and volumes were removed. No port is published that was not already.
