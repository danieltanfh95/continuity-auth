# continuity-auth — deployment guide

This guide describes the production deployment topology and the operational knobs an SRE needs to know about.

## Container

A single uberjar deployed in a slim base image. Multi-stage `Dockerfile` produces the runtime image with an AppCDS archive for faster startup.

```bash
docker build -t continuity-auth:vX.Y.Z .
```

Image targets:
- Memory: 512 MB heap + 200 MB off-heap (LMDB mmap)
- CPU: 2 vCPU sustains ~2000 req/s `/verify`
- Startup: ≈ 1.5 s with AppCDS
- Health: `/healthz` and `/readyz`

## Database

Two modes are supported transparently at the call site:

### Dev / staging — embedded LMDB

`FPL_DTLV_URI=/var/data/continuity-auth.dtlv`

Single-process. The app opens an LMDB env directly. Suitable for local development, single-instance staging, and CI.

### Production — Datalevin server mode

`FPL_DTLV_URI=dtlv://user:pw@host:8898/continuity-auth`

Multi-instance. App instances are stateless and scale horizontally; all instances talk to the Datalevin server. For HA, run a 3-node Raft Datalevin cluster.

## Configuration

Aero EDN, loaded at startup from `resources/config.edn` with the profile selected by `FPL_PROFILE` (or `--profile <kw>`).

Environment-variable overrides (all `FPL_*`):

| Env var | Default | Purpose |
|---|---|---|
| `FPL_PROFILE` | `prod` | aero profile (dev/test/prod) |
| `FPL_HTTP_HOST` | `0.0.0.0` | Jetty bind address |
| `FPL_HTTP_PORT` | `8080` | Jetty port |
| `FPL_HTTP_THREADS` | `64` | Jetty max threads |
| `FPL_DTLV_URI` | `/tmp/continuity-auth-dev.dtlv` (dev), required (prod) | Datalevin URI |
| `FPL_DTLV_DB_NAME` | `continuity-auth` | Datalevin DB name |
| `FPL_DTLV_WRITE_MODE` | `async` | `:async` or `:sync` |
| `FPL_TRUSTED_PROXY_CIDRS` | (empty) | Comma-separated CIDR allowlist for IP-header proxy |
| `FPL_IP_HEADER` | `x-forwarded-for` | Header to read client IP from when behind trusted proxy |
| `FPL_LOG_LEVEL` | `info` | mulog level |
| `FPL_PROM_BEARER` | (empty) | Bearer token for `/metrics`; if empty, endpoint is open |
| `FPL_OTEL_ENDPOINT` | (empty) | OTLP exporter endpoint; if empty, no trace export |

## Migrations

```bash
clojure -M:migrate --uri "dtlv://user:pw@host:8898/continuity-auth"
```

The runner reads the persisted `:schema/version` and applies pending migrations in order. The app refuses to start if the persisted version mismatches the code version — run the migrator first.

## Observability

- **Metrics**: `/metrics` exposes Prometheus text format. Scrape interval recommended 15 s. Key series:
  - `fpl_verify_total{outcome, tier}` (counter)
  - `fpl_verify_latency_seconds` (histogram)
  - `fpl_signature_verify_failures_total{alg}` (counter)
  - `fpl_nonce_replay_attempts_total` (counter)
  - `fpl_cluster_merge_total{kind}` (counter)
  - `fpl_identity_total{tier}` (gauge)
- **Logs**: mu/log structured JSON to stdout. Forward via the container runtime (Docker / Kubernetes) to your log sink.
- **Tracing**: in v1.0 only the `X-Request-Id` correlation header is honoured (echoed back on every response). The OpenTelemetry SDK deps and `FPL_OTEL_ENDPOINT` config knob are loaded but no exporter is wired — see Open operator items below. Setting the env var without the exporter has no effect.

## Health and readiness

- `GET /healthz` — liveness. 200 once Jetty is up.
- `GET /readyz` — readiness. 200 when storage is reachable. Tie this into the load balancer's health check; do not route traffic if it returns 503.

## Backup

LMDB hot-backup via Datalevin's `copy` operation. Nightly cron recommended:

```bash
dtlv copy <source-uri> /var/backup/continuity-auth-$(date +%Y%m%d).dtlv
```

Then upload to object storage. Retention: 30 days minimum.

For HA cluster failure, restore by stopping all nodes, copying the backup into the leader's data dir, and restarting.

## Resource sizing

For a single app instance, 2 vCPU + 1 GiB RAM handles ~2000 req/s on `/verify` at P99 < 25 ms.

Datalevin storage growth (rough):
- `request_event`: ~150 bytes per request × peak rate × 30-day retention. At 100 req/s sustained: ~40 GB hot. Plan 100 GB SSD per Datalevin node.
- `tuple` + `identity` + `pubkey`: ~1 KB per identity total. 1M identities = ~1 GB.
- `nonce_cache`: bounded by 120-second TTL × peak rate. Negligible (~20 MB at 1000 req/s).

Archival job runs nightly: moves `request_event` rows older than 30 days to compressed EDN in object storage and retracts them from the live DB. Configure threshold via the operator's preferred scheduler.

## Secrets

- Host integration HMAC keys (`/v1/link-account` attestations): per-host shared secret, rotated quarterly with overlap. Load at startup from your secret manager (Vault, AWS Secrets Manager, GCP Secret Manager).
- Admin HMAC keys (`/v1/admin/*`): separate key, rotated similarly.
- TLS termination: handled by ingress (recommended) or by Jetty with the configured cert path.

Secrets are never logged. Use SIGHUP to re-read at runtime if your secret-manager rotation is automated.

## Graceful shutdown

The JVM shutdown hook in `main.clj` halts the integrant system in reverse order:

1. Jetty stops accepting new connections; in-flight requests drain.
2. Nonce sweeper stops.
3. Storage closes.

SIGTERM is the standard signal. Allow ≥ 15 s for graceful drain before SIGKILL.

## Disaster recovery

| Scenario | Action |
|---|---|
| Single app-instance crash | Restart; the system is stateless. |
| Datalevin node failure (HA cluster) | Raft elects a new leader automatically. |
| Whole Datalevin cluster loss | Restore from latest backup. Accept ≤ 24 h of nonce-cache loss (replays from that window become possible; mitigated by clock-skew window). |
| Schema migration failure | The migrator is one-shot and idempotent; re-run after fixing root cause. The app refuses to start until version matches. |

## Open operator items (v1.0)

- HA cluster failover is documented but not yet exercised in production by anyone other than the author. Plan a chaos test in your environment.
- The trace exporter is OTLP; if your stack uses a different transport (Jaeger HTTP, Zipkin), wrap or replace `observability/tracing.clj` (not yet implemented as of this writing — task #14 partial).
- The host-link path is specified but not yet implemented (task #16 pending). v1.0 ships without tier uplift via account; tier uplift via sustained LS-anchored history works.
