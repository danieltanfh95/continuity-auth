# continuity-auth: runbook

Operational guidance for on-call. For deployment, see `deployment.md`. For threat-model background, see `threat-model.md`.

## Quick reference

- **Healthcheck**: `curl https://fl.example.com/healthz` → 200
- **Readiness**: `curl https://fl.example.com/readyz` → 200 with `{ready: true, db_status: "ok"}`
- **Metrics**: `curl -H "Authorization: Bearer $CONTINUITY_AUTH_PROM_BEARER" https://fl.example.com/metrics`
- **Logs**: `kubectl logs -l app=continuity-auth --tail=200` (or your stack equivalent)

## Common alerts

### `cauth_verify_latency_seconds{quantile="0.99"} > 0.025`

P99 verify latency exceeded 25 ms. Investigation:

1. Check Datalevin write latency: `cauth_datalevin_write_latency_seconds`.
2. If Datalevin is the bottleneck, check the writer node's IO. LMDB single-writer means write contention here is expected under load; consider sharding (see deployment.md) if sustained.
3. If verify latency is high but Datalevin is fine, the signature verify path may be GC-thrashing. Check JVM `-XX:NativeMemoryTracking` or thread dumps.

### `rate(cauth_signature_verify_failures_total[5m]) > 10`

Elevated signature verify failures. Possible causes:

1. **A new attacker probing**: check `cauth_nonce_replay_attempts_total` for correlation. If replays are also up, this is enumeration.
2. **A bug in a host integration**: contact host owner; recent deploy of theirs?
3. **Clock skew**: check the host's clock vs ours. Server-side `journalctl -u chrony` etc.

### `rate(cauth_nonce_replay_attempts_total[5m]) > 50`

Elevated replay attempts. This is suspicious. Action:

1. Identify which integration is affected (correlate request-ids in logs).
2. If the rate is sustained > 1 minute, alert security.
3. Replays are correctly rejected; no immediate user impact, but indicates active enumeration.

### `cauth_identity_total{tier="banned"}` is non-zero and growing

Identities being demoted to `:banned`. Investigation:

1. Pull a sample log line for a recently-banned identity.
2. Confirm the score trajectory in the audit log (`trust-event/*`).
3. If a legitimate user is incorrectly banned, the runbook for manual reset is `POST /v1/admin/reset-tier` *(planned v1.1)*.

### `/readyz` returning 503

Storage is unreachable. Action:

1. Check Datalevin server status if in production mode.
2. Check network between app instances and Datalevin.
3. Check disk space on Datalevin nodes.
4. If recovery is not imminent, mark this instance unhealthy at the load balancer and divert traffic.

## Manual queries (Datalevin REPL)

```bash
clojure -M:dev
;; in REPL:
(require '[datalevin.core :as d])
(def conn (d/get-conn "dtlv://admin:pw@host:8898/continuity-auth"))
(d/q '[:find ?id ?score ?ever
       :where
       [?e :identity/id ?id]
       [?e :identity/score ?score]
       [?e :identity/ever-tracked? ?ever]] (d/db conn))
```

## Bootstrap rate-limit tuning

`/v1/bootstrap` is gated by per-IP exponential backoff with optional
IP-anchored signal multipliers. The defaults in [resources/config.edn](../resources/config.edn)
ship safe for residential and shared-NAT traffic. Adjust only on observed
abuse or operator-confirmed compromise.

### Defaults

| Knob | Default | Env override | Effect |
|---|---|---|---|
| `:floor-ms`              | 1000 (1s)     | `CONTINUITY_AUTH_BOOT_FLOOR_MS`     | first allow's penalty |
| `:cap-ms`                | 60000 (60s)   | `CONTINUITY_AUTH_BOOT_CAP_MS`       | absolute upper bound on any penalty |
| `:doubling-factor`       | 2             | `CONTINUITY_AUTH_BOOT_FACTOR`       | strike multiplier per consecutive allow |
| `:reset-threshold-ms`    | 300000 (5m)   | `CONTINUITY_AUTH_BOOT_RESET_MS`     | quiet-time before strike count resets |
| `:signals-enabled?`      | true          | `CONTINUITY_AUTH_BOOT_SIGNALS`      | gate the indexed AVET read |
| `:signal-read-timeout-ms`| 50            | `CONTINUITY_AUTH_BOOT_SIG_TIMEOUT`  | hard deadline on the read |
| `:signal-cache-ttl-ms`   | 300000 (5m)   | `CONTINUITY_AUTH_BOOT_SIG_TTL`      | per-IP cache freshness window |
| `:datacenter-cidrs`      | `""` (empty)  | `CONTINUITY_AUTH_BOOT_DC_CIDRS`     | comma-separated CIDR list, ×5 multiplier |

### Datacenter / cloud-provider CIDR refresh

The Tier 3 multiplier penalises IPs that fall inside a known datacenter or
cloud-provider block. The project ships an empty list by default. Opinionated
curation belongs to the operator, not the library.

Recommended sources (refresh roughly monthly, since cloud providers publish JSON or
plain-text ranges):

- **AWS**: `https://ip-ranges.amazonaws.com/ip-ranges.json` (filter on
  `prefixes[].ip_prefix` where `region != global` if you want regional
  granularity).
- **Hetzner**: `https://docs.hetzner.com/cloud/general/ip-ranges/`
  (a small fixed list).
- **DigitalOcean**: `https://digitalocean.com/geo/google.csv`.
- **OVH**: `https://github.com/ovh/public-cloud-ip-ranges` (community-maintained
  mirror, verified against OVH's published feed).
- **Google Cloud**: `https://www.gstatic.com/ipranges/cloud.json`.
- **Microsoft Azure**: published weekly to `https://www.microsoft.com/...`
  (download URL changes, check the Azure docs at refresh time).

Set `CONTINUITY_AUTH_BOOT_DC_CIDRS` to the concatenated comma-separated list:

    CONTINUITY_AUTH_BOOT_DC_CIDRS="3.0.0.0/8,5.9.0.0/16,46.4.0.0/16,..."

The list is parsed at startup into a sorted vector of [low, high]
inclusive-Long IPv4 ranges. The per-bootstrap membership check is O(log N).
**IPv4 only.** IPv6 ranges are silently ignored.

**False-positive cost.** A residential user on a known datacenter VPN
exit will see the ×5 multiplier on bootstrap only. Once they bootstrap
once, subsequent `/verify` is unaffected (the protocol keeps IP advisory
everywhere except bootstrap). Acceptable trade-off for most deployments.

**Refresh rhythm.** Cloud providers add new ranges several times a year.
Stale lists fail safely (an attacker's new IP just falls through to Tier
1 + Tier 2 signals, still defended but no Tier 3 boost). A monthly
refresh job is enough. No rush on missed updates.

### Tuning under attack

If an active attack escapes the defaults:

1. **Drop `:cap-ms` to 300000** (5 minutes). Caps each identity at one
   per 5 minutes per IP steady-state. Legit users behind shared NAT will
   feel one delay before bootstrap.
2. **Raise `:doubling-factor` to 3.** Staircase climbs 1s → 3s → 9s →
   27s → cap. More aggressive escalation against burst attackers.
3. **Populate `:datacenter-cidrs`** if not already (see above).
4. **Watch `cauth_bootstrap_signal_fallback_total`.** A climbing series
   means the Datalevin index is slow. Raise `:signal-read-timeout-ms` to
   200, or set `:signals-enabled? false` to fall back to pure Tier 1.

### Tuning for trusted-network deployments

If `/v1/bootstrap` is only reachable from an authenticated reverse proxy
or a private network where every IP is trusted, set
`CONTINUITY_AUTH_BOOT_FLOOR_MS=0` and `CONTINUITY_AUTH_BOOT_CAP_MS=0`. The limiter then runs
as a no-op and the staircase collapses to no penalty. Use only when
an upstream gate already bounds bootstrap rate.

## Capacity planning

| Metric | Threshold | Action |
|---|---|---|
| Sustained `/verify` rate per instance | 1500 req/s | Add an instance. |
| Sustained Datalevin write latency P99 | > 10 ms | Investigate writer-node IO. |
| Datalevin disk fill | > 70% | Run archival job manually. Expand volume. |
| Memory RSS per instance | > 1 GiB | Investigate. Expected baseline is ~700 MiB at moderate load. |

## Forced reset / manual interventions

### Revoking a pubkey (security incident)

**Preferred path: admin CLI** (no DB downtime, audited via `:admin-revoke` trust event).

```bash
CONTINUITY_AUTH_ENDPOINT=https://fl.example.com \
CONTINUITY_AUTH_ADMIN_KEY_ID=ops-01 \
CONTINUITY_AUTH_ADMIN_SECRET_FILE=/etc/cauth/admin-ops-01.secret \
continuity admin revoke-key <b64url-thumbprint>
```

The CLI signs with HMAC-SHA256. The server validates against the keystore at `CONTINUITY_AUTH_ADMIN_HMAC_KEYS_PATH` (a `{:keys [{:id, :secret-b64}]}` EDN file loaded at startup). On success the pubkey's `:pubkey/revoked-at` is set to `now` and subsequent `/verify` returns `E_FORBIDDEN`.

**Fallback path: direct DB** (when the server is down or the keystore is lost).

```bash
clojure -M:dev
(require '[continuity-auth.server.storage.datalevin :as dtlv]
         '[continuity-auth.server.storage.protocol :as s])
(def store (dtlv/open "dtlv://..."))
(s/transact! store [{:db/id [:pubkey/id <thumbprint-bytes>]
                     :pubkey/revoked-at (java.util.Date.)}])
```

### Inspecting effective configuration

```bash
CONTINUITY_AUTH_ENDPOINT=https://fl.example.com \
CONTINUITY_AUTH_ADMIN_KEY_ID=ops-01 \
CONTINUITY_AUTH_ADMIN_SECRET_FILE=/etc/cauth/admin-ops-01.secret \
continuity admin config | jq
```

This dumps the aero-resolved config (env vars applied). Sensitive fields (`:prometheus-bearer`, `:host-keys-path`, `:admin-keys-path`) come back as `"<redacted>"`. Use this to verify what the server *actually* loaded, especially when a redeploy did or didn't pick up an expected change.

### Changing configuration

**continuity-auth has no live-config-mutation surface, by design.** Dynamic config is a footgun: it races with in-flight requests, defeats infrastructure-as-code audit, and produces deploys that don't match git. The canonical path is:

1. Update `resources/config.edn` (or the env var override) in the source repo.
2. Open a PR; review; merge.
3. Redeploy. The new pod loads the new config on startup.
4. Verify with `continuity admin config`.

The only attributes that change at runtime are stored in the database (trust scores, pubkey revocations, identity tiers) and are mutated via the API.

### Erasing an identity (GDPR)

The HTTP `DELETE /v1/identity/{id}` endpoint is planned for v1.1. In v1.0, perform the retraction manually:

```bash
clojure -M:dev
(require '[continuity-auth.server.storage.datalevin :as dtlv]
         '[continuity-auth.server.storage.protocol :as s])
(def store (dtlv/open "dtlv://..."))
;; Find the identity:
(def eid (->> (s/q store (s/snapshot store)
                    '[:find [?e ...]
                      :in $ ?id
                      :where [?e :identity/id ?id]]
                    [#uuid "..."])
              first))
;; Retract identity, its tuples, pubkeys, host-links, requests, trust-events.
;; (One transact, atomic.)
;; Leave an audit stub.
(s/transact! store
  [...])  ;; see ontology.md §I9 and the planned implementation
```

Document the request, requester, and outcome in the operator's incident log.

## Diagnostics

### "Why was this request throttled?"

Look up the most recent `:request/identity` for the relevant identity-ref:

```clojure
(d/q '[:find [(pull ?r [:request/ts :request/outcome :request/match-axes :request/identity]) ...]
       :in $ ?id
       :where
       [?i :identity/id ?id]
       [?r :request/identity ?i]
       [?r :request/ts ?ts]]
     (d/db conn) #uuid "...")
```

Then check the bucket state. Each `(identity, window)` has at most one token-bucket entity; `:bucket/tokens` is the current count (capped at the tier's capacity) and `:bucket/last-refill-ms` is the epoch ms of the last check that consumed or observed it. `tokens-now = min(capacity, tokens + (now-ms - last-refill-ms) * leak-rate / 1000)`.

```clojure
(d/q '[:find [(pull ?b [:bucket/window :bucket/tokens :bucket/last-refill-ms]) ...]
       :in $ ?id
       :where
       [?i :identity/id ?id]
       [?b :bucket/identity ?i]]
     (d/db conn) #uuid "...")
```

### "Why is this user banned?"

```clojure
(d/q '[:find [(pull ?e [:trust-event/ts :trust-event/reason :trust-event/delta :trust-event/score-after]) ...]
       :in $ ?id
       :where
       [?i :identity/id ?id]
       [?e :trust-event/identity ?i]]
     (d/db conn) #uuid "...")
```

The score-trajectory tells you which signals contributed.

## IP-HMAC keystore

`:tuple/ip-hash` stores `HMAC-SHA256(client-ip)` under a server-side keystore secret. The keystore is a single 32-byte secret loaded once at startup. Why this exists is in `docs/threat-model.md` "PII minimisation".

**Resolution precedence** (in `continuity-auth.server.crypto.ip-hmac/load-or-create-key!`):

1. Env `CONTINUITY_AUTH_IP_HMAC_KEY` (base64url, 32 raw bytes). Used directly when set. Never written to disk. The path orchestrators (Kubernetes Secret, Vault, AWS Secrets Manager) integrate with.
2. Env `CONTINUITY_AUTH_IP_HMAC_KEY_PATH` overrides the configured `:key-path` in `resources/config.edn`.
3. Configured `:key-path` (default `/var/lib/continuity-auth/ip-hmac.key`).
4. Auto-generation. With no file at the resolved path on startup, 32 `SecureRandom` bytes are written there with POSIX `rw-------`. The next startup reads it back.

**File format**: EDN, `{:secret-b64 "<base64url, 32 bytes>"}`.

**Backup.** Back up the keyfile alongside the Datalevin store. Without it, the cluster-by-IP grouping fragments: the same physical IP under a new key produces a new hash, lands in a new tuple, breaks the cluster's history. Operationally this is a forced re-bootstrap for every active client.

**Rotation (manual).** Rotation is a redeploy with a new key. Pre-rotation tuples retain their old-key hashes. Post-rotation observations from the same IP produce new-key hashes and create new tuples. The cluster fragments for the rotation generation. The current build has no hot rotation. Hot rotation would require either keyed columns (per-tuple `:tuple/ip-key-id`) or a re-hash migration with both keys available, neither of which is in scope. Forced rotation (e.g. suspected key compromise) accepts the downtime.

**Disposal.** A destroyed keyfile without a backup is data loss for the IP axis. Trust scores anchored in pubkey continuity survive. Cluster-by-IP grouping starts fresh. No key, no IP linkage. The pubkey and fp signals still flow.

**Auditing the keyfile.**

```bash
# perms (expected: rw-------)
stat -c '%a %n' /var/lib/continuity-auth/ip-hmac.key

# secret length (32 bytes after b64url decode)
cat /var/lib/continuity-auth/ip-hmac.key
# {:secret-b64 "..."}
```

**IPv6.** The hash takes whatever the trusted-proxy header delivers. No canonicalisation (no collapse of `::ffff:1.2.3.4` into `1.2.3.4`). When upstream proxies emit both v4-mapped and dotted-quad forms for the same client, the two hash to different values. Canonicalisation at the proxy is the simpler fix. Canonicalisation in continuity-auth itself stays open if it becomes load-bearing.

## Escalation

- Security incidents: pager L2.
- Datalevin cluster outage: pager L2 + database SME.
- Host integration bugs: contact the host team via your usual channel.
