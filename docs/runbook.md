# continuity-auth — runbook

Operational guidance for on-call. For deployment, see `deployment.md`. For threat-model background, see `threat-model.md`.

## Quick reference

- **Healthcheck**: `curl https://fl.example.com/healthz` → 200
- **Readiness**: `curl https://fl.example.com/readyz` → 200 with `{ready: true, db_status: "ok"}`
- **Metrics**: `curl -H "Authorization: Bearer $CAUTH_PROM_BEARER" https://fl.example.com/metrics`
- **Logs**: `kubectl logs -l app=continuity-auth --tail=200` (or your stack equivalent)

## Common alerts

### `cauth_verify_latency_seconds{quantile="0.99"} > 0.025`

P99 verify latency exceeded 25 ms. Investigation:

1. Check Datalevin write latency: `cauth_datalevin_write_latency_seconds`.
2. If Datalevin is the bottleneck, check the writer node's IO. LMDB single-writer means write contention here is expected under load; consider sharding (see deployment.md) if sustained.
3. If verify latency is high but Datalevin is fine, the signature verify path may be GC-thrashing — check JVM `-XX:NativeMemoryTracking` or thread dumps.

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

## Capacity planning

| Metric | Threshold | Action |
|---|---|---|
| Sustained `/verify` rate per instance | 1500 req/s | Add an instance. |
| Sustained Datalevin write latency P99 | > 10 ms | Investigate writer-node IO. |
| Datalevin disk fill | > 70% | Run archival job manually; expand volume. |
| Memory RSS per instance | > 1 GiB | Investigate; expected baseline is ~700 MiB at moderate load. |

## Forced reset / manual interventions

### Revoking a pubkey (security incident)

**Preferred — admin CLI** (no DB downtime, audited via `:admin-revoke` trust event):

```bash
CAUTH_ENDPOINT=https://fl.example.com \
CAUTH_ADMIN_KEY_ID=ops-01 \
CAUTH_ADMIN_SECRET_FILE=/etc/cauth/admin-ops-01.secret \
continuity admin revoke-key <b64url-thumbprint>
```

The CLI signs with HMAC-SHA256; the server validates against the keystore at `CAUTH_ADMIN_HMAC_KEYS_PATH` (a `{:keys [{:id, :secret-b64}]}` EDN file loaded at startup). On success the pubkey's `:pubkey/revoked-at` is set to `now` and subsequent `/verify` returns `E_FORBIDDEN`.

**Fallback — direct DB** (when the server is down or the keystore is lost):

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
CAUTH_ENDPOINT=https://fl.example.com \
CAUTH_ADMIN_KEY_ID=ops-01 \
CAUTH_ADMIN_SECRET_FILE=/etc/cauth/admin-ops-01.secret \
continuity admin config | jq
```

This dumps the aero-resolved config (env vars applied). Sensitive fields (`:prometheus-bearer`, `:host-keys-path`, `:admin-keys-path`) come back as `"<redacted>"`. Use this to verify what the server *actually* loaded — useful when a redeploy did or didn't pick up a change you expected.

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

Then check the bucket state:

```clojure
(d/q '[:find [(pull ?b [:bucket/window :bucket/start :bucket/count]) ...]
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

## Escalation

- Security incidents: pager L2.
- Datalevin cluster outage: pager L2 + database SME.
- Host integration bugs: contact the host team via your usual channel.
