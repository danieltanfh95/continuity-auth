# continuity-auth — HTTP API (v1)

All endpoints are HTTPS, JSON over HTTP/1.1 or HTTP/2. UTF-8 throughout. Every request and response carries an `X-Request-Id` correlation header.

The error model is uniform. All error responses share the shape:

```json
{ "ok": false, "retry_after_ms": <long>, "code": "E_<CODE>" }
```

`code` is a public-stable opaque token. We do not disclose which check failed (signature vs. replay vs. malformed input). See `docs/threat-model.md` T10.

| Status | Code           | Meaning |
|---|---|---|
| 400 | `E_BAD_REQUEST`  | Malformed input, missing field, schema violation |
| 401 | `E_UNAUTHORIZED` | Signature or HMAC failed, key unknown, clock-skew window violated |
| 403 | `E_FORBIDDEN`    | Revoked pubkey, banned tier |
| 404 | `E_NOT_FOUND`    | Identity not found |
| 409 | `E_REPLAY`       | Nonce already seen |
| 409 | `E_CONFLICT`     | Integrity error (orphan pubkey, etc.) |
| 429 | `E_RATE`         | Rate limit hit |
| 500 | `E_INTERNAL`     | Unexpected server failure |
| 503 | `E_UNAVAILABLE`  | Storage unreachable |

## Envelope wire format

Every signed request body carries an `envelope` object:

```json
{
  "v":           "FPL2\n",
  "method":      "POST",
  "path":        "/v1/verify",
  "body_sha":    "<base64url(SHA-256(body))>",
  "ts":          "2026-05-24T12:34:56.789Z",
  "nonce":       "<base64url(16 random bytes)>",
  "fp":          "<base64url(32-byte fingerprint digest)>",
  "key_id":      "<base64url(32-byte SHA-256 of pubkey)>",
  "host_user_id": "<optional string>",
  "alg":         "ed25519" | "p256",
  "sig":         "<base64url(64-byte signature R||S)>"
}
```

The signature is computed over a length-prefixed binary form of the envelope (without `v`, `alg`, `sig`). See `docs/crypto-protocol.md` for the exact byte layout.

## Endpoints

### `POST /v1/bootstrap`

First signed request from a fresh keypair. Creates the identity at anonymous tier.

**Request body:**
```json
{
  "envelope": <envelope>,
  "pubkey":   "<base64url(canonical pubkey bytes)>",
  "alg":      "ed25519" | "p256"
}
```

**Response (201):**
```json
{
  "ok":           true,
  "identity_ref": "<uuid>",
  "tier":         "anonymous"
}
```

**Errors:** `E_BAD_REQUEST`, `E_UNAUTHORIZED` (signature failed, clock-skew exceeded), `E_REPLAY`.

### `POST /v1/verify`

Main rate-limit decision path. The host backend calls this for every request it wants to rate-limit.

**Request body:**
```json
{ "envelope": <envelope> }
```

**Response (200, allow):**
```json
{
  "ok":              true,
  "identity_ref":    "<uuid>",
  "tier":            "anonymous" | "tracked" | "penalized" | "banned",
  "retry_after_ms":  0,
  "priority_weight": 30.0
}
```

**Response (429, throttle):** standard error shape with `code = "E_RATE"`, `retry_after_ms > 0`, and `priority_weight` carried through so hosts can place the failed request into a tiered retry queue. An optional `scope` field names which gate fired:

```json
{ "ok": false, "code": "E_RATE", "retry_after_ms": 1200, "priority_weight": 1.0, "scope": "class" }
```

| `scope`   | Meaning |
|-----------|---------|
| `"caller"` | This identity drained its own per-caller bucket. Back-pressure is specific to this key. |
| `"class"`  | The shared per-tier ceiling is saturated; the tier as a whole is shedding load even though this caller may be within its own budget. |

`scope` is advisory: hosts that don't branch on it can ignore it. It exists so a host can tell "this caller is hot" (raise their bar / queue them) from "the service is busy" (back off and retry the whole tier later). Absent when no class cap is configured.

**`priority_weight`** is a host-side scheduling input: a relative weight for weighted fair queuing or priority admission. continuity-auth itself does **not** enforce priority. Hosts may consult the weight to order their own queues or ignore it entirely. Default values mirror the `:1m` capacity ratios in `:ratelimit/:tiers`:

| Tier         | `priority_weight` |
|--------------|-------------------|
| `tracked`    | 30.0              |
| `anonymous`  | 1.0               |
| `penalized`  | 0.0               |
| `banned`     | 0.0               |

The numeric scale is advisory and non-normative. Hosts that want a different ordering can map the `tier` string directly. The weight is included so the common case (weighted fair queuing keyed on tier) requires zero host-side configuration. The table above is the default; operators can override any tier's weight via `:ratelimit/:priority-weights` (see config knobs below), and the value returned in `priority_weight` reflects the configured map.

**Rate-limit shape:** the per-tier limits in `:ratelimit/:tiers` are token-bucket capacities. Each window has its own bucket per identity. Bursts up to `capacity` are absorbed and steady-state throughput equals the leak rate. `retry_after_ms` is the time until the next token leaks in, not the time until the window edge. Trusted callers recover faster from short bursts than they did under the prior sliding-window engine.

**Configurable bucket parameters.** A `:ratelimit/:tiers` cell may be a bare number (capacity; leak derived as `capacity / window_seconds`, the v0.2 behavior) **or** a map `{:capacity <long> :leak-per-sec <double>}` that sets the leak rate independently — e.g. a large burst capacity with a slow steady drain. Both forms are accepted per-cell; a bare number and the derived-leak map are equivalent.

**Class-level back-pressure caps.** Per-caller buckets bound each identity but not the *aggregate*: many distinct identities, each within its own budget, can collectively swamp a tier. `:ratelimit/:class-caps` adds one shared bucket per `(tier, window)` that all callers of that tier draw from. A request must pass **both** its own per-caller bucket **and** its tier's class bucket; a denial at either gate consumes no tokens at the other (a caller isn't penalized for a class-level shed). Class caps are per-tier, per-window, with the same bare-number-or-map cell shape as `:tiers`. Only the `(tier, window)` pairs you list are capped; the feature is **off by default** (absent `:class-caps` ⇒ pure per-caller behavior, identical to v0.2). When a class cap fires, the 429 carries `scope: "class"`.

**How a caller climbs tiers.** The `tier` is a projection of a trust
score, and that score is a **spaced-continuity memory weight**, not a
per-request accumulator. Trust rewards *spaced* recurrence — the same key
returning over days and weeks — far more than *massed* frequency — many
requests in a short burst. A brand-new key starts at the score floor
(`anonymous`) no matter how it bootstraps; it earns `tracked` through
sustained, low-anomaly observation over calendar time (or via a host-link).
Idle trust decays with a ~30-day half-life, and axis mismatches / anomalies
erode the score toward `banned` via a violation rate. The weight constants
(`freq-cap`, `span-exponent`, `gap-min-days`, `decay-half-life-days`,
`squash-scale`, `score-floor`, `violation-k`, …) live under `:scoring` in
config; see [ontology §6](ontology.md) for the formula and
[`config.edn`](../resources/config.edn) for the tunable defaults. The
practical consequence for integrators: a respectful long-lived caller is
afforded progressively higher limits, while a farm of throwaway keys gains
almost nothing — spacing is expensive to fake at scale, volume is not.

**Errors:** `E_BAD_REQUEST`, `E_UNAUTHORIZED`, `E_FORBIDDEN` (revoked key, banned tier), `E_REPLAY`, `E_RATE`.

### `POST /v1/rotate-key`

Replace the identity's signing keypair. Envelope signed with the OLD key carries the user's intent. The request body adds the new pubkey bytes and alg.

**Request body:**

```json
{
  "envelope":   { /* wire envelope, key-id = OLD thumbprint, signed by OLD private key */ },
  "new-pubkey": "<base64url canonical bytes of NEW pubkey>",
  "new-alg":    "ed25519"
}
```

**Response (200):**

```json
{ "ok": true,
  "new_key_id":       "<base64url SHA-256 thumbprint of new pubkey>",
  "grace_expires_at": "2026-05-25T13:34:56.789Z" }
```

Within the grace window (config `:grace/:key-rotation-overlap-seconds`, default 86 400) BOTH keys verify. After the window, the old key is treated as revoked. The new pubkey is attached to the same identity (no merge, no cluster change).

**Errors:** `E_BAD_REQUEST`, `E_UNAUTHORIZED`, `E_FORBIDDEN` (old key already revoked), `E_REPLAY`, `E_CONFLICT` (new pubkey already registered).

### `POST /v1/revoke-key`

User-initiated revocation. Envelope signed with the key being revoked.

**Request body:** `{ "envelope": <wire envelope, key-id = thumbprint to revoke, signed by that key> }`

**Response (200):** `{ "ok": true, "revoked_at": "2026-05-25T13:34:56.789Z" }`

No grace window. The key is rejected from the next request onward. The identity is otherwise unchanged. The user can call `/v1/bootstrap` with a fresh keypair to start a new cluster.

**Errors:** `E_BAD_REQUEST`, `E_UNAUTHORIZED`, `E_FORBIDDEN`, `E_REPLAY`.

### `POST /v1/admin/revoke-key`

Operator-initiated revocation by thumbprint. HMAC-authenticated, no user signature required. This is the escape hatch for compromised keys whose holders can no longer (or won't) sign a `/v1/revoke-key` envelope.

**Headers** (all required):

| Header           | Value                                                                                       |
|------------------|---------------------------------------------------------------------------------------------|
| `X-Admin-Key-Id` | identifier of the admin key (must match a record in the server's keystore)                  |
| `X-Admin-Ts`     | ISO 8601 timestamp, within ±60 s of server clock                                            |
| `X-Admin-Nonce`  | base64url 16 raw bytes (replay-cached, same 120 s TTL as envelope nonces)                   |
| `X-Admin-Sig`    | base64url HMAC-SHA256 over `METHOD \n PATH \n b64url(sha256(body)) \n TS \n b64url(NONCE)`  |

**Request body:** `{ "key_id": "<base64url thumbprint>" }`

**Response (200):** `{ "ok": true, "revoked_at": "…" }`

**Errors:** `E_BAD_REQUEST`, `E_UNAUTHORIZED` (signature / clock-skew / unknown key-id), `E_FORBIDDEN` (admin keystore not configured, so admin endpoints are disabled), `E_REPLAY`, `E_NOT_FOUND` (thumbprint not in DB).

### `GET /v1/admin/config`

Dump the effective aero-resolved config (env vars applied) for ops verification. Same HMAC auth as above. Sensitive fields (`:prometheus-bearer`, `:host-keys-path`, `:admin-keys-path`) are returned as `"<redacted>"`.

### `POST /v1/link-account` *(planned, v1.1)*

Host-to-server attestation: `(host_user_id, identity_ref)` bound. HMAC over the body using a per-host shared secret. 24-hour cooling-off before merge commits if the user_id was previously bound to a different identity.

### `DELETE /v1/identity/{id}` *(planned, v1.1)*

GDPR right-to-erasure. Requires both host HMAC and a signed envelope from the identity's signing key.

### `GET /healthz`
Liveness. Returns 200 `{ "ok": true }` once the process is accepting requests.

### `GET /readyz`
Readiness. Returns 200 `{ "ready": true, "db_status": "ok" }` when storage is reachable, 503 with `db_status: "unreachable"` otherwise.

### `GET /metrics`
Prometheus text exposition. If `:prometheus-bearer` is configured in `:observability`, the request must carry `Authorization: Bearer <token>`.

## Conventions

- Timestamps are ISO 8601 UTC with millisecond precision (`2026-05-24T12:34:56.789Z`).
- All byte fields are base64url **without** padding.
- Idempotency: mutating endpoints accept `Idempotency-Key` header *(planned, v1.1)*. (key, body-hash) cached for 24 h.
- `Server-Timing` response header carries `latency;dur=<ms>` for observability.
