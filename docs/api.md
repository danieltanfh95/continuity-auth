# continuity-auth — HTTP API (v1)

All endpoints are HTTPS, JSON over HTTP/1.1 or HTTP/2. UTF-8 throughout. Every request and response carries an `X-Request-Id` correlation header.

The error model is uniform; all error responses share the shape:

```json
{ "ok": false, "retry_after_ms": <long>, "code": "E_<CODE>" }
```

`code` is a public-stable opaque token. We do not disclose which check failed (signature vs. replay vs. malformed input) — see `docs/threat-model.md` T10.

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
  "v":           "FPL1\n",
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

**Response (200 — allow):**
```json
{
  "ok":             true,
  "identity_ref":   "<uuid>",
  "tier":           "anonymous" | "tracked" | "penalized" | "banned",
  "retry_after_ms": 0
}
```

**Response (429 — throttle):** standard error shape with `code = "E_RATE"` and `retry_after_ms > 0`.

**Errors:** `E_BAD_REQUEST`, `E_UNAUTHORIZED`, `E_FORBIDDEN` (revoked key, banned tier), `E_REPLAY`, `E_RATE`.

### `POST /v1/rotate-key` *(planned, v1.1)*

Replace the LS keypair. Envelope signed with the OLD key. New pubkey valid immediately; old pubkey valid for the configured grace period (default 24 h).

### `POST /v1/revoke-key` *(planned, v1.1)*

User-initiated revocation. Envelope signed with the key being revoked.

### `POST /v1/link-account` *(planned, v1.1)*

Host-to-server attestation: `(host_user_id, identity_ref)` bound. HMAC over the body using a per-host shared secret. 24-hour cooling-off before merge commits if the user_id was previously bound to a different identity.

### `DELETE /v1/identity/{id}` *(planned, v1.1)*

GDPR right-to-erasure. Requires both host HMAC and a signed envelope from the identity's LS key.

### `GET /healthz`
Liveness. Returns 200 `{ "ok": true }` once the process is accepting requests.

### `GET /readyz`
Readiness. Returns 200 `{ "ready": true, "db_status": "ok" }` when storage is reachable; 503 with `db_status: "unreachable"` otherwise.

### `GET /metrics`
Prometheus text exposition. If `:prometheus-bearer` is configured in `:observability`, the request must carry `Authorization: Bearer <token>`.

## Conventions

- Timestamps are ISO 8601 UTC with millisecond precision (`2026-05-24T12:34:56.789Z`).
- All byte fields are base64url **without** padding.
- Idempotency: mutating endpoints accept `Idempotency-Key` header *(planned, v1.1)*; (key, body-hash) cached for 24 h.
- `Server-Timing` response header carries `latency;dur=<ms>` for observability.
