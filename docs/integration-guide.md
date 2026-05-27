# continuity-auth — integration guide

This guide describes how a host application integrates continuity-auth as a parallel auth method — a rate-limit / trust advisor that sits *alongside* the host's existing authentication, not in place of it.

The contract:

- continuity-auth does not own sessions, cookies, or redirects.
- continuity-auth returns advisory decisions of the form `{ok, tier, retry_after_ms, identity_ref, priority_weight}` per envelope.
- The host enforces the decision. `priority_weight` is optional input for host-side weighted fair queuing — see [Rate-limiter stacking](#rate-limiter-stacking) below.

## Architecture

```
       Client (any substrate)            Host backend             continuity-auth
       ┌──────────────────────┐         ┌──────────────┐         ┌──────────────────┐
       │ Browser (WebCrypto + │         │              │         │                  │
       │   IndexedDB)         │         │  /api/...    │ ──S2S─→ │  POST /v1/verify │
       │ CLI (PEM + openssl)  │ ──HTTP→ │  handler     │         │  (sig verified,  │
       │ daemon / mobile      │         │  + enforce   │ ←────── │   tier decision) │
       └──────────────────────┘         └──────────────┘         └──────────────────┘
```

continuity-auth is **substrate-neutral**: any client that holds a private key and can emit length-prefixed canonical bytes is a first-class caller. The browser is one substrate, the CLI / daemon is another, hardware-anchored callers (TPM / Secure Enclave / Keystore) are a v1.1+ direction. All three speak the same wire protocol.

The integration flow:

1. The client (any substrate) holds a private key — generated once at first contact and persisted in a substrate-natural store (browser: non-extractable IndexedDB handle; CLI: filesystem PEM at `$CONTINUITY_AUTH_HOME/key.pem`).
2. For every outgoing request the host wants to rate-limit, the client signs an envelope over the canonical bytes (see [`docs/crypto-protocol.md`](crypto-protocol.md)).
3. The host's backend forwards the `envelope` to `POST /v1/verify` (server-to-server, over HTTPS).
4. continuity-auth returns a decision (`ok`, `tier`, `retry_after_ms`, `priority_weight`); the host backend enforces it.

## Frontend integration (browser substrate)

```clojure
;; ClojureScript host:
(require '[continuity-auth.client.core :as cauth])

(cauth/init {:endpoint "https://fl.example.com"
           :host-id  "my-app"})

;; Outgoing request:
(-> (cauth/sign-fetch {:method "POST"
                      :path   "/api/foo"
                      :body   "..."})
    js/fetch)
```

```javascript
// JS/TS host (npm bundle):
import * as cauth from "@continuity-auth/client";

await cauth.init({endpoint: "https://fl.example.com", hostId: "my-app"});

const signedRequest = await cauth.signFetch({
  method: "POST",
  path:   "/api/foo",
  body:   "...",
});
await fetch("/api/foo", signedRequest);
```

The frontend library NEVER sets cookies, never reads or modifies the host's session storage.

## CLI / daemon integration (CLI substrate)

For non-browser callers — a shell script, a daemon, a mobile app, a long-running batch job — there are two ways to participate:

```bash
# Ergonomic: the unified `continuity` CLI (babashka-based).
continuity auth init                     # generates key + bootstraps identity
continuity auth curl -X POST \
  -d '{"thing": 1}' \
  https://app.example.com/api/thing      # wraps curl with X-Continuity-Envelope
```

```bash
# Bytes-for-bytes reference: a POSIX shell script using only openssl + curl + jq.
CONTINUITY_AUTH_ENDPOINT=https://fl.example.com ./scripts/cauth-curl-example.sh
```

The CLI substrate stores the keypair as `$CONTINUITY_AUTH_HOME/key.pem` (PEM/PKCS8, openssl-compatible) and the identity record as `$CONTINUITY_AUTH_HOME/identity.edn`. The wire bytes are identical to the browser path — see [`docs/crypto-protocol.md`](crypto-protocol.md) and [`docs/non-browser-clients.md`](non-browser-clients.md).

Operator guidance for filesystem-resident keys: `chmod 700 $CONTINUITY_AUTH_HOME`; treat the key like any long-lived API credential; rotate via `continuity admin revoke-key` + `continuity auth init` if compromise is suspected. The threat-model coverage is in [`docs/threat-model.md`](threat-model.md) T1 (CLI substrate row).

## What about non-engaging callers?

continuity-auth provides a trust signal only for callers that engage with the protocol. The README defines four levels of engagement (no envelope / bootstrap-only / sustained / host-linked). Level-0 callers — requests with no envelope at all — bypass continuity-auth entirely; the host's per-IP layer (or whatever else is configured) is what catches them. continuity-auth does not impose a host-side fallback contract; composition is the host's choice.

A practical layering that works:

```
host-side defense pyramid:

  ┌─────────────────────────┐
  │  CAPTCHA (top)          │  ← invoked only for level-1+ callers flagged
  │  - genuinely suspicious │     as anomalous by continuity-auth, or for
  └─────────────────────────┘     level-0 callers on high-value endpoints
  ┌─────────────────────────┐
  │  continuity-auth        │  ← level-1+ callers; trust gradient
  │  - tier-based limits    │     by accumulated observation
  └─────────────────────────┘
  ┌─────────────────────────┐
  │  per-IP limits (bottom) │  ← level-0 callers and the absolute floor
  │  - cheap, broad         │     for everyone
  └─────────────────────────┘
```

## Backend integration

For each request that arrives with a continuity-auth envelope:

```
host-backend handler (pseudo):
  ;; 1. Forward the envelope to continuity-auth for advisory.
  decision = http POST fl-endpoint/v1/verify {envelope: req.body.envelope}

  ;; 2. Enforce the decision.
  if decision.status == 429:
    return 429 with decision.headers["Retry-After"]
  if decision.status == 403:
    return 403
  ;; 3. Proceed with normal handler.
  ...

  ;; 4. (Optional) On user login, attest the binding.
  if user-just-logged-in:
    http POST fl-endpoint/v1/link-account
         body: {host_user_id, identity_ref}
         hmac: HMAC-SHA-256(shared-secret, body)
```

## Rate-limiter stacking

If the host already has its own rate limiter (e.g. per-IP, per-route), it can:

- Use continuity-auth as the **outer** limiter — more sophisticated, includes fingerprint and signing-key continuity. Recommended.
- Disable the host's IP-based limiter on routes covered by continuity-auth.

Or keep both stacked. continuity-auth makes the tiering decision; the host's per-route limiter can still narrow further on specific high-value endpoints.

## Priority queuing on the host (using `priority_weight`)

continuity-auth's rate limiter is a token bucket per `(identity, window)` per tier — it returns *allow / deny + retry_after_ms*, never a held connection. If you want trusted callers to *jump the line* during burst (rather than just getting a larger bucket), implement priority admission on your side and key it off `priority_weight`. The verify response carries the weight in both the 200 (allow) and 429 (E_RATE) cases so a host-side queue can place denied retries at the right position too.

Default weights mirror the `:1m` capacity ratios in `:ratelimit/:tiers`:

| Tier        | `priority_weight` | Rough intent                                    |
|-------------|-------------------|-------------------------------------------------|
| `tracked`   | 30.0              | Trusted; jumps ahead of anonymous under load    |
| `anonymous` | 1.0               | Baseline                                        |
| `penalized` | 0.0               | Effectively last in line                        |
| `banned`    | 0.0               | Same; usually a 403 path anyway                 |

continuity-auth itself never holds connections — that would turn a trust service into a deployment liability. Priority queuing belongs on the host or in a sidecar.

## CORS

The frontend library calls continuity-auth's endpoint (not the host's). Configure continuity-auth's CORS to allow the host's origin:

```
CORS allowed-origins: ["https://app.example.com"]
```

No CORS configuration is needed on the host's own endpoints from continuity-auth's perspective (no calls flow that direction outside link-account, which is server-to-server).

## What you *don't* need to do

- **Don't share cookies.** continuity-auth never sets cookies. Storage is IndexedDB on the client side.
- **Don't pass the user's session.** continuity-auth has no concept of "logged-in"; it has an `identity_ref` you can correlate with your own user record.
- **Don't proxy continuity-auth through your domain.** Direct connection from the browser to fl-endpoint is fine and reduces latency.

## What you *might* want to do

- **Cache the verify response** if you're going to make multiple decisions about the same envelope (you shouldn't — each envelope has a unique nonce and is single-use).
- **Pre-warm the keypair** by calling `cauth.init()` early in your app boot, so the first user action doesn't pay keygen latency.
- **Expose your own `Retry-After` based on continuity-auth's `retry_after_ms`** to help your frontend render a sensible "please wait" UX.

## Cost / latency expectations

- Round trip from your backend to fl-endpoint should be ≤ 5 ms (intra-region) for `/v1/verify`.
- Library bundle adds ≤ 40 KB gzipped to your frontend (current build 31.79 KB).
- Keygen on first visit: ≤ 50 ms on a modern browser; happens once per device.
- Signing per request: ≤ 5 ms on a modern browser.

## Versioning

The HTTP protocol is versioned at the path level (`/v1/...`). Breaking changes ship as `/v2/...` and run side by side during migration. The library auto-targets v1 until a major-version release.

The envelope's literal version tag (`"FPL2\n"`, see `crypto-protocol.md`) prevents accidental cross-version signing.
