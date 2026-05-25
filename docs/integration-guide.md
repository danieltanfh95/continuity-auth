# continuity-auth — integration guide

This guide describes how a host application integrates continuity-auth as a parallel auth method — a rate-limit / trust advisor that sits *alongside* the host's existing authentication, not in place of it.

The contract:

- continuity-auth does not own sessions, cookies, or redirects.
- continuity-auth returns advisory decisions of the form `{ok, tier, retry_after_ms, identity_ref}` per envelope.
- The host enforces the decision.

## Architecture

```
                Browser                 Host backend              continuity-auth
                ┌────────────┐         ┌──────────────┐          ┌──────────────────┐
                │  Host UI   │         │              │          │                  │
                │            │         │  /api/...    │  ──S2S─→ │  POST /v1/verify │
                │  + fpl-lib │ ──HTTP→ │  handler     │          │  (sig verified,  │
                │  (signs)   │         │  + enforce   │ ←────── │   tier decision) │
                └────────────┘         └──────────────┘          └──────────────────┘
```

1. The host frontend includes the `@continuity-auth/client` library (npm) or `org.continuity-auth/client` (Clojars).
2. The library generates a non-extractable Ed25519 (or P-256) keypair on first visit, stores the handle in IndexedDB.
3. For every outgoing request the host wants to rate-limit, the library signs an envelope and attaches it to the request body as `envelope`.
4. The host's backend forwards the `envelope` to `POST /v1/verify` (S2S, over HTTPS).
5. continuity-auth returns a decision; the host backend enforces it.

## Frontend integration

```clojure
;; ClojureScript host:
(require '[continuity-auth.client.core :as fpl])

(fpl/init {:endpoint "https://fl.example.com"
           :host-id  "my-app"})

;; Outgoing request:
(-> (fpl/sign-fetch {:method "POST"
                      :path   "/api/foo"
                      :body   "..."})
    js/fetch)
```

```javascript
// JS/TS host (npm bundle):
import * as fpl from "@continuity-auth/client";

await fpl.init({endpoint: "https://fl.example.com", hostId: "my-app"});

const signedRequest = await fpl.signFetch({
  method: "POST",
  path:   "/api/foo",
  body:   "...",
});
await fetch("/api/foo", signedRequest);
```

The frontend library NEVER sets cookies, never reads or modifies the host's session storage.

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

- Use continuity-auth as the **outer** limiter — more sophisticated, includes fingerprint and LS-key continuity. Recommended.
- Disable the host's IP-based limiter on routes covered by continuity-auth.

Or keep both stacked. continuity-auth makes the tiering decision; the host's per-route limiter can still narrow further on specific high-value endpoints.

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
- **Pre-warm the keypair** by calling `fpl.init()` early in your app boot, so the first user action doesn't pay keygen latency.
- **Expose your own `Retry-After` based on continuity-auth's `retry_after_ms`** to help your frontend render a sensible "please wait" UX.

## Cost / latency expectations

- Round trip from your backend to fl-endpoint should be ≤ 5 ms (intra-region) for `/v1/verify`.
- Library bundle adds ≤ 40 KB gzipped to your frontend (current build 33.29 KB).
- Keygen on first visit: ≤ 50 ms on a modern browser; happens once per device.
- Signing per request: ≤ 5 ms on a modern browser.

## Versioning

The HTTP protocol is versioned at the path level (`/v1/...`). Breaking changes ship as `/v2/...` and run side by side during migration. The library auto-targets v1 until a major-version release.

The envelope's literal version tag (`"FPL1\n"`, see `crypto-protocol.md`) prevents accidental cross-version signing.
