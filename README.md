# continuity-auth

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Respect is earned, not given.

By using **device-continuity proof** as a trust signal and **time** as the core resource, `continuity-auth` provides a graceful, zero-trust, login-less method to prevent abuse in a world where we can't (and shouldn't) reliably identify humans vs LLMs.

## The problem

Rate-limiting on the open web has bad shape.

- **CAPTCHA** (Turnstile, hCaptcha, reCAPTCHA) makes humans pay the toll while losing ground year-on-year against computer-use LLMs.
- **Per-IP limits** punish shared NATs (offices, mobile carriers, university dorms) and don't slow a residential-proxy bot at all.
- **Per-cookie limits** evaporate the moment the attacker clears cookies or opens a new browser profile.
- **Anonymous tokens** (Privacy Pass, mCaptcha) are great when there's a trusted issuer. Most apps don't have one, and the issuance gate just relocates the rate-limit problem.
- **Cost-floor PoW gates** (Anubis) only work while the cost-of-scraping stays above the value of scraped data. 

## What makes us different

Every caller of your service earns a trust score based on how much continuity they're willing to demonstrate. The more sustained, low-anomaly observation, the higher the respect, and the higher the rate-limit afforded.

**This is a zero-auth trust service for rate-limiting and abuse decisions.** It lets a backend ask *"should I serve this request?"* by accepting a cryptographically anchored device-continuity proof from any client (browser, curl/wget, daemon, mobile) without making the user log in, without showing a CAPTCHA, and without trusting IP or browser fingerprint alone.

The caller demonstrates persistent control of a private key tied to a registered identity. Browsers hold a non-extractable Ed25519 (or P-256) key in IndexedDB via Web Crypto. CLI, daemon, and mobile clients hold a PEM-encoded key on disk or in a hardware secure element. Every rate-limited request carries an envelope signed by that key, and the server resolves it to an identity, applies a token-bucket rate limit at the trust-derived tier, and returns a decision.

The protocol has two phases that happen at different cadences.

**Phase 1: Bootstrap** (once per device, on first use)

```
Client                              continuity-auth
  │                                       │
  │ generateKey() → store locally         │
  │   browser: non-extractable WebCrypto  │
  │   CLI: PEM at $CONTINUITY_AUTH_HOME   │
  │                                       │
  │ build bootstrap envelope:             │
  │   { pubkey, ts, nonce, fp-digest,     │
  │     sig over canonical bytes }        │
  │                                       │
  ├─ POST /v1/bootstrap ─────────────────▶│
  │                                       │   verify sig (key is in envelope)
  │                                       │   check nonce / per-IP backoff
  │                                       │   create Identity + Pubkey + first Tuple
  │   { ok, identity_ref,                 │
  │◀── tier: "anonymous" }────────────────┤
```

The keypair stays on-device forever after this. Bootstrap is idempotent on `cauth.init()` since an existing keypair skips the call. It only re-runs on a fresh device or after `revoke-key`.

**Phase 2: Verify** (every rate-limited request, indefinitely)

```
Client                  Host backend            continuity-auth
  │                          │                       │
  │ signFetch(req):          │                       │
  │   build envelope         │                       │
  │   { key-id, ts, nonce,   │                       │
  │     method, path,        │                       │
  │     body-sha256,         │                       │
  │     fp-digest, sig }     │                       │
  │                          │                       │
  ├─ HTTP request +─────────▶│                       │
  │   X-Continuity-Envelope  │                       │
  │                          │ POST /v1/verify       │
  │                          ├─{envelope}───────────▶│
  │                          │                       │   sig verify (lookup by key-id)
  │                          │                       │   nonce check
  │                          │                       │   classify (new tuple? same cluster?)
  │                          │                       │   update score
  │                          │                       │   project tier
  │                          │                       │   token-bucket check
  │                          │   { ok, identity_ref, │
  │                          │     tier,             │
  │                          │     retry_after_ms,   │
  │                          │◀── priority_weight }──┤
  │                          │                       │
  │   serve / 429────────────┤ enforce decision      │
  │◀─────────────────────────┤                       │
```

The envelope is single-use (nonce-bound and TTL-bound, default 60s tolerance + 120s nonce cache). The pubkey from bootstrap is what `key-id` references. Without that prior bootstrap, there is no Identity to attach the observation to and `/v1/verify` returns `E_UNAUTHORIZED`.

## Why this works (threat-model sketch)

The resource being gated is **wall-clock observation time**, not CPU. A PoW gate prices the attacker in CPU-hours, which a $1/hr GPU rental commoditizes at ~10⁵ challenges/sec. Time can't be commoditized the same way. An attacker can't run two days of behaviour into one. Tier accumulation is gated by the calendar, not by the price of compute.

The trust signal is **cryptographic** (signing key) rather than **observed** (IP) or **claimed** (fingerprint). An attacker who shares one axis with a victim (same coffee-shop IP, same browser version) cannot poison the victim's cluster, because they don't have the key. IP is stored only as `HMAC-SHA256(ip)` under a server-side keystore secret. Clusters still group by IP, but an operator dumping the store sees opaque hex, not raw addresses.

The full threat-model lives in **[`docs/threat-model.md`](docs/threat-model.md)**. It enumerates what's defended (T1–T19), what's explicitly out of scope, and where the boundaries are.

## Read more

Full doc index: [`docs/`](docs/README.md).

## Quick start

```bash
git clone https://github.com/danieltanfh95/continuity-auth.git
cd continuity-auth
cp .env.example .env                # then edit CONTINUITY_AUTH_DTLV_PASSWORD
docker compose up -d

curl -s http://localhost:8080/healthz
# {"ok":true}
```

> **Apple Silicon:** the upstream `huahaiy/datalevin` image is GraalVM native-image for `x86_64`. Rosetta cannot emulate AVX. Run the JVM dev path: `clojure -M:run` (embedded Datalevin at `/tmp/continuity-auth-dev.dtlv`).

Browser-side integration (ESM):

```js
import * as cauth from "@continuity-auth/client";

await cauth.init({ endpoint: "https://fl.example.com", hostId: "my-app" });

const opts = await cauth.signFetch({
  method: "POST",
  path:   "/api/expensive-thing",
  body:   JSON.stringify(payload),
});
const res = await fetch("/api/expensive-thing", opts);
if (res.status === 429) {
  // The host backend re-surfaces continuity-auth's retry_after_ms.
}
```

Backend-side (any language, the wire is JSON-over-HTTP):

```
POST /v1/verify
{ "envelope": "<base64url envelope from the client>" }

→ 200 {"ok": true,  "identity_ref": "01J7…",  "tier": "tracked",   "retry_after_ms": 0}
→ 429 {"ok": false, "code": "E_RATE",         "retry_after_ms": 4200}
→ 403 {"ok": false, "code": "E_FORBIDDEN"}
```

Optional CLI install for non-browser callers: see [`docs/non-browser-clients.md`](docs/non-browser-clients.md).

## Stack

Proudly built with Clojure/Script, Babashka, and Datalevin

## For devs

Repo layout: `src/continuity_auth/server/` (Clojure server), `src/continuity_auth/client/` (ClojureScript), `test/` (unit / integration / adversarial suites).

Common commands:

```
just ci                       # the one gate: lint + tests + uberjar + cljs release + bundle check
clojure -M:run                # JVM dev server, embedded Datalevin at /tmp/continuity-auth-dev.dtlv
clojure -M:test               # JVM tests only
npx shadow-cljs watch core    # rebuild the client on save
```

Architecture, module structure, and per-request data flow: [`docs/architecture.md`](docs/architecture.md).

## Roadmap

The goal of continuity-auth is to make device-continuity proof a viable, login-less trust signal for the open web: every caller that can hold a private key (browser, CLI, daemon, mobile, hardware-anchored) earns a higher rate-limit tier through sustained, anomaly-free observation rather than by proving identity. A scope rule guides what we build — we own the high-friction, security-critical surface (key handling, envelope construction, crypto) and leave low-friction host-side glue as optional helpers. Milestones are tentative (mobile is deferred to 0.99.0) and priorities may shift with feedback.

**Shipped**

- **0.1.0** ~~Public API, wire envelope, and DB schema stable. Ed25519 / P-256 with non-extractable Web Crypto in the browser. CLI substrate with PEM keys. HMAC IP-hashing. Key rotation and revocation. Admin endpoints.~~ [Released 2026-05-26]
- **0.2.0** ~~Token-bucket recovery and `priority_weight` hint. Trusted callers recover from bursts at leak-rate granularity instead of at the window edge. `/v1/verify` exposes a numeric scheduling weight for host-side weighted fair queuing.~~ [Released 2026-05-27]
- **0.3.0** ~~Global per-tier capacity caps as a class-level back-pressure gate, orthogonal to per-caller buckets. Configurable bucket parameters so capacity, leak rate, and priority weight are independently tunable per tier rather than derived from a single knob.~~ [Released 2026-05-28]
- **0.4.0** ~~Passwords done right (optional knowledge-factor binding). Add a secret only you know on top of your device key, so you can reclaim the same identity from a new device. Unlike a login, the server stores only a verifier — never the secret — and you prove it by challenge instead of sending it. Upgrades "same device over time" to "same device, plus something only you know."~~ [Released 2026-05-29]
- **0.5.0** ~~Offline authorisation (Biscuit capability tokens). A caller mints a short-lived token asserting the tier they've earned — like a ticket checked at the door — so hosts allow or deny each action offline by verifying it against a published root key, without calling `/v1/verify` again. Strictly additive; the advisory verify response is unchanged.~~ [Released 2026-05-29]
- **0.99.0** Mobile, with the key in the phone's secure chip (iOS Secure Enclave, Android Keystore). The wire protocol and P-256 path already accommodate this; the remaining work is a client-side key backend plus the platform DER↔raw conversions. High-friction and platform-specific, so demand-gated rather than scheduled.
- **0.99.1** A server-side helper SDK. A thin wrapper over the documented `/v1/verify` contract for the host's queue: weighted fair queuing / delay-then-serve (using `priority_weight` from 0.2.0) and `retry_after_ms` / 429 handling. Easy enough to build yourself, so it stays optional rather than core.

## License

MIT. See [LICENSE](LICENSE). © 2026 Daniel Tan.
