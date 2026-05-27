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
- **Cost-floor PoW gates** (Anubis) only work while the cost-of-scraping stays above the value-of-scraped-data. A high-value site needs a per-request floor proportional to that value, which burns real CPU on every legitimate visitor too. The floor that deters a million-page scrape of a low-value forum is invisible against a scraper monetising data at $1/page.

## What makes us different

Every caller of your service earns a trust score based on how much continuity they're willing to demonstrate. The more sustained, low-anomaly observation, the higher the *respect*, and the higher the rate-limit afforded. **All without requiring the user to log in.**

**This is a zero-auth trust service for rate-limiting and abuse decisions.** It lets a backend ask *"should I serve this request?"* by accepting a cryptographically anchored device-continuity proof from any client (browser, curl/wget, daemon, mobile) without making the user log in, without showing a CAPTCHA, and without trusting IP or browser fingerprint alone.

The caller demonstrates persistent control of a private key tied to a registered identity. The mechanism speaks one wire protocol across every client type. Browser callers hold a non-extractable Ed25519 (or P-256) key in IndexedDB via Web Crypto. CLI, daemon, and mobile callers hold a PEM-encoded key on disk or in a hardware secure element. Every request to a rate-limited endpoint carries an envelope signed by that key. The server resolves the envelope to an identity, applies a token-bucket rate limit at a tier derived from accumulated trust, and returns a decision.

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

The keypair stays on-device forever after this. Bootstrap is idempotent on `cauth.init()`: an existing keypair skips the call. It only re-runs on a fresh device or after `revoke-key`.

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

The asymmetry is intentional. Bootstrap is the expensive identity-creation path with per-IP exponential backoff that deters mass-anonymous-identity creation. Verify is the cheap per-request decision path: one indexed lookup plus token-bucket math.

## Why this works (threat-model sketch)

The resource being gated is **wall-clock observation time**, not CPU. A PoW gate prices the attacker in CPU-hours, which a $1/hr GPU rental commoditizes at ~10⁵ challenges/sec. Time can't be commoditized the same way. An attacker can't run two days of behaviour into one. Tier accumulation is gated by the calendar, not by the price of compute.

The trust signal is **cryptographic** (signing key) rather than **observed** (IP) or **claimed** (fingerprint). An attacker who shares one axis with a victim (same coffee-shop IP, same browser version) cannot poison the victim's cluster, because they don't have the key. IP is stored only as `HMAC-SHA256(ip)` under a server-side keystore secret. Clusters still group by IP, but an operator dumping the store sees opaque hex, not raw addresses.

The full threat-model lives in **[`docs/threat-model.md`](docs/threat-model.md)**. It enumerates what's defended (T1–T19), what's explicitly out of scope, and where the boundaries are.

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

CLI install for non-browser callers: see [`docs/non-browser-clients.md`](docs/non-browser-clients.md).

## Stack

Server: Clojure 1.12 on JDK 21, Ring/Reitit, Jetty 11, Malli, Integrant. Storage: Datalevin (LMDB, server mode in production). Crypto: BouncyCastle for Ed25519/P-256 on JVM. Web Crypto SubtleCrypto in the browser. Client: ClojureScript via shadow-cljs, `:esm` target, gzipped budget 40 KB (currently well under).

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

## Status

Public API, wire envelope, and DB schema are stable. Releases and changelog live in the GitHub releases page. Planned items are tracked in [`docs/api.md`](docs/api.md) and [`docs/architecture.md`](docs/architecture.md).

This project does not use hosted CI runners. [`docs/architecture.md`](docs/architecture.md) "CI posture" explains why. The single gate is `just ci` (lint + tests + uberjar + cljs release + bundle-size check).

## Roadmap

The goal of continuity-auth is to make device-continuity proof a viable trust signal for the open web. We aim to give every caller that can hold a private key (browser, CLI, daemon, mobile, hardware-anchored) a graceful, login-less path to a higher rate-limit tier through sustained, anomaly-free observation. Below are the tentative milestones. Priorities may shift with feedback.

- **0.1.0** ~~Public API, wire envelope, and DB schema stable. Ed25519 / P-256 with non-extractable Web Crypto in the browser. CLI substrate with PEM keys. HMAC IP-hashing. Key rotation and revocation. Admin endpoints.~~ [Released 2026-05-26]
- **0.2.0** Token-bucket recovery and `priority_weight` hint. Trusted callers recover from bursts at leak-rate granularity instead of at the window edge. `/v1/verify` exposes a numeric scheduling weight for host-side weighted fair queuing.
- **0.3.0** Global per-tier capacity caps as a class-level back-pressure gate, orthogonal to per-caller buckets. Configurable bucket parameters so capacity, leak rate, and priority weight are independently tunable per tier rather than derived from a single knob.
- **0.4.0** Mobile support via hardware-anchored keys (iOS Secure Enclave, Android Keystore). The wire protocol already accommodates these. Only the client-side storage layer needs the new path.

## License

MIT. See [LICENSE](LICENSE). © 2026 Daniel Tan.
