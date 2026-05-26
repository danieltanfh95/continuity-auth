# continuity-auth

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A zero-auth trust service for rate-limiting and abuse decisions.** Lets a backend ask *"should I serve this request?"* without making the user log in, without showing a CAPTCHA, and without trusting IP or browser fingerprint alone.

> **Status:** v0.1.0 — feature-complete for v0.1 scope, tested end-to-end (292 tests / 1416 assertions / 0 failures; bundle 31.79 KB gzipped), not yet deployed at scale. Public API, wire envelope, and DB schema are stable for 0.1.x. v1.1 items are listed below.

## What it is

A small service that emits one of three answers — **allow**, **throttle**, **deny** — per request. The host application keeps its own auth; continuity-auth advises on the requests where authentication wasn't required in the first place.

The trust signal is a cryptographically anchored *device-continuity proof*: each browser holds a non-extractable Ed25519 (or P-256) keypair, generated once on first visit and persisted in IndexedDB. Every request to a rate-limited endpoint carries an envelope signed by that key. The server resolves the envelope to an identity, applies a sliding-window rate limit at a tier derived from accumulated trust, and returns a decision.

```
┌───────────────────────────────────────────────────────────────────────┐
│  client (cljs lib, 32 KB)        host backend          continuity-auth│
│  ──────────────────────          ────────────          ────────────── │
│                                                                       │
│  1. generateKey({extractable: false})                                 │
│      → SubtleCrypto, persisted in IndexedDB                           │
│                                                                       │
│  2. signed envelope ──fetch──▶ POST /api/whatever                     │
│                                  ├─ forward envelope ──▶ POST /v1/verify
│                                  │                       ├ verify sig │
│                                  │                       ├ check nonce│
│                                  │                       ├ score tier │
│                                  │   {ok, tier,   ◀──────┤            │
│                                  │   retry_after}                     │
│                                  ◀ enforce ──┘                        │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

The browser-side key is **non-extractable by Web Crypto**: even an XSS attacker on the host page can *use* the key to sign one request, but cannot exfiltrate it. No third-party JS crypto. No CDN-loaded `elliptic.js`.

## Why this exists

Rate limiting on the open web has bad shape:

- **CAPTCHA** (Turnstile, hCaptcha, reCAPTCHA) interrupts the human, ships a third-party iframe, and loses ground every year against frontier bots.
- **Per-IP limits** punish shared NATs (offices, mobile carriers, university dorms, anyone behind CGNAT) and don't slow a residential-proxy bot at all.
- **Per-cookie limits** evaporate the moment the attacker clears cookies or opens a new browser profile.
- **Anonymous tokens** (Privacy Pass, mCaptcha, Anubis) are great when there's a trusted issuer to issue tokens from, but most apps don't have one, and the issuance gate just relocates the rate-limit problem.

continuity-auth takes a different cut: keep the rate limit on the device, not on the network. The LS keypair is the only cryptographically anchored merge signal — IP and fingerprint are corroborating, not authoritative. An attacker who shares one axis with a victim (same coffee-shop IP, same browser version) cannot poison the victim's cluster, because they don't have the key.

Tiers are earned by sustained, low-anomaly observation. A fresh browser sits in the cautious tier. A browser that has signed a thousand uneventful requests over a week sits higher. The score is a single number in [0, 1] per identity; tier projection is configurable.

## How it compares

| | continuity-auth | CAPTCHA (Turnstile, hCaptcha) | Per-IP rate limit | Anonymous tokens (Privacy Pass, Anubis) |
|---|---|---|---|---|
| User friction | None (transparent signing) | Interaction or invisible challenge | None | Light (one-time challenge) |
| Resistance to residential proxies | High (IP is advisory) | Medium-low | None | High |
| Resistance to fingerprint randomization | High (LS key is the merge signal) | Medium | n/a | High |
| Resistance to "user clears cookies" | High (IndexedDB persists) | Per-challenge | None | Issuer-dependent |
| Privacy posture | No third-party iframe, no cross-site signals | Vendor-dependent | Best | Good |
| Requires a trusted issuer | No | Yes (vendor) | No | Yes |
| Decision granularity | per request | per session | per IP | per token |
| Self-hostable | Yes | Mostly no | Yes | Some |
| Works for curl / wget / daemons / mobile | Yes (any client that can hold a key) | No (JS-required) | Yes (no identity) | Anubis: no (JS-required PoW). Privacy Pass: issuer-dependent |

These are not exclusive. continuity-auth pairs naturally with per-IP for the bottom of the rate-limit pyramid and with a CAPTCHA for the genuinely-suspicious top.

## Non-browser clients

continuity-auth's wire protocol is implementable from `openssl` + `curl` — there's no "headless mode," it's the same bytes a browser produces. The shell reference is at [`scripts/cauth-curl-example.sh`](scripts/cauth-curl-example.sh). The ergonomic equivalent is the babashka-based `continuity` CLI, installed via the one-liner in the Install section below.

```bash
# bytes-for-bytes reference (zero deps beyond openssl/curl/jq/xxd):
CAUTH_ENDPOINT=http://localhost:8080 ./scripts/cauth-curl-example.sh

# or via the unified binary:
continuity auth init
continuity auth curl -X POST -d '{"thing":1}' https://app.example.com/api/thing
```

Full walkthrough — including how this compares mechanism-by-mechanism with Anubis (SHA-256 PoW gate, JS-required, anonymous) — in [`docs/non-browser-clients.md`](docs/non-browser-clients.md).

## Install the `continuity` CLI

The unified `continuity` binary (built on babashka) is the ergonomic surface for non-browser callers. Pick one:

```bash
# one-liner (POSIX: linux/macos/wsl). Installs bb if missing.
curl -fsSL https://raw.githubusercontent.com/The-Continuity-Project/continuity-auth/main/install.sh | sh

# Homebrew tap (once registered):
brew tap The-Continuity-Project/tap && brew install continuity

# Windows PowerShell:
iwr https://raw.githubusercontent.com/The-Continuity-Project/continuity-auth/main/install.ps1 -UseBasicParsing | iex

# Manual: install babashka yourself (https://github.com/babashka/babashka), then clone this repo and put bin/continuity on PATH.
```

Verify: `continuity --version`. The binary exposes `continuity auth …` for the client surface and `continuity admin …` for the operator surface; both routes ship in the same install. See [`docs/non-browser-clients.md`](docs/non-browser-clients.md) for the full env-var contract.

`continuity` is also the umbrella CLI for the trust-mechanism family; `continuity-auth` (this project) is its first member. The dispatcher does git-style plugin discovery — any `continuity-NAME` executable on PATH is reachable as `continuity NAME …` — so future members can ship as independent repos without touching the core dispatcher.

## Quick start

```bash
# clone + bring up the stack (Clojure not required on the host)
git clone https://github.com/The-Continuity-Project/continuity-auth.git
cd continuity-auth
cp .env.example .env                # then edit CAUTH_DTLV_PASSWORD
docker compose up -d

# liveness check
curl -s http://localhost:8080/healthz
# {"ok":true}

# readiness check (DB reachable)
curl -s http://localhost:8080/readyz
# {"ready":true,"db_status":"ok"}
```

> **Apple Silicon note:** the upstream `huahaiy/datalevin:0.9.22` image is a GraalVM native-image built for `x86_64` with AVX instructions, which Rosetta/qemu cannot emulate. On Apple Silicon, run the JVM dev path instead: `clojure -M:run` (uses embedded Datalevin at `/tmp/continuity-auth-dev.dtlv`). Linux `x86_64` and Linux/ARM64 with a future Datalevin arm64 release work via `docker compose up -d`.

Browser-side integration (ESM):

```js
import * as cauth from "@continuity-auth/client";  // 32 KB gzipped

await cauth.init({ endpoint: "https://fl.example.com", hostId: "my-app" });

// signFetch returns a fetch options bag with the signed envelope on the body.
// Hand it to fetch yourself; the host backend forwards the envelope to
// continuity-auth for the decision and enforces the result.
const opts = await cauth.signFetch({
  method: "POST",
  path:   "/api/expensive-thing",
  body:   JSON.stringify(payload),
});
const res = await fetch("/api/expensive-thing", opts);
if (res.status === 429) {
  // The host backend re-surfaces continuity-auth's retry_after_ms.
  // Render a sensible "please wait" UX here.
}
```

Backend-side (any language, the wire is JSON-over-HTTP):

```
POST /v1/verify
{
  "envelope": "<base64url envelope from the client>"
}

→ 200 {"ok": true,  "identity_ref": "01J7…",  "tier": "tracked",   "retry_after_ms": 0}
→ 429 {"ok": false, "code": "E_RATE",         "retry_after_ms": 4200}
→ 403 {"ok": false, "code": "E_FORBIDDEN"}
```

Full API in [`docs/api.md`](docs/api.md). Integration walk-through in [`docs/integration-guide.md`](docs/integration-guide.md).

## Stack

- **Server:** Clojure 1.12 on JDK 21, Ring/Reitit, Jetty 11, Malli, Integrant.
- **Storage:** Datalevin (LMDB, server mode in production).
- **Crypto:** BouncyCastle for Ed25519/P-256 on JVM; Web Crypto SubtleCrypto in the browser.
- **Client:** ClojureScript via shadow-cljs, `:esm` target, 31.79 KB gzipped.

## Layout

```
src/continuity_auth/        Clojure + ClojureScript sources
test/                        kaocha (JVM) + cljs.test + karma + k6 load
docs/                        api · architecture · ontology · threat-model · deployment
docs/style/                  imported Clojure / correctness-framing conventions
bin/                         continuity CLI (auth + admin subcommands)
resources/                   aero config, logback
scripts/check-bundle-size.mjs   CI gate on the gzipped bundle
.plans/                      implementation plan (current + archive/)
```

## Common tasks (via [`just`](https://github.com/casey/just))

```
just run-dev       # start the service against an embedded Datalevin
just test          # run backend tests (kaocha)
just cljs-dev      # frontend dev server with hot reload
just cljs-release  # produce the publishable bundle + size gate
just docker-up     # run the full stack in containers
just load          # run the k6 load test
just lint          # clj-kondo
```

## What's done / what's not

**Shipped in v0.1.0** (all integration-tested):

- Bootstrap (first-visit identity creation with self-signed envelope) at `POST /v1/bootstrap`.
- Verify (the main rate-limit decision path) at `POST /v1/verify`.
- Key rotation at `POST /v1/rotate-key` (grace-window aware).
- Key revocation at `POST /v1/admin/revoke-key`.
- HMAC-authenticated admin surface (`/v1/admin/*`) with constant-time compare + nonce replay defence.
- Unified `continuity` CLI (`bin/continuity`) for client (`auth …`) and operator (`admin …`) surfaces.
- Per-tier sliding-window rate limits.
- Bootstrap per-IP rate limit (anti-spam on identity creation).
- Body-size limit, Content-Length parsing, strict X-Forwarded-For extraction.
- Prometheus `/metrics` with bearer-token auth (defaults to closed).
- Threat-model coverage of T1–T19 (see [`docs/threat-model.md`](docs/threat-model.md)).

**Deferred to v1.1** (specified in docs/api.md, not yet wired):

- `POST /v1/link-account` (host-attested cross-identity merge).
- `DELETE /v1/identity/{id}` (GDPR erasure).
- Admin `reset-tier`.
- Idempotency middleware on the public surface.
- OTLP/Jaeger trace exporter.
- 5-second committed-cursor watermark on async transacts (currently fire-and-forget).
- Live demo deployment.

## How it really works

If you're going to push this into production, read these in order:

1. [`docs/threat-model.md`](docs/threat-model.md) — what we defend against (T1–T19), what's explicitly out of scope, where the boundaries are.
2. [`docs/ontology.md`](docs/ontology.md) — the data model: identity, tuple, pubkey, host-link, score, tier. The verify-path logic in §3 is the operating heart of the system.
3. [`docs/architecture.md`](docs/architecture.md) — module structure, decisions, trade-offs, the data flow per request.
4. [`docs/crypto-protocol.md`](docs/crypto-protocol.md) — envelope format, canonical bytes, signature algorithms.
5. [`docs/api.md`](docs/api.md) — wire format for every endpoint.
6. [`docs/deployment.md`](docs/deployment.md) — environment variables, secrets, Datalevin server mode, Prometheus scrape, OTel.

## Limitations

Honest list of what this is *not* good at, so HN comments don't have to:

- **Residential-proxy bot farms with per-instance fingerprint randomization** are out of scope. continuity-auth raises the cost of cheap automation; it doesn't beat dedicated adversaries who treat each bot as a fresh identity. The trust-budget design caps the damage from cheap sybils (anonymous tier is intentionally low value), but a determined attacker can pay the cost of sustained observation per bot.
- **Browser fingerprint is fragile and bypassable.** That's why it's advisory only — the LS key is the merge gate. A fingerprint match against a different cluster's tuples becomes an *ops signal*, not an automatic merge.
- **The host application is the trust boundary for the user identity.** If the host's HMAC keys leak, the link-account path (v1.1) loses integrity; recovery is the host's responsibility.
- **XSS on the host page is a signing oracle.** The key cannot be exfiltrated, but an attacker with JS execution can request signatures while the page is open. We mitigate via client-side rate caps and server-side anomaly metrics; we do not prevent XSS — the host does.
- **Datalevin async transact has a bounded event-loss window on crash.** Statistical events (request logs) may lose up to a few seconds on hard kill; correctness-critical writes (score updates, nonces) are synchronous. The 5-second committed-cursor watermark is a v1.1 mitigation.

## Verification

This project does not use hosted CI runners. The gate is `just ci` (run locally before pushing), which covers lint + tests + uberjar build + cljs release + bundle-size check. Rationale: hosted runners are an out-of-band trust assumption that a project whose pitch is "don't trust signals you can't verify" should not import. The recent CI-ecosystem incidents (tj-actions/changed-files exfiltration, the Ultralytics PyPI compromise, GitHub Actions cache poisoning) are the kind of supply-chain bleed-through this posture exists to avoid. See [`docs/architecture.md`](docs/architecture.md) "CI posture" for the longer reasoning.

```bash
just ci   # the single gate; run before every push.
```

## License

MIT — see [LICENSE](LICENSE). © 2026 Daniel Tan.
