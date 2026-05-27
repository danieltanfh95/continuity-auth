# continuity-auth — architecture

High-level overview. For the conceptual model see `ontology.md`. For the wire protocol see `crypto-protocol.md`. For the operational view see `deployment.md`.

## One picture

```
┌────────────────────────── Browser ──────────────────────────┐
│                                                             │
│  Host UI                                                    │
│   └─ @continuity-auth/client (cljs):                        │
│        - non-extractable Ed25519 key in IndexedDB           │
│        - fingerprint signal collection                      │
│        - envelope canonicalization + signing                │
│                                                             │
└──────────────────┬──────────────────────────────────────────┘
                   │ JSON (envelope + signature)
                   ▼
┌──────────────────────── Host backend ───────────────────────┐
│                                                             │
│   Existing host auth + business logic                       │
│                                                             │
│   Rate-limit step:                                          │
│     POST /v1/verify {envelope}      ── S2S ───┐             │
│                                               │             │
└───────────────────────────────────────────────┼─────────────┘
                                                │
                                                ▼
┌──────────────────── continuity-auth (this) ────────────────┐
│                                                             │
│   Ring/Reitit router                                        │
│     │                                                       │
│     ├── /v1/bootstrap, /v1/verify, /v1/rotate-key,          │
│     │       /v1/revoke-key                                  │
│     ├── /v1/admin/revoke-key, /v1/admin/config (HMAC)       │
│     │                                                       │
│     ├── /healthz, /readyz, /metrics                         │
│     │                                                       │
│   Envelope verification: parse → validate → clock → pubkey  │
│        lookup → signature verify → atomic nonce record      │
│                                                             │
│   Cluster classification (identity/merge.clj)               │
│        pubkey-anchored attach OR new tuple in cluster       │
│                                                             │
│   Sliding-window-counter (ratelimit/window.clj)             │
│        check + transact bucket                              │
│                                                             │
│   Datalevin (LMDB or dtlv:// server)                         │
│        identity, tuple, pubkey, request, trust-event,       │
│        nonce, host-link, bucket, erase-stub                 │
└─────────────────────────────────────────────────────────────┘
```

## Key design points

### The four axes are *not* equivalent

| Axis | Epistemic status | Role |
|---|---|---|
| `pubkey` | Cryptographic | The only merge gate |
| `host-user-id` | Cryptographic-by-proxy (HMAC) | Cross-identity merge via cooling-off |
| `ip` | Observed | Advisory only |
| `fp-digest` | Claimed | Advisory only |

This asymmetry is the heart of why continuity-auth resists poisoning attacks: an attacker who shares the victim's IP and fingerprint cannot enter the victim's cluster because they lack the victim's private key (regardless of substrate — browser non-extractable WebCrypto, CLI PEM, or hardware-anchored). See `ontology.md §2` and `threat-model.md §T3`, `§T6`.

### Single read snapshot per decision

The `/verify` handler obtains one Datalevin snapshot at the start of the request. All downstream computation (pubkey lookup, cluster classification, tier projection, token-bucket check) reads from that snapshot. Writes are dispatched via `transact-async!` after the response is sent.

This is what makes the decision TOCTOU-safe (invariant I10) and keeps response latency decoupled from write throughput.

### Rate-limit engine: token-bucket per tier per window

Each `(identity, window)` pair has one token-bucket entity keyed by `:bucket/key = "<identity-eid>|<window>"`. Capacity is the per-tier per-window value from `:ratelimit/:tiers` in config (e.g. `:tracked {:1m 30 :5m 120 :1d 5000}`); leak rate is derived as `capacity / window-seconds`, which makes steady-state throughput identical to the prior sliding-window engine. The difference is the recovery shape under burst: `retry_after_ms` is the time until the next token leaks back into the bucket, not the time until the window edge. A trusted caller who exhausts a `:1m` budget recovers within a few hundred milliseconds rather than tens of seconds.

The verify response surfaces `:priority_weight` — a numeric proxy for tier that hosts can use as a weighted-fair-queuing weight. continuity-auth itself does not hold connections or implement priority admission (that would turn the trust service into a deployment liability); priority queuing belongs in the host backend or a sidecar, and `priority_weight` is the integration seam.

### Pure-where-possible, transactional-where-necessary

Score deltas, tier projection, token-bucket arithmetic, envelope canonicalization are pure functions. Storage interaction is concentrated in two phases per request: read at the top, write asynchronously after the decision. This makes most of the system trivially testable without a real DB; only the integration layer needs ephemeral Datalevin.

### Genericity through protocols

Three Clojure protocols define the seams:
- `Axis` — pluggable identity-vector component
- `TrustPolicy` — pluggable scoring
- `Storage` — pluggable persistence

In v1 only the default implementations exist; the protocols are documented as the v2 evolution path.

## Layer / namespace map

```
continuity-auth.envelope                    .cljc — shared client+server codec
continuity-auth.crypto                      .cljc — algorithm constants

continuity-auth.server.crypto.{hash,pubkey,verify}   JVM crypto
continuity-auth.server.storage.{schema,protocol,datalevin,migrations}
continuity-auth.server.replay.nonce         replay cache
continuity-auth.server.identity.{score,merge}   trust math + classification
continuity-auth.server.ratelimit.{tier,window}  tiering + windowed counter
continuity-auth.server.http.{errors,middleware,router,envelope-check,util}
continuity-auth.server.http.handlers.{bootstrap,verify,health,
                                       rotate-key,revoke-key,admin}  endpoints
continuity-auth.server.admin.hmac           admin HMAC verification
continuity-auth.server.protocols.*          Axis / TrustPolicy / Storage seams
continuity-auth.server.observability.{metrics,logging}
continuity-auth.server.{config,system,main} composition

continuity-auth.client.{core,crypto,fingerprint,storage,tabs}  cljs client
continuity-auth.client.{cli,dispatch,json}  bb-compatible client CLI (bin/continuity)
continuity-auth.admin.cli                   HMAC admin CLI (continuity admin …)
```

Boundaries:
- `envelope.cljc` and `crypto.cljc` are the only cross-platform code.
- `server.identity.*`, `server.ratelimit.*`, `server.identity.score` are pure.
- `server.crypto.*` depends only on `clojure.*` + Java + BouncyCastle.
- `server.storage.datalevin` depends on Datalevin.
- `server.http.*` composes everything.

## Decision log

Decisions that shaped the architecture and shouldn't be re-litigated without reason.

- **Datalevin as the only persistence.** No Redis, no Postgres. Smaller surface, single-source-of-truth, simpler ops.
- **Length-prefixed binary signing input.** No JSON canonicalization for signatures — too many edge cases.
- **Non-extractable Web Crypto keys.** XSS cannot exfiltrate. Cost: legacy browser support requires the P-256 fallback.
- **Async transact-after-response.** Decouples write latency from decision latency. Cost: bounded event loss on crash; acceptable for statistical event data.
- **Strict `:db.unique/value` for nonces.** Upsert semantics (`:db.unique/identity`) would silently allow replays.
- **Sliding-window-counter, not sliding-log.** O(1) per check; the approximation error is bounded and acceptable for opportunistic-abuse defense.
- **No weak-attach in v1.** Cluster merge requires pubkey match or host-link attestation; no IP/fp-only continuity. Simpler, harder to poison.
- **ClojureScript-only client.** No hand-written JS facade. shadow-cljs `:target :npm-module` provides the JS distribution.

## Trade-offs accepted

- **Sliding-window-counter approximation** can under-count by up to ~prev-bucket-count for non-uniform bursts at bucket edges. Documented in `ratelimit/window.clj`.
- **5-second event-loss window** on app crash (async transact). Documented in `risk-register #7` in the plan.
- **Anonymous tier is intentionally low value.** Bootstrap is cheap; sybil gains nothing. Tier uplift requires sustained observation or host-link.
- **Client lib bundle ≤ 40 KB gzipped.** Hard CI gate (`scripts/check-bundle-size.mjs`). Current bundle is 31.79 KB. Future fingerprint signals can blow this; we will favor signal removal over budget increase.

## CI posture

continuity-auth does not use hosted CI runners. The verification gate is `just ci`, run locally on the maintainer's machine before every push.

The rationale is structural rather than performative. Hosted CI is, from the project's perspective, an extension of the trust boundary — a runner can execute arbitrary code with whatever secrets the workflow exposes, against whatever code the runner happens to checkout. For a project whose entire pitch is "don't trust signals you can't verify locally" — IP is advisory, browser fingerprint is advisory, the cryptographic key is the only authoritative axis — taking a hosted-runner dependency would be internally inconsistent.

The recent CI-ecosystem incidents make this more than a stylistic preference. The tj-actions/changed-files compromise (March 2025) leaked credentials from ~23,000 repos via a single compromised tag. The Ultralytics PyPI compromise (December 2024) routed through a GitHub Actions cache poisoning chain. GitHub's own audit logs document several action-cache poisoning patterns. The defensive ask isn't "trust GitHub" but "trust every action you transitively use, the runner image, the cache, and the secrets surface." That ask is incompatible with what this project is trying to be.

`just ci` runs:

```
clojure -M:lint-init   # populate clj-kondo cache from deps
clojure -M:lint        # clj-kondo
clojure -M:test        # kaocha (unit + adversarial + property + integration)
clojure -T:build uber  # uberjar build (proves the production artifact assembles)
node_modules/.bin/shadow-cljs release npm-module
node scripts/check-bundle-size.mjs
```

There is no PR auto-verification signal — the maintainer is the gate. This trades the contributor convenience of "your PR is green or red" for a smaller attack surface. The accepted cost is real: it slows third-party contributions, makes status visible only to the maintainer until the PR is reviewed locally, and asks contributors to run `just ci` themselves before they push. If the project's contributor population grows to the point where this gate is the bottleneck, the discussion to re-open is "can we run a self-hosted runner under our trust assumptions" — not "can we adopt GitHub Actions on faith."
