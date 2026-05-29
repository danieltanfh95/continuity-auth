# continuity-auth — architecture

High-level overview. The conceptual model lives in `ontology.md`, the wire protocol in `crypto-protocol.md`, and the operational view in `deployment.md`.

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
│   Token-bucket check (ratelimit/window.clj)                 │
│        per-caller + class buckets → transact all            │
│                                                             │
│   Datalevin (LMDB or dtlv:// server)                         │
│        identity, tuple, pubkey, request, trust-event,       │
│        nonce, host-link, bucket, erase-stub                 │
└─────────────────────────────────────────────────────────────┘
```

## Key design points

### The four axes are not equivalent

| Axis | Epistemic status | Role |
|---|---|---|
| `pubkey` | Cryptographic | The only merge gate |
| `host-user-id` | Cryptographic-by-proxy (HMAC) | Cross-identity merge via cooling-off |
| `ip` | Observed | Advisory only |
| `fp-digest` | Claimed | Advisory only |

This asymmetry is the heart of why continuity-auth resists poisoning attacks: an attacker who shares the victim's IP and fingerprint cannot enter the victim's cluster because they lack the victim's private key (regardless of substrate, whether browser non-extractable WebCrypto, CLI PEM, or hardware-anchored). See `ontology.md §2` and `threat-model.md §T3`, `§T6`.

### Single read snapshot per decision

The `/verify` handler obtains one Datalevin snapshot at the start of the request. All downstream computation (pubkey lookup, cluster classification, tier projection, token-bucket check) reads from that snapshot. Writes are dispatched via `transact-async!` after the response is sent.

This is what makes the decision TOCTOU-safe (invariant I10) and keeps response latency decoupled from write throughput.

### Rate-limit engine: token-bucket per tier per window

Each `(identity, window)` pair has one token-bucket entity keyed by `:bucket/key = "<identity-eid>|<window>"`. Capacity is the per-tier per-window value from `:ratelimit/:tiers` in config (e.g. `:tracked {:1m 30 :5m 120 :1d 5000}`). Leak rate defaults to `capacity / window-seconds`, which makes steady-state throughput identical to the prior sliding-window engine. The difference is the recovery shape under burst: `retry_after_ms` is the time until the next token leaks back into the bucket, not the time until the window edge. A trusted caller who exhausts a `:1m` budget recovers within a few hundred milliseconds rather than tens of seconds.

**Independent leak rate.** A `:tiers` cell may be a bare number (capacity, leak derived as above) or a map `{:capacity <long> :leak-per-sec <double>}` that sets the leak rate independently of capacity. The cell is normalized to the map form once at spec-build time (`window/normalize-cell`); the pure `refill`/`decision` arithmetic is unchanged. This lets an operator decouple burst size from steady-state drain — a large `:capacity` with a small `:leak-per-sec` absorbs spikes but refills slowly.

**Class-level back-pressure caps.** Per-caller buckets bound each identity; they do not bound the aggregate. Ten thousand distinct anonymous identities, each within its own budget, can collectively saturate the service — the structural answer to "what stops 1000 farmed keys." `:ratelimit/:class-caps` adds one shared bucket per `(tier, window)`, keyed `:bucket/key = "tier:<tier>|<window>"` (no collision with the numeric per-caller keys) and tagged `:bucket/scope :class` with no `:bucket/identity`. Because production runs multiple stateless instances over one Datalevin server, the cap must be shared state, so the class bucket is an ordinary DB entity read and written in the **same** snapshot+transact as the per-caller buckets — no extra round trip. A request must pass both gates; the handler runs one `check!` over the concatenated per-caller and class specs, allows iff every spec allows, and on allow writes every bucket in one transaction. A denial at either gate writes nothing (a caller is not charged for a class-level shed) and the 429 reports which gate fired via `scope` (`"caller"` vs `"class"`). The cap inherits the same bounded read-then-write overshoot the per-caller buckets already document; it's a soft back-pressure floor, and CAS/token-leasing is noted as future hardening. Off by default (absent `:class-caps`).

The verify response surfaces `:priority_weight`, a numeric proxy for tier that hosts can use as a weighted-fair-queuing weight. The defaults mirror the `:1m` capacity ratios but are overridable via `:ratelimit/:priority-weights`; the handler reads the configured map (falling back to defaults, and to `1.0` for an unknown tier). continuity-auth itself does not hold connections or implement priority admission (that would turn the trust service into a deployment liability). Priority queuing belongs in the host backend or a sidecar, and `priority_weight` is the integration seam.

### Pure-where-possible, transactional-where-necessary

Spaced-continuity scoring, tier projection, token-bucket arithmetic, envelope canonicalization are pure functions. Storage interaction is concentrated in two phases per request: read at the top, write asynchronously after the decision. This makes most of the system trivially testable without a real DB. Only the integration layer needs ephemeral Datalevin.

### Genericity through protocols

Three Clojure protocols define the seams:
- `Axis` — pluggable identity-vector component
- `TrustPolicy` — pluggable scoring
- `Storage` — pluggable persistence

In v1 only the default implementations exist. The protocols are documented as the v2 evolution path.

## Layer / namespace map

```
continuity-auth.envelope                    .cljc — shared client+server codec
continuity-auth.crypto                      .cljc — algorithm constants

continuity-auth.server.crypto.{hash,pubkey,verify}   JVM crypto
continuity-auth.server.crypto.{ip-hmac,verifier-box} keystore-wrapped material
continuity-auth.server.storage.{schema,protocol,datalevin,migrations}
continuity-auth.server.replay.nonce         replay cache
continuity-auth.server.identity.{score,merge}   trust math + classification
continuity-auth.server.ratelimit.{tier,window}  tiering + windowed counter
continuity-auth.server.http.{errors,middleware,router,envelope-check,util}
continuity-auth.server.http.handlers.{bootstrap,verify,health,rotate-key,
                                       revoke-key,set-verifier,
                                       recover-identity,admin}  endpoints
continuity-auth.server.admin.hmac           admin HMAC verification
continuity-auth.server.protocols.*          Axis / TrustPolicy / Storage seams
continuity-auth.server.observability.{metrics,logging}
continuity-auth.server.{config,system,main} composition

continuity-auth.client.{core,crypto,fingerprint,storage,tabs,kf}  cljs client
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
- **Length-prefixed binary signing input.** No JSON canonicalization for signatures, too many edge cases.
- **Non-extractable Web Crypto keys.** XSS cannot exfiltrate. Cost: legacy browser support requires the P-256 fallback.
- **Async transact-after-response.** Decouples write latency from decision latency. Cost: bounded event loss on crash, acceptable for statistical event data.
- **Strict `:db.unique/value` for nonces.** Upsert semantics (`:db.unique/identity`) would silently allow replays.
- **Token-bucket, not sliding-log.** O(1) per check, with burst absorption up to capacity and a recovery shape (next-token-leak) friendlier to trusted callers than window-edge resets. Leak rate is configurable per cell.
- **No weak-attach in v1.** Cluster merge requires pubkey match or host-link attestation, no IP/fp-only continuity. Simpler, harder to poison.
- **ClojureScript-only client.** No hand-written JS facade. shadow-cljs `:target :npm-module` provides the JS distribution.
- **Knowledge-factor recovery: derive-and-wrap, not store-the-secret.** The KF verifier is an Ed25519 pubkey the client derives via `Argon2id(secret, salt)`; the server stores it AES-256-GCM-wrapped under a keystore secret separate from the IP-HMAC key (`crypto/verifier-box`), the same opaque-at-rest membrane as `:tuple/ip-hash`. Reclaim flows `system → recover-identity/make-handler`: the new-key envelope proves the new private key (route/nonce binding via `envelope-check`), then `verifier-box/unwrap` + `crypto/verify` check the KF signature; on success a new `Pubkey` is attached to the existing identity with no sketch change. Argon2id + BIP-39 run client-side only (`client/kf`); the JVM never runs Argon2id (it only wraps/unwraps and verifies a signature). OPAQUE/OPRF (defending a live-compromised server) is deferred — no mature JVM library, and the server-secret membrane matches the existing IP-hash boundary (threat-model T20).

## Trade-offs accepted

- **Read-then-write token-bucket overshoot.** Concurrent verifies for the same bucket read the same snapshot, so under flood a bucket can briefly serve slightly more than capacity before the writes settle. Bounded and acceptable for opportunistic-abuse defense; the class-cap bucket inherits the same property. Documented in `ratelimit/window.clj`. CAS/token-leasing is noted as future hardening.
- **5-second event-loss window** on app crash (async transact). Documented in `risk-register #7` in the plan.
- **Anonymous tier is intentionally low value.** Bootstrap is cheap, sybil gains nothing. Tier uplift requires sustained observation or host-link. Trust is a **spaced-continuity memory weight** (ontology §6), not a per-verify accumulator: it rewards *spaced* recurrence (a key seen long ago and again recently) over *massed* frequency (many hits in a burst). This is the structural anti-farming property — volume is cheap to manufacture, calendar time and spacing are not. The score is derived at read time from an O(1) per-identity sketch; a fresh clean key lands at the floor (`:anonymous`) and `:banned` is reached only through the violation term.
- **Client lib bundle ≤ 64 KB gzipped.** Hard CI gate (`scripts/check-bundle-size.mjs`). Current bundle is 60.07 KB. The v0.4.0 jump from ~32 KB is the knowledge-factor recovery stack: Argon2id has no SubtleCrypto primitive and an Ed25519 pubkey cannot be derived from a raw seed via WebCrypto, so `client/kf` links paulmillr's audited pure-JS libraries (`@noble/hashes`, `@noble/ed25519`, `@scure/bip39` + its 2048-word list). The whole stack lands in the single `core.js`, so even verify-only consumers pay it. Documented future optimisation: code-split the KF cold path into a dynamically-imported chunk so the verify hot path returns to ~32 KB. Beyond fingerprint signals, we favor signal removal / the code-split over budget increases.

## CI posture

continuity-auth does not use hosted CI runners. The verification gate is `just ci`, run locally on the maintainer's machine before every push.

The rationale is structural, not stylistic. Hosted CI is, from the project's perspective, an extension of the trust boundary: a runner can execute arbitrary code with whatever secrets the workflow exposes, against whatever code the runner happens to checkout. For a project whose entire pitch is "don't trust signals you can't verify locally" (IP is advisory, browser fingerprint is advisory, the cryptographic key is the only authoritative axis), taking a hosted-runner dependency would be internally inconsistent.

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

There is no PR auto-verification signal. The maintainer is the gate. This trades the contributor convenience of "your PR is green or red" for a smaller attack surface. The accepted cost is real: it slows third-party contributions, makes status visible only to the maintainer until the PR is reviewed locally, and asks contributors to run `just ci` themselves before they push. If the project's contributor population grows to the point where this gate is the bottleneck, the discussion to re-open is "can we run a self-hosted runner under our trust assumptions", not "can we adopt GitHub Actions on faith."
