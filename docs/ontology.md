# continuity-auth — ontology

The conceptual model. Everything else (schema, merge algorithm, rate-limit engine, API) is a projection of this. If something in this document is wrong, fix it here first. Do not paper over it downstream.

## 1. Entities (the kinds of things in the system)

| Kind | What it is | Identity criterion | Owns its lifecycle? |
|---|---|---|---|
| `Identity` | A logical user cluster — the system's best guess at "the same actor". Not a person. | UUID `:identity/id` | Yes |
| `Tuple` | An observed combination `(ip, fp-digest, pubkey-ref)`. One tuple per distinct combination ever observed (not per request). | `(ip, fp-digest, pubkey)` triple. Composite key. | No — bound to one identity |
| `Pubkey` | A registered public key (Ed25519 / P-256). | 32-byte SHA-256 thumbprint of the canonical pubkey bytes | No — bound to one identity |
| `Request` | One observed `/verify` attempt. Audit/rate-limit data; never user-facing. | EID (or `nonce-hash` while live) | No — bound to one identity |
| `TrustEvent` | An explicit modification to an identity's trust score (audit trail). | EID | No — bound to one identity |
| `Nonce` | A one-shot anti-replay token. | Hash of the raw nonce (we never store the raw nonce). | Self |
| `HostLink` | Attestation by the host application: "host_user_id `X` belongs to identity `I`." | `(host-id, host-user-id)` pair | No — bound to one identity |
| `Bucket` | Token-bucket accounting unit. Two scopes: a per-caller bucket, one per `(identity, window)`, and a class bucket, one per `(tier, window)`, that every caller of a tier draws from collectively (back-pressure). State for both: `:bucket/tokens` (current count, double) + `:bucket/last-refill-ms` (epoch ms). `:bucket/scope` is `:identity` or `:class`. Tokens refill at a leak rate that defaults to `capacity / window-seconds` but is independently configurable. | `(scope, identity-or-tier, window)` | No — bound to one identity (`:identity` scope) or to a tier (`:class` scope) |
| `EraseStub` | Audit trace of a GDPR erasure. Hashed identity-id only; no user data. | EID + `:erase-stub/identity-hash` | Self (long-lived) |

A "Person" is not an entity in this system. We track clusters, and clusters are evidence-based proxies for persons. Two clusters can refer to one person (post-erasure regeneration, multiple devices without host-link). One cluster can in principle refer to multiple people (shared device with a shared keypair, such as a browser profile shared across users or a CLI `$CONTINUITY_AUTH_HOME` shared across operators). The system does not claim to identify persons.

## 2. The four axes (and why they are not equivalent)

Each axis in the trust vector has different epistemic status. This asymmetry is the central conceptual move of the system. Merge logic must respect it.

| Axis | Source | Server-verifiable? | Spoof difficulty | Trust role |
|---|---|---|---|---|
| `ip` | TCP/IP connection (or trusted-proxy header), stored as `HMAC-SHA256(ip)` under a server keystore secret (`:tuple/ip-hash`); raw IP exposed only inside the request's middleware chain for the CIDR check, never persisted, never logged | Yes — via the network stack | Hard for the naive attacker; trivial with a VPN/proxy chain | **Observed** |
| `fp-digest` | Client-computed; client claims it in the envelope | No — the server cannot independently compute the client's browser fingerprint | Trivial — any attacker can claim any digest | **Claimed** |
| `pubkey` | Client signs the envelope with the corresponding private key; pubkey thumbprint is in the envelope | Yes — by verifying the signature | Hard — requires private-key compromise via substrate-specific path (XSS for browser non-extractable WebCrypto, filesystem read for CLI PEM, physical device access for hardware-anchored) | **Cryptographic** |
| `host-user-id` | Host backend attests the binding via HMAC over a server-to-server call | Yes — by verifying the HMAC | Requires host secret compromise | **Cryptographic-by-proxy** |

Operational rule that falls out of this table:

> **Only cryptographic / cryptographic-by-proxy axes can *gate* cluster entry. Observed and claimed axes can only *corroborate* (positive evidence within a cluster) or *flag* (mismatch within a cluster).**

This is the formal version of "pubkey-match is the only trustworthy merge signal" from the plan. Concretely: a request arriving with a verified signature against a pubkey already attached to identity A is known to be from a holder of A's key. A request arriving with `ip` or `fp-digest` matching a tuple in identity A's cluster is merely consistent with such an actor. A determined attacker can fabricate either.

## 3. Identity lifecycle

States:

```
                         ┌────────────────────────────┐
                         ▼                            │
   (no identity) ── bootstrap ──► [active] ─── erase ─► (retracted; EraseStub remains)
                                    │
                                    ├──► [active] (score decays / increases over time)
                                    │
                                    └──► (no terminal "banned" state — banned is a tier projection, not a state)
```

Notable:

- `Identity` does not transition through `:registered → :active`. Bootstrap creates an active identity at anonymous tier in one step.
- `:anonymous`, `:tracked`, `:penalized`, `:banned` are **projections** of `(score, host-linked?)`, not stored states. They are computed at read time. This is important: it means tier transitions are continuous and reversible (decay can promote a penalized identity back to tracked).
- An identity has no separate "logged-in" state. Whether it has a `HostLink` is just a property visible from its outgoing refs.
- Erasure is one-way. After erasure, only `EraseStub` survives. There is no "un-erase".

## 4. Pubkey lifecycle

```
   (none) ── bootstrap ──► [registered, active]
                                  │
                                  ├── rotate-key ──► [rotated]
                                  │                     │ (successor created;
                                  │                     │  predecessor still
                                  │                     │  valid until grace_until)
                                  │                     ▼
                                  │                  [revoked]  (after grace_until,
                                  │                              or explicit revoke)
                                  │
                                  └── revoke-key / admin revoke ──► [revoked]
```

- `:rotated` is implicit: a pubkey is "rotated" when a successor with `:pubkey/rotation-of` referencing it exists AND `now < successor.created_at + grace_seconds`.
- `:revoked` is explicit: `:pubkey/revoked-at` is set.
- A revoked pubkey is retained in the DB for audit. Signatures against it always fail (irrespective of grace).
- Rotation produces *one* successor per predecessor at most. A second rotation creates a new successor that supersedes the first.

### 4b. Knowledge-factor reclaim (recovery from a new device)

Normally a pubkey enters an identity's cluster only via `bootstrap` (a *new* cluster) or `rotate-key` (signed by an existing key of *that* cluster). Reclaim adds a third, narrow entry path: a holder of the **knowledge factor** (a secret only the user knows) can attach a fresh device key to an *existing* identity from a device that has never held one of its keys.

The identity stores a **verifier** — an Ed25519 public key the user derives client-side as `Argon2id(secret, salt)`, where `salt` is a domain-separated hash of the identity UUID (unique, not secret). The server keeps only `IV ‖ AES-256-GCM(kf-wrap-secret, kf-pubkey)`; the secret and the KF private key never leave the client. The KF attributes live on the `Identity`:

```
:identity/kf-verifier  bytes    IV(12) ‖ AES-256-GCM(kf-wrap-secret, kf-pubkey)
:identity/kf-alg        keyword  :ed25519 (only value in v0.4.0)
:identity/kf-kdf        keyword  :argon2id-v1 (fixed protocol constant; stored for versioning)
:identity/kf-set-at     instant  when the verifier was set/replaced
```

These are sparse — absent ⇒ no knowledge factor ⇒ pure pre-v6 behavior. They sit on the Identity, so the erasure path (I9) that retracts the identity already covers them.

A reclaim proof is **cryptographic-by-proxy** (§2): possession of the knowledge factor, proven by signing a challenge, is the gate for *re-attaching a key* — it is **not** a trust signal. Reclaim therefore grants **no tier uplift**: it attaches the new pubkey and leaves the spaced-continuity sketch (§6) untouched, so the reclaimed key inherits the identity's *earned* tier. You recover continuity, not free trust. This is the one exception to "pubkey-match is the only cluster-entry gate," and it is deliberate: the knowledge factor is itself a cryptographic gate, just keyed on something the user knows rather than something their device holds. Old keys are not auto-revoked at reclaim (the server cannot distinguish "lost device" from "second device"); the user revokes them explicitly via `revoke-key`.

## 5. Tuple lifecycle

Tuples are append-only inside an identity's cluster. They have no retraction except via erasure. They are never re-bound to a different identity except via the host-link merge described in §8.

A tuple's `:tuple/observation-count` and `:tuple/last-seen` are updated each time the same `(ip, fp, pubkey)` combination is re-observed. No other axis can be updated.

## 6. Trust as a structured quantity

Trust on an identity is a single continuous score in `[0.0, 1.0]`. Tier and limits are functions of `(score, host-linked?)`:

```
tier(score, host-linked?) =
    :anonymous   if not host-linked? and score < 0.3
    :tracked     if (not host-linked? and score >= 0.3) or
                    (host-linked? and score >= 0.5)
    :penalized   if score < 0.3 and identity has ever been :tracked
    :banned      if score < 0.05
```

`limits(tier, window)` is a lookup table loaded from config. Each cell
carries a bucket capacity and a leak rate; the leak rate defaults to
`capacity / window-seconds` but is independently configurable, so a tier
can have a large burst capacity with a slow steady drain or vice versa.
The per-tier `priority_weight` surfaced to hosts is likewise config-driven.

Orthogonal to these per-caller limits, an optional **class cap** sets a
shared ceiling per `(tier, window)` across all callers of that tier. A
request must pass BOTH its per-caller bucket and (if configured) its
class bucket. The class cap is back-pressure: it bounds aggregate tier
throughput regardless of how many distinct identities appear, so a flood
of well-behaved-individually callers cannot collectively swamp the service.

The score is **not** a running sum of per-verify deltas. It is a
*spaced-continuity memory weight* recomputed at read time from a small
O(1) per-identity sketch, in the spirit of the spacing effect: a key seen
long ago and again recently is more load-bearing than one seen frequently
in a short burst. Spaced recurrence dominates raw frequency, which makes
earned trust expensive to farm — volume can be manufactured cheaply, but
calendar time and spacing cannot.

The sketch (updated O(1) on each verify, see §1 `Identity`):

```
:identity/clean-count       long    pubkey-matched verifies (continuity signal)
:identity/spacing           double  Σ ln(1+gap_days) over returns after a dormant gap
:identity/created-at        instant first-seen (span anchor)
:identity/last-clean-at     instant last reinforcing verify (decay + gap detection)
:identity/violation-count   long    axis-mismatch / anomaly observations
```

The score is derived from the sketch at `now`:

```
freq   = min(√clean-count, freq-cap)          ; freq-cap 4.0 (volume saturates fast)
span   = (1 + ln(1 + span-days))^span-exp      ; span-exp 1.5 (calendar longevity)
gap    = 1 + spacing                            ; spaced returns accumulate here
within = (span-days < span-min) ? 0.5 : 1.0     ; penalize single-burst cram only
decay  = 0.5 ^ (idle-days / half-life)          ; half-life 30d, idle = now − last-clean
base   = freq · span · gap · within · decay
earned = 1 − 2^(−base / squash-scale)           ; squash-scale 60.0 → [0,1)
vrate  = violation-count / (violation-count + clean-count)
score  = clamp01( (floor + (1−floor)·earned) · (1 − violation-k·vrate) )   ; floor 0.1
```

Constants live in config `:scoring` (see [`config.edn`](../resources/config.edn))
and `score/default-scoring`. Consequences of this shape:

- A **fresh clean key** (clean-count 1, no span, no spacing) derives ≈ 0.105
  — the score floor, in the `:anonymous` band. Bootstrap is cheap and a
  brand-new key (including a farmed sybil) is *unproven*, never `:tracked`
  on arrival.
- **Bot-cram** (thousands of massed hits in an hour) stays `:anonymous`:
  frequency saturates at the √-cap, and with no span and no spacing the
  weight barely lifts off the floor.
- **`:banned` is reached through the violation term**, not absence of
  history. Low *earned* trust means "unproven" (`:anonymous`), not "bad".
  A high violation rate (axis mismatches / anomalies) erodes the score
  toward 0 regardless of how much continuity was accrued.
- A new tuple with an axis mismatch (a roaming user on a new IP) still
  *reinforces* continuity (clean-count++) while recording a violation — a
  single relocation barely dents the score; persistent mismatching erodes
  it via `vrate`.

Each verify records a `TrustEvent` (`:trust-event/delta` = the change in
derived score this event caused) for audit. `:identity/score` is retained
as a write-time cache for audit/metrics; the verify path always recomputes
from the sketch. The sketch fields are updated synchronously in the same
transaction as the request event.

## 7. Tuple membership rule (merge)

Given an incoming envelope:

1. Verify signature → obtain a verified `pubkey` (cryptographic axis: PASSED or REJECTED).
2. Look up the pubkey thumbprint:
   - If it maps to an identity (`I_LS`), the request is gated into that identity's cluster — no exceptions. (This is the invariant I6 in §10.)
   - If it does not, this is a bootstrap-equivalent: a new identity is created and the pubkey attached.
3. Within `I_LS`, look up the incoming `(ip, fp-digest)` against the identity's tuples:
   - Same `(ip, fp-digest)` as an existing tuple → observation, no new tuple. Score reinforcement.
   - Different — at least one axis differs from any existing tuple → new tuple in this identity's cluster. Score penalty according to which axes differ.

The cluster never grows across identities through `ip` or `fp-digest` alone. Cross-axis matches against tuples in different identities are logged as advisory and possibly become an ops signal. A fingerprint shared by two clusters is a useful trace, but it does not merge them.

## 8. Cross-identity merge (host-link)

> **Status (v0.1.0):** the host-link path described below is *specified, not
> yet implemented.* The `:host-link/*` schema attributes exist, but
> `POST /v1/link-account` is not wired as an HTTP handler in v0.1.0 — see
> `docs/api.md` (planned, v1.1) and `docs/threat-model.md` T8/T14. Tier
> uplift from anonymous → tracked in v0.1.0 happens via sustained
> observation in the pubkey-anchored cluster (`score.clj`). The host-link path
> is purely additive.

The intended-by-design way two identities would become one is via a host-link attestation that says "identity-A and identity-B both belong to host_user_id `X`". Operationally:

1. Host would call `POST /v1/link-account` attesting `(host_user_id, identity_ref)`. Each call would create an in-state `HostLink` with `:host-link/state :pending`.
2. If `host_user_id` is already linked to a *different* identity, that would be a pending merge candidate:
   - Record `(identity-A, identity-B, host_user_id, cool-until = now + 24h)` as a `MergePending`.
   - Emit ops alert.
3. After `cool-until`, if no admin abort, the merge would commit:
   - All tuples, pubkeys, host-links, requests, trust-events from identity-B are re-pointed to identity-A.
   - Identity-B is retracted.
   - Identity-A's score = max(A.score, B.score). Tier re-projects.
   - Buckets: max(A.bucket.count, B.bucket.count) per (window-size, start).
4. If ops aborts within the cooling-off, the merge would be dropped and a `TrustEvent` recorded.

The 24h is a blast-radius reducer. A compromised host HMAC cannot merge arbitrary identities silently in the time it takes ops to detect. It does not eliminate the risk. It shrinks it.

## 9. The signed envelope as the system's truth-bearer

A request is admitted to the trust system iff:

- The envelope deserializes correctly,
- All structural validations pass (sizes, UTF-8 bounds),
- `|now - envelope.ts| ≤ replay-window`,
- `envelope.nonce` has not been seen in the last `nonce-ttl`,
- The signature verifies against `envelope.key-id`.

Anything else (score, tier, limits, response) is derived from this envelope plus what is already in the database. The envelope is the truth-bearer because it is the only artefact whose contents cannot be tampered with after the client produces it.

This is structurally identical to pdsa's "challenge-response with a client-derived secret", but generalized:
- pdsa: one secret, one identity, register-then-prove.
- continuity-auth: one secret (private key, substrate-specific) + corroborating signals, an identity per key, no separate register step. The first signed envelope auto-registers.

## 10. Invariants

| # | Statement | Enforced by |
|---|---|---|
| I1 | A pubkey thumbprint maps to exactly one identity. | `:pubkey/id` is `:db.unique/identity`; mass-merge logic in §8 re-points pubkeys before retracting. |
| I2 | A tuple maps to exactly one identity. | `:tuple/identity` ref; transaction logic. |
| I3 | An identity's derived score is always in `[0.0, 1.0]`. | `score/score-of` clamps; the score is recomputed from the sketch at read time. |
| I12 | A fresh clean key projects to `:anonymous`, never `:tracked`; `:banned`/`:penalized` are reached only via the violation term, not absence of history. | `score/score-of` floors a no-violation key at `:score-floor` (≈ 0.105 < tracked threshold); the `(1 − violation-k·vrate)` factor is the only path below the floor. |
| I4 | A nonce hash is unique in the DB while live. | `:nonce/hash` is `:db.unique/identity`. |
| I5 | A tuple cannot be created with a pubkey-ref whose `:pubkey/revoked-at` is set. | Verify step rejects revoked-key envelopes upstream of tuple creation. |
| I6 | Two distinct identities never share a pubkey thumbprint. | I1; merge logic in §8. |
| I7 | A `HostLink` in `:pending` state does not cause a cross-identity merge. | §8 step 3 is gated on `cool-until` elapsed AND no admin abort. |
| I8 | Exactly one bucket per `(identity, window)` and exactly one class bucket per `(tier, window)`. | `:bucket/key` is `:db.unique/identity` (`"<eid>\|<window>"` or `"tier:<tier>\|<window>"`); concurrent writes upsert into one entity. |
| I11 | A request is admitted only if it passes its per-caller bucket AND, when a class cap is configured for its tier+window, the class bucket too. A denial by either consumes no tokens from any bucket. | `ratelimit/window.clj` `check!` — allow iff all specs allow; transact only on full allow. |
| I9 | Erasure removes all identity-bearing entities; only an `EraseStub` remains. | Erasure transaction is one big tx; tested in adversarial suite. |
| I10 | Every `/verify` decision is computed from a single consistent read snapshot of the DB. | One read tx per request; write is `transact-async` after the response is dispatched. |

## 11. Provenance — who can claim what about whom

A request envelope makes implicit claims. We classify them by who can be held to them:

- The **client** can claim its `fp-digest` and its `key-id`. The latter is bound by the signature: a claim of `key-id = K` is honored only if the signature verifies under `K`'s public key. The former is honored at face value but never used as a gating criterion.
- The **client** cannot claim its `ip`. The server takes the IP from the network layer (or a trusted-proxy header configured by ops). The envelope's ts and nonce ride along but the IP does not.
- The **host** can claim a `host-user-id → identity_ref` binding, gated by HMAC. The host *cannot* claim which user is signing (the client owns the private key).
- The **server** observes: `ip`, `ts` (via its own clock plus tolerance), signature validity, nonce uniqueness.

Anything that violates this provenance ("the client claims its IP", "the host claims a tuple") is a category error and must be rejected at the boundary, not honored.

## 12. Genericity ontology

The above is the v1 implementation. The system is generic in three dimensions, each captured by a protocol:

| Protocol | What it generalizes | v1 implementations |
|---|---|---|
| `Axis` | A component of the trust vector | `IPAxis`, `FpDigestAxis`, `LSPubkeyAxis`, `HostUserIdAxis` |
| `TrustPolicy` | Mapping `(identity sketch, now) → (derived score, tier, limits)` | `DefaultPolicy` (the spaced-continuity weight in §6) |
| `Storage` | Persistence + indexed lookup | `DatalevinStorage` |

A new axis is added by:
1. Implementing `Axis`.
2. Declaring its `weight` (`:cryptographic | :advisory | :weak`).
3. Registering in config.

The merge algorithm operates on `weight`, not on hardcoded axis names. Adding a new `:cryptographic` axis (e.g., mTLS client cert thumbprint, device attestation token) automatically participates in cluster gating. An `:advisory` axis only corroborates.

## 13. Out of scope (v1)

These are deliberate omissions from the ontology:

- **Person.** Not modeled. The system identifies clusters of evidence.
- **Session.** Not modeled. The system is stateless across requests. The client-side key handle is the only persistent state.
- **Account.** Not modeled. Host accounts are referenced via `HostLink`, never owned.
- **Trust transitivity.** Trust does not propagate from one identity to another via shared signals.
- **Geo / ASN.** Not an axis in v1. Could be added via the `Axis` protocol in v2.
- **Behavioral ML.** v1 has structural anomaly signals only (regular intervals, concurrency), no learned model.
- **Multi-tenancy.** v1 is single-host per deployment. Schema is namespaced so multi-tenant can be added without migration.

## 14. Glossary

- **axis** — one named component of the trust vector (`ip`, `fp-digest`, `pubkey`, `host-user-id`).
- **bootstrap** — the first signed request from a new keypair. Creates an identity at anonymous tier.
- **claimed** — epistemic status of a signal whose value the server takes at face value from the client.
- **cluster** — a synonym for an identity's set of attached tuples.
- **cool-until** — the timestamp before which a pending host-link merge cannot commit.
- **cryptographic** — epistemic status of a signal whose validity the server verifies cryptographically.
- **delta** — a single trust-score change recorded as a `TrustEvent`.
- **envelope** — the signed payload sent with every request to continuity-auth.
- **identity** — a logical user cluster, the system's unit of trust accounting.
- **key-id** — 32-byte SHA-256 thumbprint of a pubkey's canonical bytes.
- **pubkey-match** — the case in which an envelope's `key-id` resolves to a pubkey already attached to an identity. (Formerly "LS-match", from the browser-localStorage era. Renamed because the substrate-prefix embedded an assumption the protocol no longer relies on. See [`docs/non-browser-clients.md`](non-browser-clients.md).)
- **observed** — epistemic status of a signal the server reads from out-of-band machinery (TCP/IP, clock).
- **tier** — the discrete projection of trust score plus host-link state. Determines rate limits.
- **tuple** — an `(ip, fp-digest, pubkey-ref)` combination observed once or more.
- **verify (endpoint)** — `POST /v1/verify`, the main path. Returns a rate-limit decision.
- **verify (cryptographic)** — the operation of checking a signature against a pubkey.
