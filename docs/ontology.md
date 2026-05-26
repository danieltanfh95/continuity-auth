# continuity-auth — ontology

The conceptual model. Everything else (schema, merge algorithm, sliding window, API) is a projection of this. If something in this document is wrong, fix it here first; do not paper over it downstream.

## 1. Entities (the kinds of things in the system)

| Kind | What it is | Identity criterion | Owns its lifecycle? |
|---|---|---|---|
| `Identity` | A logical user cluster — the system's best guess at "the same actor". Not a person. | UUID `:identity/id` | Yes |
| `Tuple` | An observed combination `(ip, fp-digest, pubkey-ref)`. One tuple per distinct combination ever observed (not per request). | `(ip, fp-digest, pubkey)` triple. Composite key. | No — bound to one identity |
| `Pubkey` | A registered public key (Ed25519 / P-256). | 32-byte SHA-256 thumbprint of the canonical pubkey bytes | No — bound to one identity |
| `Request` | One observed `/verify` attempt. Audit/sliding-window data; never user-facing. | EID (or `nonce-hash` while live) | No — bound to one identity |
| `TrustEvent` | An explicit modification to an identity's trust score (audit trail). | EID | No — bound to one identity |
| `Nonce` | A one-shot anti-replay token. | Hash of the raw nonce (we never store the raw nonce). | Self |
| `HostLink` | Attestation by the host application: "host_user_id `X` belongs to identity `I`." | `(host-id, host-user-id)` pair | No — bound to one identity |
| `Bucket` | Accounting unit for the sliding-window-counter algorithm. | `(identity, window-size, start)` | No — bound to one identity |
| `EraseStub` | Audit trace of a GDPR erasure. Hashed identity-id only; no user data. | EID + `:erase-stub/identity-hash` | Self (long-lived) |

A *Person* is not an entity in this system. We track clusters; clusters are evidence-based proxies for persons. Two clusters can refer to one person (post-erasure regeneration, multiple devices without host-link); one cluster can in principle refer to multiple people (shared device with a shared keypair — browser profile shared across users, CLI `$CAUTH_HOME` shared across operators). The system does not claim to identify persons.

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

This is the formal version of "pubkey-match is the only trustworthy merge signal" from the plan. Concretely: a request arriving with a verified signature against a pubkey already attached to identity A is *known* to be from a holder of A's key. A request arriving with `ip` or `fp-digest` matching a tuple in identity A's cluster is merely *consistent with* such an actor — but a determined attacker can fabricate either.

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
- A revoked pubkey is retained in the DB for audit; signatures against it always fail (irrespective of grace).
- Rotation produces *one* successor per predecessor at most. A second rotation creates a new successor that supersedes the first.

## 5. Tuple lifecycle

Tuples are append-only inside an identity's cluster. They have no retraction except via erasure. They are *not* re-bound to a different identity except via the host-link merge described in §8.

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

`limits(tier, window)` is a static lookup table loaded from config.

Score deltas:

```
+0.05    pubkey-match within cluster (a verified signature against a known pubkey)
+0.30    HostLink committed (after cooling-off)
-0.02    IP mismatch within cluster
-0.05    fp-digest mismatch within cluster
-0.10    Both ip+fp mismatch within cluster (new tuple, pubkey-only match)
-0.05    Behavioral anomaly (regular-interval signaling, high concurrency)
+ decay  Toward 0.5 at 0.01/day with no activity
```

Each delta is recorded as a `TrustEvent` for audit.

**The score is the only attribute that changes asynchronously**; all other identity attributes are either created-and-immutable or updated synchronously with bookkeeping.

## 7. Tuple membership rule (merge)

Given an incoming envelope:

1. Verify signature → obtain a verified `pubkey` (cryptographic axis: PASSED or REJECTED).
2. Look up the pubkey thumbprint:
   - If it maps to an identity (`I_LS`), the request is gated into that identity's cluster — no exceptions. (This is the invariant I6 in §10.)
   - If it does not, this is a bootstrap-equivalent: a new identity is created and the pubkey attached.
3. Within `I_LS`, look up the incoming `(ip, fp-digest)` against the identity's tuples:
   - Same `(ip, fp-digest)` as an existing tuple → observation, no new tuple. Score reinforcement.
   - Different — at least one axis differs from any existing tuple → new tuple in this identity's cluster. Score penalty according to which axes differ.

The cluster never grows across identities through `ip` or `fp-digest` alone. Cross-axis matches against tuples in *different* identities are logged as advisory and possibly become an ops signal (a fingerprint shared by two clusters is *interesting*, but it does not merge them).

## 8. Cross-identity merge (host-link)

> **Status (v0.1.0):** the host-link path described below is *specified, not
> yet implemented.* The `:host-link/*` schema attributes exist, but
> `POST /v1/link-account` is not wired as an HTTP handler in v0.1.0 — see
> `docs/api.md` (planned, v1.1) and `docs/threat-model.md` T8/T14. Tier
> uplift from anonymous → tracked in v0.1.0 happens via sustained
> observation in the pubkey-anchored cluster (`score.clj`); the host-link path
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

The 24h is a *blast radius reducer*: a compromised host HMAC cannot merge arbitrary identities silently in the time it takes ops to detect. It does not eliminate the risk — it shrinks it.

## 9. The signed envelope as the system's truth-bearer

A request is admitted to the trust system iff:

- The envelope deserializes correctly,
- All structural validations pass (sizes, UTF-8 bounds),
- `|now - envelope.ts| ≤ replay-window`,
- `envelope.nonce` has not been seen in the last `nonce-ttl`,
- The signature verifies against `envelope.key-id`.

Anything else — score, tier, limits, response — is derived from this envelope plus what is already in the database. The envelope is the truth-bearer because it is the only artefact whose contents cannot be tampered with after the client produces it.

This is structurally identical to pdsa's "challenge-response with a client-derived secret", but generalized:
- pdsa: one secret, one identity, register-then-prove.
- continuity-auth: one secret (private key, substrate-specific) + corroborating signals, an identity per key, no separate register step — the first signed envelope auto-registers.

## 10. Invariants

| # | Statement | Enforced by |
|---|---|---|
| I1 | A pubkey thumbprint maps to exactly one identity. | `:pubkey/id` is `:db.unique/identity`; mass-merge logic in §8 re-points pubkeys before retracting. |
| I2 | A tuple maps to exactly one identity. | `:tuple/identity` ref; transaction logic. |
| I3 | An identity's score is always in `[0.0, 1.0]`. | Score-mutation transaction-fn clamps. |
| I4 | A nonce hash is unique in the DB while live. | `:nonce/hash` is `:db.unique/identity`. |
| I5 | A tuple cannot be created with a pubkey-ref whose `:pubkey/revoked-at` is set. | Verify step rejects revoked-key envelopes upstream of tuple creation. |
| I6 | Two distinct identities never share a pubkey thumbprint. | I1; merge logic in §8. |
| I7 | A `HostLink` in `:pending` state does not cause a cross-identity merge. | §8 step 3 is gated on `cool-until` elapsed AND no admin abort. |
| I8 | At most 2 buckets per `(identity, window-size)` at any time. | Bucket allocator in `ratelimit/window.clj`. |
| I9 | Erasure removes all identity-bearing entities; only an `EraseStub` remains. | Erasure transaction is one big tx; tested in adversarial suite. |
| I10 | Every `/verify` decision is computed from a single consistent read snapshot of the DB. | One read tx per request; write is `transact-async` after the response is dispatched. |

## 11. Provenance — who can claim what about whom

A request envelope makes implicit claims. We classify them by who can be held to them:

- The **client** can claim its `fp-digest` and its `key-id`. The latter is bound by the signature: a claim of `key-id = K` is honored only if the signature verifies under `K`'s public key. The former is honored at face value but never used as a gating criterion.
- The **client** cannot claim its `ip`. The server takes the IP from the network layer (or a trusted-proxy header configured by ops); the envelope's ts and nonce ride along but the IP does not.
- The **host** can claim a `host-user-id → identity_ref` binding, gated by HMAC. The host *cannot* claim which user is signing (the client owns the private key).
- The **server** observes: `ip`, `ts` (via its own clock plus tolerance), signature validity, nonce uniqueness.

Anything that violates this provenance ("the client claims its IP", "the host claims a tuple") is a category error and must be rejected at the boundary, not honored.

## 12. Genericity ontology

The above is the v1 instantiation. The system is generic in three dimensions, each captured by a protocol:

| Protocol | What it generalizes | v1 implementations |
|---|---|---|
| `Axis` | A component of the trust vector | `IPAxis`, `FpDigestAxis`, `LSPubkeyAxis`, `HostUserIdAxis` |
| `TrustPolicy` | Mapping `(identity, recent_events) → (score deltas, tier, limits)` | `DefaultPolicy` (the table in §6) |
| `Storage` | Persistence + indexed lookup | `DatalevinStorage` |

A new axis is added by:
1. Implementing `Axis`.
2. Declaring its `weight` (`:cryptographic | :advisory | :weak`).
3. Registering in config.

The merge algorithm operates on `weight`, not on hardcoded axis names. Adding a new `:cryptographic` axis (e.g., mTLS client cert thumbprint, device attestation token) automatically participates in cluster gating; an `:advisory` axis only corroborates.

## 13. Out of scope (v1)

These are deliberate omissions from the ontology:

- **Person.** Not modeled. The system identifies clusters of evidence.
- **Session.** Not modeled. The system is stateless across requests; the client-side key handle is the only persistent state.
- **Account.** Not modeled. Host accounts are referenced via `HostLink`, never owned.
- **Trust transitivity.** Trust does not propagate from one identity to another via shared signals.
- **Geo / ASN.** Not an axis in v1. Could be added via the `Axis` protocol in v2.
- **Behavioral ML.** v1 has structural anomaly signals only (regular intervals, concurrency); no learned model.
- **Multi-tenancy.** v1 is single-host per deployment. Schema is namespaced so multi-tenant can be added without migration.

## 14. Glossary

- **axis** — one named component of the trust vector (`ip`, `fp-digest`, `pubkey`, `host-user-id`).
- **bootstrap** — the first signed request from a new keypair; creates an identity at anonymous tier.
- **claimed** — epistemic status of a signal whose value the server takes at face value from the client.
- **cluster** — a synonym for an identity's set of attached tuples.
- **cool-until** — the timestamp before which a pending host-link merge cannot commit.
- **cryptographic** — epistemic status of a signal whose validity the server verifies cryptographically.
- **delta** — a single trust-score change recorded as a `TrustEvent`.
- **envelope** — the signed payload sent with every request to continuity-auth.
- **identity** — a logical user cluster; the system's unit of trust accounting.
- **key-id** — 32-byte SHA-256 thumbprint of a pubkey's canonical bytes.
- **pubkey-match** — the case in which an envelope's `key-id` resolves to a pubkey already attached to an identity. (Formerly "LS-match", from the browser-localStorage era; renamed because the substrate-prefix embedded an assumption the protocol no longer relies on — see [`docs/non-browser-clients.md`](non-browser-clients.md).)
- **observed** — epistemic status of a signal the server reads from out-of-band machinery (TCP/IP, clock).
- **tier** — the discrete projection of trust score plus host-link state; determines rate limits.
- **tuple** — an `(ip, fp-digest, pubkey-ref)` combination observed once or more.
- **verify (endpoint)** — `POST /v1/verify`; the main path. Returns a rate-limit decision.
- **verify (cryptographic)** — the operation of checking a signature against a pubkey.
