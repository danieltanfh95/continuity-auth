# continuity-auth — threat model

Defensive analysis of continuity-auth as a *parallel auth method*: it does not replace host authentication; it provides advisory trust/rate-limit decisions to a host application that calls `POST /v1/verify` from its backend.

This document maps the attacks we *do* defend against, the attacks we *do not*, and where the boundary lies. Code-level evidence (test files) is referenced alongside each mitigation so reviewers can audit the implementation against the model.

## Scope

**In scope (v1):**
- Opportunistic abuse: a single attacker probing free-tier limits or attempting low-effort sybil
- Automated extraction: bots probing systematically
- Replay attacks: capture-and-resubmit of signed envelopes
- CDN/edge IP-header spoofing
- Trust-vector poisoning: causing the system to attribute the attacker's actions to a victim's cluster (or vice versa)
- Cross-axis collision: attacker shares IP or fingerprint with a victim
- XSS as signing oracle: attacker can use the victim's signing key while present, but cannot exfiltrate it
- Side-channel timing on signature verify
- Forced trust decay (denial of service against a specific identity)

**Out of scope (v1):**
- Nation-state actors with rotating residential proxy pools + headless browser farms with per-instance fingerprint randomization
- Host application compromise (if the host's auth or HMAC keys leak, recovery is the host's responsibility)
- Physical-device compromise (key extracted via direct device access)

## Asset map

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| LS private key (browser) | **HIGH** (never extractable) | n/a (cannot be modified externally) | LOW (user can clear) |
| Pubkey database | LOW (public material) | **HIGH** (database integrity) | MEDIUM |
| Trust scores | LOW | **HIGH** (decisions hang off this) | MEDIUM |
| Nonce cache | LOW | **HIGH** (replay defense) | MEDIUM (sweeper handles GC) |
| Host integration HMAC keys | **HIGH** (would allow forged links) | **HIGH** | MEDIUM |
| Admin HMAC keys | **HIGH** | **HIGH** | MEDIUM |

## Threats × mitigations

| # | Threat | Property violated | Mitigation | Code evidence |
|---|---|---|---|---|
| T1 | LS-key theft (XSS on host page, malicious extension) | Confidentiality of LS private key | Web Crypto `generateKey(..., {extractable: false}, ...)`. Key handle stored in IndexedDB. Private bytes never reach JS heap. | `src/continuity_auth/client/crypto.cljs` (client). |
| T2 | IP-header spoofing at CDN edge | Integrity of `ip` axis | Explicit trusted-proxy CIDR allowlist; only one configured header is honored; remote-addr fallback when no proxy. Direct connections from untrusted IPs are not believed for header-supplied IP. | `src/.../http/middleware.clj` `extract-client-ip`. |
| T3 | Fingerprint spoofing | Integrity of `fp` axis | Treated as **claimed**, never gates cluster entry. Only corroborates within an LS-anchored cluster. Documented in `docs/ontology.md §2`. | `test/.../adversarial/poisoning_test.clj` `fp-collision-does-not-merge`. |
| T4 | Replay (capture + resubmit signed envelope) | Authenticity / freshness | ± 60 s timestamp window + 16-byte nonce + 32-byte hash in unique cache for 120 s. Strict `:db.unique/value` semantics — duplicate-rejection at transact, not upsert. | `src/.../replay/nonce.clj` + `test/.../replay/nonce_test.clj` `concurrent-replay-attempts-rejected` (parallel attempt; exactly one writer wins). |
| T5 | Sybil (one human, many identities) | Trust-budget integrity | Anonymous tier is intentionally low value. Bootstrap is cheap by design but gains nothing — no tier uplift without either (a) host-link attestation or (b) sustained LS-anchored history. Host-link merge has 24-hour cooling-off. | `docs/ontology.md §6`, `§7`, `§8`. |
| T6 | Trust-vector poisoning: attacker causes IP/fp collision with victim to enter victim's cluster | Cluster integrity | LS-match is the only merge gate. IP/fp matches are advisory only. | `test/.../adversarial/poisoning_test.clj` `ip-collision-does-not-merge`, `fp-collision-does-not-merge`, `combined-ip-fp-collision-without-ls-key-does-not-merge`. |
| T7 | Cross-axis collision (request matches victim on fp, attacker on IP) | Disambiguation | Resolution: LS-match > host-link > exact (IP+fp); never merge across LS boundary. | `src/.../identity/merge.clj` `classify`. |
| T8 | Host `user_id` spoofing | Authorization of account axis | Host attests via HMAC over server-to-server `POST /v1/link-account`. Quarterly key rotation. | `src/continuity_auth/server/storage/schema.clj` `:host-link/host-sig-verified?`. (Link endpoint and rotation: pending, post-v1 task #16.) |
| T9 | TOCTOU on trust score | Decision integrity | Single Datalevin read snapshot for the decision; write via `transact-async!` after response dispatched. | `src/.../http/handlers/verify.clj` `make-handler` (snapshot bound once, used by classify + tier + windows). |
| T10 | Side-channel timing on signature verify | Confidentiality (which check failed) | Constant-time verify via BouncyCastle's libsodium-equivalent path. Single error response shape; `code` is opaque (`E_UNAUTHORIZED`, not `E_BAD_SIGNATURE` vs `E_BAD_NONCE`). | `src/.../http/errors.clj` (uniform `{ok, code, retry_after_ms}` shape), `src/.../crypto/hash.clj` `constant-time-equal?`. |
| T11 | DoS via forced trust decay (attacker fabricates mismatches against victim) | Availability | Mismatch penalties apply only WITHIN an LS-anchored cluster. An attacker without the victim's LS key cannot enter the victim's cluster, so cannot induce trust-score deltas there. Cross-cluster matches go to the advisory log only. | `test/.../adversarial/poisoning_test.clj` `classify-records-cross-cluster-advisory-but-does-not-merge`. |
| T12 | XSS as signing oracle (attacker has JS execution while page is open) | Confidentiality (signed requests) | Key is non-extractable; attacker cannot exfiltrate. Attacker CAN request signatures while the page is open. We mitigate detection (client-side sign-rate cap, server-side anomaly metrics) but do not prevent. CSP guidance in README. | (mitigation guidance only; XSS prevention is host's responsibility) |
| T13 | Revoked-key continued use | Integrity of pubkey lifecycle | `:pubkey/revoked-at` is checked in `classify`; revoked → `:revoked-pubkey` → `E_FORBIDDEN`. | `test/.../identity/merge_test.clj` `classify-revoked-pubkey`. |
| T14 | Bootstrap sybil at scale | Trust-budget integrity | Anonymous tier severe; no tier uplift on bootstrap. /v1/bootstrap is per-IP rate-limited (anti-spam) — pending wiring (task #16). | `docs/ontology.md §6`. |
| T15 | Datalevin write-loss on crash (events lost) | Audit | Async transact carries best-effort semantics. Periodic 5-second committed-cursor watermark bounds loss. Documented as accepted trade-off — events are statistical, not authoritative. | `src/.../storage/datalevin.clj` `transact-async!`. |
| T16 | DoS via oversized request body (multi-MB JSON to exhaust heap) | Availability | Hard upper bound on the body in bytes (`:limits/:max-body-bytes`, default 64 KiB). `Content-Length` rejected before any read; chunked uploads drained at most `limit + 1` then rejected. Returns 413 `E_PAYLOAD_TOO_LARGE`. | `src/.../http/middleware.clj` `wrap-body-size-limit`, `test/.../http/integration_test.clj` `oversize-body-rejected`. |
| T17 | Unauthenticated admin call (force-revoke arbitrary key, dump config) | Authorization | All `/v1/admin/*` endpoints require X-Admin-{Key-Id, Ts, Nonce, Sig} headers. Sig is HMAC-SHA256 over method+path+sha256(body)+ts+nonce. Constant-time compare. ±60 s ts window. Nonce replay-cached (same store as envelope nonces). Server returns 403 `E_FORBIDDEN` when no admin keystore is configured (admin endpoints disabled). | `src/.../http/handlers/admin.clj` `verify-admin!`, `test/.../http/integration_test.clj` `admin-rejects-unsigned-call`, `admin-rejects-wrong-key`, `admin-disabled-without-keystore`. |
| T18 | Replayed admin call (captured Sig header reused) | Authenticity / freshness | Admin nonce is recorded in the same unique-attribute nonce cache as envelope nonces; duplicate rejected with `E_REPLAY`. Nonce check happens AFTER signature verifies, so attackers can't pollute the cache by spamming junk. | `src/.../http/handlers/admin.clj` `verify-admin!`, `src/.../replay/nonce.clj` `check-and-record!`. |

## Untreated risks (open items)

These are known gaps documented for the operator:

- **T8 implementation**: `POST /v1/link-account` is specified in `docs/api.md` but not yet implemented as an HTTP handler. v1.0 ships without the host-link path. Acceptable because tier uplift from anonymous → tracked happens via *sustained observation* in the LS-anchored cluster (the score model in `score.clj`); the host-link path is purely additive in v1.1.
- **T14 bootstrap rate limit**: not yet implemented as a per-IP limiter on `/v1/bootstrap`. Mitigated for now by the fact that bootstrap is cheap to detect (high rate of new pubkeys from one IP) and ops would catch via metrics.
- **T15 event loss**: the 5-second watermark is documented but not yet implemented. v1.0 has fire-and-forget async transacts.

## Invariants (cross-referenced with `docs/ontology.md §10`)

The system's correctness rests on the following invariants. Any change that touches the implementation should re-verify them by running the test suite.

- **I1 — pubkey thumbprint uniqueness**: enforced by `:db.unique/identity` on `:pubkey/id`.
- **I3 — score bounded in [0, 1]**: enforced by `score/clamp`; property-tested at `score_test.clj` `p-apply-delta-bounded`.
- **I4 — nonce hash uniqueness**: enforced by `:db.unique/value` on `:nonce/hash`; concurrent-replay test at `nonce_test.clj`.
- **I5 — no revoked-key tuple creation**: enforced by classify-time rejection; tested at `merge_test.clj` `classify-revoked-pubkey`.
- **I6 — distinct identities never share pubkey thumbprint**: enforced by I1 + bootstrap creates new identity only.
- **I9 — erasure removes all identity-bearing entities**: enforced by the `DELETE /v1/identity/{id}` handler (implementation pending in v1.1).
- **I10 — verify decision uses single read snapshot**: enforced by capturing `snap` once in `verify/make-handler`.

## Threat-model review checklist (for security review skill)

- [ ] Every threat in the table has a code evidence pointer.
- [ ] Every code evidence pointer resolves to an existing file/test.
- [ ] No undocumented HTTP endpoint exists beyond the documented set.
- [ ] No JSON field in any endpoint is accepted without size validation.
- [ ] No log line includes raw private-key material, raw nonces, or signatures (only their hashes/digests).
- [ ] `clojure -M:test --focus :adversarial` passes.
