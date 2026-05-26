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
- XSS as signing oracle (browser substrate): attacker can use the victim's signing key while present, but cannot exfiltrate it
- Filesystem-key compromise (CLI substrate): attacker reads `$CAUTH_HOME/key.pem` and can sign as the victim until anomaly detection demotes the identity
- Side-channel timing on signature verify
- Forced trust decay (denial of service against a specific identity)

All threats below assume a level-1+ caller (engaged with the protocol — see the engagement-ladder framing in [`../README.md`](../README.md)). Level-0 callers (no envelope at all) bypass continuity-auth entirely; the host's per-IP / CAPTCHA layer is what catches them. Fallback for non-engaging callers is a host-side composition concern, not a continuity-auth feature.

**Out of scope (v1):**
- Nation-state actors with rotating residential proxy pools + headless browser farms with per-instance fingerprint randomization
- Host application compromise (if the host's auth or HMAC keys leak, recovery is the host's responsibility)
- Physical-device compromise (key extracted via direct device access)

## Asset map

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Private key — browser substrate (Web Crypto + IndexedDB) | **HIGH** (`generateKey({extractable:false})` — bytes never reach JS heap) | n/a (cannot be modified externally) | LOW (user can clear IndexedDB) |
| Private key — CLI substrate (PEM on filesystem) | **MEDIUM** (filesystem read by anyone with `$CAUTH_HOME` access exfiltrates it; mode 0700 is the only barrier) | n/a (overwrite would just create a new identity) | MEDIUM (file deletion or rotate forces re-bootstrap) |
| Private key — hardware-anchored substrate (TPM / Secure Enclave / Keystore) | **HIGHEST** (key never leaves the secure element) | n/a | substrate-dependent (deferred to v1.1+) |
| Pubkey database | LOW (public material) | **HIGH** (database integrity) | MEDIUM |
| Trust scores | LOW | **HIGH** (decisions hang off this) | MEDIUM |
| Nonce cache | LOW | **HIGH** (replay defense) | MEDIUM (sweeper handles GC) |
| Host integration HMAC keys | **HIGH** (would allow forged links) | **HIGH** | MEDIUM |
| Admin HMAC keys | **HIGH** | **HIGH** | MEDIUM |

## Threats × mitigations

| # | Threat | Property violated | Mitigation | Code evidence |
|---|---|---|---|---|
| T1 | Private-key compromise — substrate-dependent | Confidentiality of the private key behind the identity | Substrate determines the attack surface. **Browser substrate:** Web Crypto `generateKey(..., {extractable: false}, ...)`; key handle stored in IndexedDB; private bytes never reach JS heap; XSS becomes a signing oracle (T12) but not an exfiltration vector. **CLI substrate:** PEM on filesystem at `$CAUTH_HOME/key.pem`; defense is filesystem permissions (mode 0700 expected); host compromise or filesystem read exfiltrates the key. The score model treats "same key, many IPs in a short window" as anomalous and demotes the identity via `:fp-mismatch` / `:ip-mismatch` / `:all-mismatch` deltas (see `:scoring` in `resources/config.edn`), bounding damage to a minutes-to-hours window. **Hardware-anchored substrate (v1.1+):** key never leaves the secure element. (Replaces standalone T19; T19 collapsed into the CLI row here.) | `src/continuity_auth/client/crypto.cljs` (browser); `src/continuity_auth/client/cli.clj` (CLI); `docs/non-browser-clients.md` "Threat model — keys on disk". |
| T2 | IP-header spoofing at CDN edge | Integrity of `ip` axis | Explicit trusted-proxy CIDR allowlist; only one configured header is honored; remote-addr fallback when no proxy. Direct connections from untrusted IPs are not believed for header-supplied IP. | `src/.../http/middleware.clj` `extract-client-ip`. |
| T3 | Fingerprint spoofing | Integrity of `fp` axis | Treated as **claimed**, never gates cluster entry. Only corroborates within a pubkey-anchored cluster. Documented in `docs/ontology.md §2`. | `test/.../adversarial/poisoning_test.clj` `fp-collision-does-not-merge`. |
| T4 | Replay (capture + resubmit signed envelope) | Authenticity / freshness | ± 60 s timestamp window + 16-byte nonce + 32-byte hash in unique cache for 120 s. Strict `:db.unique/value` semantics — duplicate-rejection at transact, not upsert. | `src/.../replay/nonce.clj` + `test/.../replay/nonce_test.clj` `concurrent-replay-attempts-rejected` (parallel attempt; exactly one writer wins). |
| T5 | Sybil (one human, many identities) | Trust-budget integrity | Anonymous tier is intentionally low value. Bootstrap is cheap by design but gains nothing — no tier uplift without either (a) host-link attestation or (b) sustained pubkey-anchored history. Host-link merge has 24-hour cooling-off. | `docs/ontology.md §6`, `§7`, `§8`. |
| T6 | Trust-vector poisoning: attacker causes IP/fp collision with victim to enter victim's cluster | Cluster integrity | Pubkey-match is the only merge gate (substrate-independent). IP/fp matches are advisory only. | `test/.../adversarial/poisoning_test.clj` `ip-collision-does-not-merge`, `fp-collision-does-not-merge`, `combined-ip-fp-collision-without-ls-key-does-not-merge` (test name predates the substrate-rename). |
| T7 | Cross-axis collision (request matches victim on fp, attacker on IP) | Disambiguation | Resolution: pubkey-match > host-link > exact (IP+fp); never merge across pubkey boundary. | `src/.../identity/merge.clj` `classify`. |
| T8 | Host `user_id` spoofing | Authorization of account axis | Host attests via HMAC over server-to-server `POST /v1/link-account`. Quarterly key rotation. | `src/continuity_auth/server/storage/schema.clj` `:host-link/host-sig-verified?`. (Link endpoint and rotation: pending, post-v1 task #16.) |
| T9 | TOCTOU on trust score | Decision integrity | Single Datalevin read snapshot for the decision; write via `transact-async!` after response dispatched. | `src/.../http/handlers/verify.clj` `make-handler` (snapshot bound once, used by classify + tier + windows). |
| T10 | Side-channel timing on signature verify | Confidentiality (which check failed) | Verify path runs to completion on invalid signatures and returns a uniform boolean — no early-exit branches the attacker can time (`crypto/verify.clj` docstring). Equality on byte-comparisons (admin HMAC tag, pubkey thumbprint) goes through `hash/constant-time-equal?`. Single error response shape; `code` is opaque (`E_UNAUTHORIZED`, not `E_BAD_SIGNATURE` vs `E_BAD_NONCE`). | `src/.../crypto/verify.clj`, `src/.../crypto/hash.clj` `constant-time-equal?`, `src/.../http/errors.clj`. |
| T11 | DoS via forced trust decay (attacker fabricates mismatches against victim) | Availability | Mismatch penalties apply only WITHIN a pubkey-anchored cluster. An attacker without the victim's private key (regardless of substrate) cannot enter the victim's cluster, so cannot induce trust-score deltas there. Cross-cluster matches go to the advisory log only. | `test/.../adversarial/poisoning_test.clj` `classify-records-cross-cluster-advisory-but-does-not-merge`. |
| T12 | XSS as signing oracle (attacker has JS execution while page is open) | Confidentiality (signed requests) | Key is non-extractable; attacker cannot exfiltrate. Attacker CAN request signatures while the page is open. We mitigate detection (client-side sign-rate cap, server-side anomaly metrics) but do not prevent. CSP guidance in README. | (mitigation guidance only; XSS prevention is host's responsibility) |
| T13 | Revoked-key continued use | Integrity of pubkey lifecycle | `:pubkey/revoked-at` is checked in `classify`; revoked → `:revoked-pubkey` → `E_FORBIDDEN`. | `test/.../identity/merge_test.clj` `classify-revoked-pubkey`. |
| T14 | Bootstrap sybil at scale | Trust-budget integrity | Anonymous tier severe; no tier uplift on bootstrap. `/v1/bootstrap` is per-IP exponential-backoff rate-limited (default floor 1s, cap 60s, doubling factor 2, 5-minute quiet reset). Each allow seeds the next penalty; denied attempts inside a window do not compound. Clock injection (`:now-fn`) enables deterministic tests. `Retry-After` header carries the actual remaining ms (ceiling-divided to seconds) — not the full window. | `src/.../http/middleware.clj` `wrap-bootstrap-rate-limit`; `test/.../http/middleware_test.clj` `bootstrap-rate-limit-*`. |
| T15 | Datalevin write-loss on crash (events lost) | Audit | Async transact carries best-effort semantics. Periodic 5-second committed-cursor watermark bounds loss. Documented as accepted trade-off — events are statistical, not authoritative. | `src/.../storage/datalevin.clj` `transact-async!`. |
| T16 | DoS via oversized request body (multi-MB JSON to exhaust heap) | Availability | Hard upper bound on the body in bytes (`:limits/:max-body-bytes`, default 64 KiB). `Content-Length` rejected before any read; chunked uploads drained at most `limit + 1` then rejected. Returns 413 `E_PAYLOAD_TOO_LARGE`. | `src/.../http/middleware.clj` `wrap-body-size-limit`, `test/.../http/integration_test.clj` `oversize-body-rejected`. |
| T17 | Unauthenticated admin call (force-revoke arbitrary key, dump config) | Authorization | All `/v1/admin/*` endpoints require X-Admin-{Key-Id, Ts, Nonce, Sig} headers. Sig is HMAC-SHA256 over method+path+sha256(body)+ts+nonce. Constant-time compare. ±60 s ts window. Nonce replay-cached (same store as envelope nonces). Server returns 403 `E_FORBIDDEN` when no admin keystore is configured (admin endpoints disabled). | `src/.../http/handlers/admin.clj` `verify-admin!`, `test/.../http/integration_test.clj` `admin-rejects-unsigned-call`, `admin-rejects-wrong-key`, `admin-disabled-without-keystore`. |
| T18 | Replayed admin call (captured Sig header reused) | Authenticity / freshness | Admin nonce is recorded in the same unique-attribute nonce cache as envelope nonces; duplicate rejected with `E_REPLAY`. Nonce check happens AFTER signature verifies, so attackers can't pollute the cache by spamming junk. | `src/.../http/handlers/admin.clj` `verify-admin!`, `src/.../replay/nonce.clj` `check-and-record!`. |
| ~~T19~~ | (Retired) — formerly "filesystem-resident private key (non-browser clients)"; collapsed into T1's CLI-substrate row when T1 was reframed as substrate-dependent. Renumbering reserved for the next protocol change. | — | — | — |

## Untreated risks (open items)

These are known gaps documented for the operator:

- **T8 implementation**: `POST /v1/link-account` is specified in `docs/api.md` but not yet implemented as an HTTP handler. v1.0 ships without the host-link path. Acceptable because tier uplift from anonymous → tracked happens via *sustained observation* in the pubkey-anchored cluster (the score model in `score.clj`); the host-link path is purely additive in v1.1.
- **T14 bootstrap rate limit — cross-instance fairness**: per-IP exponential backoff is implemented and on by default (`wrap-bootstrap-rate-limit` in `http/middleware.clj`; floor 1s, cap 60s, doubling factor 2, 5-minute quiet reset). The staircase collapses a one-IP attacker from "5 identities/min indefinitely" (the prior flat-quota shape) to roughly 60 identities/hour steady-state, while legitimate users behind shared NAT pay at most floor-ms once before bootstrapping. The strike state is a per-instance atom; an HA cluster of N nodes behind a load-balancer multiplies the per-IP rate by N. Cross-instance fairness requires backing the limiter with the Datalevin `ratelimit/window.clj` infrastructure (v1.1; see plan §"Out of scope" Tier 4). Per-IP aggregation is acceptable at bootstrap specifically because the false-positive cost is bounded (one delay before bootstrap, no impact on existing identities from that IP); the rest of the protocol keeps IP advisory.

  The framing is "time as a resource": the defender's wall-clock is unparallelizable and unforgeable, so an attacker with parallel compute on one IP still pays the same calendar as everyone else. A PoW gate (Anubis-style) prices the attacker in CPU-hours, which commoditizes via cheap GPU rentals; the exponential-backoff staircase prices them in wall-clock seconds, which doesn't. The Tier 2 IP-anchored signal layer (IP-age and identity-count-per-IP) further raises the multiplier for IPs that look attacker-shaped without changing the floor for legitimate users.
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
