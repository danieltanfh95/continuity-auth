(ns continuity-auth.server.storage.schema
  "Datalevin attribute schema for continuity-auth.

  The schema is the authoritative declaration of the database shape. Every
  attribute used anywhere in the system MUST be declared here. Reading
  values for an undeclared attribute returns nothing; writing them is an
  error.

  Schema versioning: see :schema/version below. The migrations runner
  reads this constant on app startup and refuses to start if the live
  schema version is ahead of, or incompatible with, this code's version.

  Index annotations:
    :db/unique     — :db.unique/identity creates a unique upsert key
    :db/index      — secondary AVET index for attribute lookups
    :db/cardinality — :db.cardinality/many for set-valued attributes
    :db/valueType  — value type; see Datalevin docs

  The shape here is derived directly from docs/ontology.md §1.")

(def ^:const schema-version
  "Monotonically increasing schema version. Bump on any non-additive change.
  Additive changes (new attributes, new entities) may share a version.

  v2 (2026-05-25): add `:bucket/key` as the unique-identity slot key for
  rate-limit buckets. Before v2 there was no uniqueness on
  `(identity, window, start)`, so concurrent verify-paths at a window
  boundary each created their own bucket and the counter fragmented across
  them. With `:bucket/key` set to `\"<identity-eid>|<window>|<start-ms>\"`
  and `:db.unique/identity`, all writes to the same slot upsert into a
  single entity.

  v3 (2026-05-26): rename `:tuple/ip` → `:tuple/ip-hash`. The stored
  value is now HMAC-SHA256(client-ip) under a server-side keystore
  secret, hex-encoded. Equality is preserved (same IP under a fixed key
  → same hash), so cluster grouping is unchanged; only the
  representation-at-rest is pseudonymous. See
  `continuity-auth.server.crypto.ip-hmac` for the keystore.

  v4 (2026-05-28): add `:bucket/scope` (`:identity` | `:class`) to
  distinguish per-caller buckets from class-level back-pressure buckets.
  Additive: Datalevin picks up the new attribute on open; old per-caller
  buckets lack it (sparse) and read as nil. Class buckets are keyed
  `\"tier:<tier>|<window>\"` and carry no `:bucket/identity`. No data
  rewrite — the migration only stamps the version.

  v5 (2026-05-28): trust score becomes a derived spaced-continuity weight
  rather than a stored accumulator. Adds the per-identity O(1) sketch the
  weight is recomputed from at read time:
  `:identity/clean-count` (long), `:identity/spacing` (double),
  `:identity/violation-count` (long), `:identity/last-clean-at` (instant).
  `:identity/score` is retained as a write-time cache for audit/metrics,
  but the verify path now derives the score from the sketch (see
  `continuity-auth.server.identity.score`). Additive: existing identities
  read missing sketch fields as nil → a fresh-key sketch (clean-count 0)
  → score floor → :anonymous, i.e. everyone re-earns trust from the safe
  default. No data rewrite — the migration only stamps the version.

  v6 (2026-05-29): optional knowledge-factor binding for identity reclaim
  from a new device. Adds four sparse Identity attributes:
  `:identity/kf-verifier` (bytes), `:identity/kf-alg` (keyword),
  `:identity/kf-kdf` (keyword), `:identity/kf-set-at` (instant). The
  verifier is `IV ‖ AES-256-GCM(kf-wrap-secret, kf-pubkey)` — an Ed25519
  public key derived client-side from `Argon2id(secret, salt)`, then
  wrapped under a server keystore secret so a DB-only dump leaves it
  opaque (mirrors the `:tuple/ip-hash` membrane). The salt is derived from
  the identity UUID, so no salt is stored. Absent ⇒ no knowledge factor
  set ⇒ pure v5 behaviour. Additive — Datalevin picks up the new attrs on
  open; no data rewrite. See `continuity-auth.server.crypto.verifier-box`
  and `continuity-auth.server.http.handlers.{set-verifier,recover-identity}`.

  v7 (2026-05-29): IP-bounce penalty (durable fast-down for a same-key,
  same-fingerprint identity rotating across many IPs at high frequency —
  the rotating-residential-proxy signature). Adds five sparse Identity
  attributes that extend the trust sketch:
  `:identity/last-ip-hash` (string) and `:identity/last-ip-change-at`
  (instant) track the previous IP under a stable fingerprint and anchor a
  fast (~1h half-life) exponentially-decaying IP-change-velocity estimator
  `:identity/ip-churn` (double). When the decayed churn crosses a
  threshold, a durable `:identity/ip-bounce-strikes` (long) accrues
  (rate-limited to one per cooldown window via `:identity/last-strike-at`,
  instant). Strikes decay on a slow (~14d) half-life and both erode the
  derived score and hard-floor the tier to :penalized — realising the
  project's slow-up / fast-down asymmetry (penalties are harder to shed
  than rewards are to earn). A strike writes a `:trust-event` with reason
  `:ip-bounce`. Absent ⇒ ip-churn 0, strikes 0 ⇒ identical to pure v6
  behaviour. Additive — Datalevin picks up the new attrs on open; no data
  rewrite. See `continuity-auth.server.identity.score`."
  7)

(def schema
  "Datalevin attribute schema, one entry per attribute. The schema is
  passed at connection time; Datalevin enforces it on transact."
  {;; -- schema meta (a single entity) --------------------------------------
   :schema/version
   {:db/valueType :db.type/long
    :db/unique    :db.unique/identity}

   ;; -- identity ----------------------------------------------------------
   :identity/id
   {:db/valueType :db.type/uuid
    :db/unique    :db.unique/identity}

   :identity/created-at
   {:db/valueType :db.type/instant
    :db/index     true}

   :identity/last-event-at
   {:db/valueType :db.type/instant
    :db/index     true}

   ;; Write-time cache of the derived trust score. The verify path
   ;; recomputes the score from the sketch below at read time; this slot
   ;; is for audit/metrics inspection, not the source of truth.
   :identity/score
   {:db/valueType :db.type/double}

   :identity/ever-tracked?
   {:db/valueType :db.type/boolean}

   ;; -- trust sketch (spaced-continuity weight inputs, v5) ----------------
   ;; The score is a memory weight recomputed at read time from this O(1)
   ;; per-identity sketch (see `continuity-auth.server.identity.score`).
   ;; `:identity/created-at` is the span anchor; `:identity/last-clean-at`
   ;; anchors decay + gap detection.
   :identity/clean-count
   {:db/valueType :db.type/long}            ; pubkey-matched clean verifies

   :identity/spacing
   {:db/valueType :db.type/double}          ; Σ ln(1+gap_days) over spaced returns

   :identity/violation-count
   {:db/valueType :db.type/long}            ; axis-mismatch / anomaly observations

   :identity/last-clean-at
   {:db/valueType :db.type/instant
    :db/index     true}                     ; last reinforcing verify

   :identity/erased-at
   {:db/valueType :db.type/instant
    :db/index     true}

   ;; -- IP-bounce velocity + durable strikes (v7) -------------------------
   ;; Extends the trust sketch to detect a same-key, same-fingerprint
   ;; identity rotating across many IPs at high frequency. All five are
   ;; sparse: absent ⇒ ip-churn 0, strikes 0 ⇒ pure v6 behaviour.
   ;; `:identity/last-ip-hash` is the previous IP-hash seen under a stable
   ;; fingerprint; `:identity/last-ip-change-at` anchors the fast-decaying
   ;; `:identity/ip-churn` velocity estimator; `:identity/ip-bounce-strikes`
   ;; is the durable, slow-decaying penalty counter; `:identity/last-strike-at`
   ;; anchors strike decay and the accrual cooldown. See
   ;; `continuity-auth.server.identity.score`.
   :identity/last-ip-hash
   {:db/valueType :db.type/string}

   :identity/last-ip-change-at
   {:db/valueType :db.type/instant}

   :identity/ip-churn
   {:db/valueType :db.type/double}

   :identity/ip-bounce-strikes
   {:db/valueType :db.type/long}

   :identity/last-strike-at
   {:db/valueType :db.type/instant}

   ;; -- knowledge-factor binding (v6, optional identity reclaim) ----------
   ;; A user-set secret-derived verifier that lets the same identity be
   ;; reclaimed from a new device. `:identity/kf-verifier` is
   ;; `IV(12) ‖ AES-256-GCM(kf-wrap-secret, kf-pubkey)` — an Ed25519 public
   ;; key derived client-side from `Argon2id(secret, salt)`, wrapped under
   ;; the server's kf-wrap keystore secret so a DB-only dump cannot mount an
   ;; offline dictionary attack (no verifier to check guesses against). The
   ;; salt is derived from the identity UUID, so it is NOT stored. All four
   ;; attrs are sparse: absent ⇒ no knowledge factor ⇒ reclaim impossible.
   :identity/kf-verifier
   {:db/valueType :db.type/bytes}

   :identity/kf-alg
   {:db/valueType :db.type/keyword}          ; :ed25519 (only value in v6)

   :identity/kf-kdf
   {:db/valueType :db.type/keyword}          ; :argon2id-v1

   :identity/kf-set-at
   {:db/valueType :db.type/instant
    :db/index     true}

   ;; -- tuple --------------------------------------------------------------
   :tuple/id
   {:db/valueType :db.type/uuid
    :db/unique    :db.unique/identity}

   :tuple/identity
   {:db/valueType :db.type/ref
    :db/index     true}

   ;; `:tuple/ip-hash` is HMAC-SHA256(client-ip) hex-encoded, under the
   ;; server's IP-HMAC keystore (see `continuity-auth.server.crypto.ip-hmac`).
   ;; Equality is preserved (same IP under a fixed key → same hash), so
   ;; cluster grouping is unchanged. The raw IP is never persisted.
   :tuple/ip-hash
   {:db/valueType :db.type/string
    :db/index     true}

   :tuple/fp-digest
   {:db/valueType :db.type/bytes
    :db/index     true}

   :tuple/pubkey
   {:db/valueType :db.type/ref
    :db/index     true}

   :tuple/first-seen
   {:db/valueType :db.type/instant}

   :tuple/last-seen
   {:db/valueType :db.type/instant
    :db/index     true}

   :tuple/observation-count
   {:db/valueType :db.type/long}

   ;; -- pubkey -------------------------------------------------------------
   :pubkey/id
   {:db/valueType :db.type/bytes
    :db/unique    :db.unique/identity}

   :pubkey/identity
   {:db/valueType :db.type/ref
    :db/index     true}

   :pubkey/bytes
   {:db/valueType :db.type/bytes}

   :pubkey/alg
   {:db/valueType :db.type/keyword
    :db/index     true}

   :pubkey/created-at
   {:db/valueType :db.type/instant
    :db/index     true}

   :pubkey/revoked-at
   {:db/valueType :db.type/instant
    :db/index     true}

   :pubkey/rotation-of
   {:db/valueType :db.type/ref}

   ;; -- request (sliding-window event log) --------------------------------
   :request/identity
   {:db/valueType :db.type/ref
    :db/index     true}

   :request/ts
   {:db/valueType :db.type/instant
    :db/index     true}

   :request/outcome
   {:db/valueType :db.type/keyword
    :db/index     true}

   :request/tuple
   {:db/valueType :db.type/ref}

   :request/match-axes
   {:db/valueType  :db.type/keyword
    :db/cardinality :db.cardinality/many}

   ;; -- trust-event (audit) ----------------------------------------------
   :trust-event/identity
   {:db/valueType :db.type/ref
    :db/index     true}

   :trust-event/ts
   {:db/valueType :db.type/instant
    :db/index     true}

   :trust-event/delta
   {:db/valueType :db.type/double}

   :trust-event/reason
   {:db/valueType :db.type/keyword
    :db/index     true}

   :trust-event/score-after
   {:db/valueType :db.type/double}

   ;; -- nonce cache (anti-replay) -----------------------------------------
   ;; :db.unique/value enforces strict rejection of duplicate transacts;
   ;; :db.unique/identity would silently merge entities, which is the
   ;; wrong semantics for replay protection.
   :nonce/hash
   {:db/valueType :db.type/bytes
    :db/unique    :db.unique/value}

   :nonce/expires-at
   {:db/valueType :db.type/instant
    :db/index     true}

   ;; -- host-link (host_user_id attestation) ------------------------------
   :host-link/id
   {:db/valueType :db.type/uuid
    :db/unique    :db.unique/identity}

   :host-link/host-id
   {:db/valueType :db.type/string
    :db/index     true}

   :host-link/host-user-id
   {:db/valueType :db.type/string
    :db/index     true}

   :host-link/identity
   {:db/valueType :db.type/ref
    :db/index     true}

   :host-link/state
   {:db/valueType :db.type/keyword
    :db/index     true}                    ; :pending | :committed | :revoked

   :host-link/linked-at
   {:db/valueType :db.type/instant
    :db/index     true}

   :host-link/cool-until
   {:db/valueType :db.type/instant
    :db/index     true}

   :host-link/host-sig-verified?
   {:db/valueType :db.type/boolean}

   ;; -- bucket (token-bucket rate-limit accounting) -----------------------
   ;; `:bucket/key` is the slot key with `:db.unique/identity` so concurrent
   ;; writes upsert into one entity. Two scopes share the same attributes:
   ;;   - per-caller: key `"<identity-eid>|<window-name>"`, `:bucket/scope
   ;;     :identity`, `:bucket/identity` set.
   ;;   - class (back-pressure): key `"tier:<tier>|<window-name>"`,
   ;;     `:bucket/scope :class`, no `:bucket/identity`. One bucket shared
   ;;     by all callers of a tier+window.
   ;; State evolves over time via `:bucket/tokens` and `:bucket/last-refill-ms`.
   ;;
   ;; `:bucket/start` and `:bucket/count` are legacy attributes from the
   ;; pre-token-bucket sliding-window scheme. They remain declared in
   ;; the schema (sparse) so old data in long-lived stores doesn't
   ;; trigger schema errors, but the current algorithm does not read
   ;; or write them. A future cleanup PR will drop them once production
   ;; stores have been soaked at the new schema for some time.
   :bucket/key
   {:db/valueType :db.type/string
    :db/unique    :db.unique/identity}

   :bucket/identity
   {:db/valueType :db.type/ref
    :db/index     true}

   :bucket/window
   {:db/valueType :db.type/keyword
    :db/index     true}                   ; :1m | :5m | :1d | ...

   :bucket/scope
   {:db/valueType :db.type/keyword
    :db/index     true}                   ; :identity | :class

   :bucket/tokens
   {:db/valueType :db.type/double}

   :bucket/last-refill-ms
   {:db/valueType :db.type/long}

   ;; -- legacy bucket attrs (sliding-window scheme, no longer written) ----
   :bucket/start
   {:db/valueType :db.type/instant
    :db/index     true}

   :bucket/count
   {:db/valueType :db.type/long}

   ;; -- erase-stub (GDPR audit trace) -------------------------------------
   :erase-stub/identity-hash
   {:db/valueType :db.type/bytes
    :db/unique    :db.unique/value}

   :erase-stub/erased-at
   {:db/valueType :db.type/instant
    :db/index     true}

   :erase-stub/reason
   {:db/valueType :db.type/keyword}

   :erase-stub/host-id
   {:db/valueType :db.type/string
    :db/index     true}

   ;; -- idempotency cache -------------------------------------------------
   :idempotency/key
   {:db/valueType :db.type/string
    :db/unique    :db.unique/identity}

   :idempotency/body-hash
   {:db/valueType :db.type/bytes}

   :idempotency/response
   {:db/valueType :db.type/string}        ; serialized JSON

   :idempotency/expires-at
   {:db/valueType :db.type/instant
    :db/index     true}})

(def host-link-states
  "Valid values for :host-link/state."
  #{:pending :committed :revoked})

(def request-outcomes
  "Valid values for :request/outcome."
  #{:ok :throttled :forbidden})

(def trust-event-reasons
  "Valid values for :trust-event/reason. Extend when adding new score
  deltas; the merge and score namespaces must agree."
  #{:pubkey-match :host-link-committed :ip-mismatch :fp-mismatch
    :all-mismatch :anomaly :decay :erasure-requested :admin-reset
    :bootstrap :rotate-key :revoke-key :admin-revoke
    :set-verifier :recover-identity :ip-bounce})
