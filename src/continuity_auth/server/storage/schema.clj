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
  rewrite — the migration only stamps the version."
  4)

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

   :identity/score
   {:db/valueType :db.type/double}

   :identity/ever-tracked?
   {:db/valueType :db.type/boolean}

   :identity/erased-at
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
    :bootstrap :rotate-key :revoke-key :admin-revoke})
