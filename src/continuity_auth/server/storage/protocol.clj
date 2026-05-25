(ns continuity-auth.server.storage.protocol
  "The Storage protocol — the seam between the merge / handler logic and
  the database. Defining this here (rather than coupling directly to
  Datalevin) keeps higher-level code testable against in-memory fakes
  and leaves room for a future alternative implementation.")

(defprotocol Storage
  "Persistence and indexed lookup for continuity-auth entities.

  Implementations must be safe to call concurrently; in particular, the
  underlying store is expected to provide read snapshots that are stable
  for the duration of a single read operation (see `with-snapshot`)."

  (snapshot
    [this]
    "Return an opaque snapshot value usable as the basis for subsequent
    indexed lookups within the same read-consistent view. Read-only.
    Implementations should ensure this is cheap.")

  (pull
    [this snapshot eid-or-lookup-ref attrs]
    "Pull `attrs` from the entity identified by `eid-or-lookup-ref`
    against the given snapshot. Returns a map or nil if not found.")

  (q
    [this snapshot query inputs]
    "Run a Datalog query against the snapshot. `query` is a Datalog
    query in vector form; `inputs` is a (possibly empty) sequential
    collection of runtime parameters passed after the snapshot.")

  (find-pubkey-by-thumbprint
    [this snapshot thumbprint-bytes]
    "Look up a pubkey by its `:pubkey/id` thumbprint (32 SHA-256 bytes).
    Returns the entity map (with at least :db/id, :pubkey/identity,
    :pubkey/bytes, :pubkey/alg, :pubkey/revoked-at) or nil.")

  (find-tuples-by-ip
    [this snapshot ip]
    "Indexed lookup: all tuples whose :tuple/ip = ip. Returns a seq of
    entity maps.")

  (find-tuples-by-fp
    [this snapshot fp-digest-bytes]
    "Indexed lookup: all tuples whose :tuple/fp-digest = fp-digest-bytes.
    Returns a seq of entity maps.")

  (find-tuples-by-ls-pubkey
    [this snapshot pubkey-eid]
    "Indexed lookup: all tuples whose :tuple/ls-pubkey = pubkey-eid.")

  (find-buckets
    [this snapshot identity-eid window]
    "Return the at-most-2 active buckets for (identity, window) ordered
    by :bucket/start descending.")

  (find-host-link-by-host-user-id
    [this snapshot host-id host-user-id]
    "Return the host-link entity for (host-id, host-user-id), or nil.")

  (nonce-seen?
    [this snapshot nonce-hash]
    "Return true iff a non-expired nonce with that hash exists in the
    cache as of the snapshot. Hot path; must be fast.")

  (transact!
    [this tx-data]
    "Synchronous transaction. Returns the transaction report or throws.
    Use sparingly on the hot path; prefer `transact-async!`.")

  (transact-async!
    [this tx-data]
    "Asynchronous transaction. Returns a `future` (or analogue) that
    completes with the report or with an exception. Used by /verify to
    write event log entries without blocking the response.")

  (sweep-expired!
    [this attr expires-attr now]
    "Bulk-retract entities whose `expires-attr` is <= now, for the
    entity-class identified by `attr` (which must be a unique-identity
    attribute on the entity). Returns the number of entities retracted.
    Used by the nonce sweeper and the idempotency-cache sweeper.")

  (close
    [this]
    "Release the underlying connection. Idempotent."))
