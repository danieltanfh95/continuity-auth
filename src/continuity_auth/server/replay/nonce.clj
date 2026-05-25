(ns continuity-auth.server.replay.nonce
  "Anti-replay cache for envelope nonces.

  Threat: an attacker who has captured a valid signed envelope replays
  it to forge a request. Mitigation: each envelope carries a 16-byte
  nonce and an ISO-8601 timestamp. The verify path:

    1. Rejects envelopes whose timestamp is outside the ±tolerance
       window relative to server clock (handled by the verify handler).
    2. Atomically checks the nonce hash against the cache and, if novel,
       records it with an expiry just longer than the timestamp window.

  We store the SHA-256 hash of the nonce, never the raw nonce. (The
  hash gains nothing for collision resistance — nonces are already
  random — but it normalizes lengths and avoids leaking nonce structure
  through the database if it is ever inspected directly.)

  Atomic check-and-record is performed by attempting a transact of the
  unique `:nonce/hash`. Datalevin throws on a uniqueness violation; we
  catch and treat it as replay. This is correct under LMDB's serialized
  writer model because the check-then-insert happens atomically inside
  the writer thread."
  (:require
   [com.brunobonacci.mulog :as mu]
   [continuity-auth.server.crypto.hash :as hash]
   [continuity-auth.server.storage.protocol :as storage]))

(defn nonce-hash
  "Return the 32-byte SHA-256 hash of a raw nonce."
  ^bytes [^bytes raw-nonce]
  (hash/sha256 raw-nonce))

(defn- plus-seconds
  ^java.util.Date [^java.util.Date now seconds]
  (java.util.Date. (+ (.getTime now) (* 1000 (long seconds)))))

(defn check-and-record!
  "Atomically check if the nonce has been seen and, if not, record it.

  Returns:
    :ok     — nonce was novel and is now recorded with TTL `ttl-seconds`.
    :replay — nonce was already in the cache (request must be rejected).

  Uses the single-writer atomicity of the underlying LMDB writer: the
  unique-identity constraint on `:nonce/hash` rejects duplicates at
  transact time, which is the correct concurrency primitive."
  [store raw-nonce ttl-seconds now]
  (let [h   (nonce-hash raw-nonce)
        exp (plus-seconds now ttl-seconds)]
    (try
      (storage/transact! store [{:nonce/hash       h
                                 :nonce/expires-at exp}])
      :ok
      (catch Throwable t
        ;; Datalevin reports uniqueness violations with a specific cause;
        ;; we treat ANY transact failure on the unique attribute as a
        ;; replay-or-failure. The handler does not distinguish between
        ;; them in its response, so the asymmetric branch here is purely
        ;; for the metrics path that follows in observability.
        (if (re-find #"(?i)unique" (or (ex-message t) ""))
          :replay
          (throw t))))))

(defn sweep!
  "Retract all nonce entities whose expiry has passed. Returns the
  number of entries reclaimed. Safe to call concurrently with reads;
  serialized against other writers by LMDB."
  [store now]
  (storage/sweep-expired! store :nonce/hash :nonce/expires-at now))

(defn start-sweeper!
  "Start a daemon thread that calls `sweep!` every `interval-seconds`.
  Returns a zero-arg `stop` function that interrupts the thread and
  waits for clean exit. Intended to be wired up by the system
  composition; tests can call sweep! directly without this.

  Failures (any non-Interrupted Throwable) are logged via `mu/log` as
  `:cauth/nonce-sweeper-failed` rather than silently swallowed (codex M8).
  Without this, storage errors hide until the DB fills."
  [store interval-seconds]
  (let [running? (volatile! true)
        thread   (Thread.
                  ^Runnable
                  (fn []
                    (while @running?
                      (try
                        (storage/sweep-expired!
                         store :nonce/hash :nonce/expires-at
                         (java.util.Date.))
                        (catch InterruptedException _
                          (vreset! running? false))
                        (catch Throwable t
                          ;; Best-effort: keep the cleaner alive across
                          ;; per-iteration errors, BUT log the failure so
                          ;; ops can see it (codex M8).
                          (mu/log :cauth/nonce-sweeper-failed
                                  :exception   (.getClass t)
                                  :message     (ex-message t))))
                      (when @running?
                        (try
                          (Thread/sleep (* 1000 (long interval-seconds)))
                          (catch InterruptedException _
                            (vreset! running? false))))))
                  "fpl-nonce-sweeper")]
    (.setDaemon thread true)
    (.start thread)
    (fn stop []
      (vreset! running? false)
      (.interrupt thread)
      (.join thread 5000))))
