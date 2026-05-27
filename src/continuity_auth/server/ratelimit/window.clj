(ns continuity-auth.server.ratelimit.window
  "Token-bucket-per-tier-per-window rate limiter.

  Algorithm (per identity, per window-keyword):
    - Persistent state: {:bucket/tokens <double>, :bucket/last-refill-ms <long>}
      keyed by `:bucket/key` = \"<identity-eid>|<window-name>\".
    - On each check at `now`:
        elapsed-ms        = max(0, now-ms - last-refill-ms)
        tokens-after-refill = min(capacity, tokens + elapsed-ms * leak-rate / 1000)
        if tokens-after-refill >= 1: allow, tokens := tokens-after-refill - 1
        else:                       deny,  tokens := tokens-after-refill,
                                    retry := ceil((1 - tokens-after-refill) / leak-rate * 1000)
    - The bucket entity is upserted via `:bucket/key` so concurrent
      writes converge on a single entity rather than fragmenting.

  Properties:
    - O(1) per check (one indexed lookup + one transact).
    - Continuous `retry-after-ms` — the next token's arrival time, not
      \"wait until the window edge.\"
    - Burst absorption up to `capacity`; steady-state throughput
      equals `leak-rate-per-sec`. With `leak-rate = capacity /
      window-seconds`, steady-state matches the pre-existing
      sliding-window scheme; only burst-recovery shape changes.

  Concurrency: the read-then-write is not strictly atomic. Under high
  concurrency, two writers can each observe the same `tokens-before`
  and both deduct, double-spending one token. That is bounded to at
  most (concurrent_writers - 1) extra allowed requests per race
  window — the same acceptable error documented previously.

  All times are `java.util.Date`; window-size is supplied as a seconds
  count alongside its keyword name."
  (:require
   [continuity-auth.server.storage.protocol :as storage]))

(defn- now-ms ^long [^java.util.Date d] (.getTime d))

(defn bucket-key
  "Per-(identity, window) slot key written into `:bucket/key`. Stable
  across time — token-bucket state evolves in place rather than
  fragmenting into time-aligned slots."
  ^String [identity-eid window]
  (str (long identity-eid) "|" (name window)))

(defn leak-rate-per-sec
  "Derive the steady-state leak rate from a window's capacity and
  duration. `(capacity / window-seconds)` keeps long-run throughput
  identical to the prior sliding-window scheme."
  ^double [capacity window-seconds]
  (if (and (pos? (long capacity)) (pos? (long window-seconds)))
    (/ (double capacity) (double window-seconds))
    0.0))

(defn refill
  "Pure: compute the post-refill token count, capped at `capacity`.
  Return-typed via internal coercion; the Clojure 4-primitive-arg
  ceiling prevents adding a `^double` return hint with this many args."
  [tokens-before last-refill-ms capacity leak-rate now-ms]
  (let [elapsed-ms (max 0 (- (long now-ms) (long last-refill-ms)))
        leaked     (* (double elapsed-ms) (/ (double leak-rate) 1000.0))]
    (double (min (double capacity) (+ (double tokens-before) leaked)))))

(defn decision
  "Pure: compute the proposed decision and new bucket state without I/O.
  Returns `{:allowed? bool, :retry-after-ms long, :new-tokens double,
  :tokens-after-refill double}`."
  [tokens-before last-refill-ms capacity leak-rate window-ms now-ms]
  (let [capacity            (long capacity)
        leak-rate           (double leak-rate)
        window-ms           (long window-ms)
        tokens-before       (double (or tokens-before capacity))
        last-refill-ms      (long (or last-refill-ms now-ms))
        tokens-after-refill (refill tokens-before last-refill-ms
                                    capacity leak-rate now-ms)
        allowed?            (and (pos? capacity) (>= tokens-after-refill 1.0))
        new-tokens          (if allowed?
                              (max 0.0 (- tokens-after-refill 1.0))
                              tokens-after-refill)
        retry-after-ms      (cond
                              allowed?         0
                              (zero? capacity) window-ms
                              (pos? leak-rate)
                              (long (Math/ceil
                                     (* 1000.0
                                        (/ (max 0.0 (- 1.0 tokens-after-refill))
                                           leak-rate))))
                              :else            window-ms)]
    {:allowed?            allowed?
     :retry-after-ms      retry-after-ms
     :new-tokens          new-tokens
     :tokens-after-refill tokens-after-refill}))

(defn- read-bucket
  "Indexed pull of the token-bucket entity for (identity, window). Returns
  `{:db/id ..., :tokens ..., :last-refill-ms ...}` or nil if no entity
  exists at the slot yet."
  [store snap identity-eid window]
  (let [b (storage/pull store snap [:bucket/key (bucket-key identity-eid window)]
                        [:db/id :bucket/tokens :bucket/last-refill-ms])]
    (when (:db/id b)
      {:db/id          (:db/id b)
       :tokens         (:bucket/tokens b)
       :last-refill-ms (:bucket/last-refill-ms b)})))

(defn- bucket-tx
  "Build the transact payload for writing the new bucket state."
  [existing identity-eid window new-tokens now-ms-val]
  (if existing
    {:db/id                 (:db/id existing)
     :bucket/tokens         (double new-tokens)
     :bucket/last-refill-ms (long now-ms-val)}
    {:bucket/key            (bucket-key identity-eid window)
     :bucket/identity       identity-eid
     :bucket/window         window
     :bucket/tokens         (double new-tokens)
     :bucket/last-refill-ms (long now-ms-val)}))

(defn consume-token!
  "Check whether a request is permitted under the token-bucket for
  (identity, window) with the given `capacity` and `window-seconds`, and
  if so consume one token. Returns:

    {:allowed?       true
     :retry-after-ms 0
     :tokens-after   <double>
     :limit          <long>}

    {:allowed?       false
     :retry-after-ms <long>
     :tokens-after   <double>
     :limit          <long>}

  On allow, the bucket is upserted with one fewer token. On deny, no
  write occurs — the existing bucket state already implies the same
  refill on the next check.

  `window` is the window keyword (e.g. `:1m`); `window-seconds` is its
  duration in seconds. `capacity` is the bucket size. Leak rate is
  derived as `capacity / window-seconds`. A capacity of 0 always
  throttles."
  [store identity-eid window window-seconds capacity ^java.util.Date now]
  (let [now-ms-val (now-ms now)
        window-ms  (* 1000 (long window-seconds))
        leak-rate  (leak-rate-per-sec capacity window-seconds)
        snap       (storage/snapshot store)
        existing   (read-bucket store snap identity-eid window)
        d          (decision (:tokens existing)
                             (:last-refill-ms existing)
                             capacity leak-rate window-ms now-ms-val)]
    (when (:allowed? d)
      (storage/transact!
       store
       [(bucket-tx existing identity-eid window
                   (:new-tokens d) now-ms-val)]))
    {:allowed?       (:allowed? d)
     :retry-after-ms (:retry-after-ms d)
     :tokens-after   (:new-tokens d)
     :limit          (long capacity)}))

(defn check-many
  "Check multiple windows for one identity. Returns the most-restrictive
  outcome — the request is allowed only if ALL windows allow. If any
  throttles, that decision is returned with the maximum
  `retry-after-ms` across denying windows. When all allow, all
  windows' buckets are upserted in a single transaction.

  `windows` is a seq of `{:window <keyword>, :seconds <long>}`. `limits`
  is a map of window-keyword to integer capacity (typically produced
  by `tier/limits-for`); a missing or zero entry always throttles."
  [store identity-eid windows limits ^java.util.Date now]
  (let [now-ms-val (now-ms now)
        snap       (storage/snapshot store)
        read-pass
        (mapv (fn [{:keys [window seconds] :as w}]
                (let [capacity   (long (get limits window 0))
                      window-ms  (* 1000 (long seconds))
                      leak-rate  (leak-rate-per-sec capacity seconds)
                      existing   (read-bucket store snap identity-eid window)
                      d          (decision (:tokens existing)
                                           (:last-refill-ms existing)
                                           capacity leak-rate window-ms now-ms-val)]
                  (assoc w
                         :limit          capacity
                         :existing       existing
                         :decision       d
                         :would-allow?   (:allowed? d)
                         :retry-after-ms (:retry-after-ms d))))
              windows)]
    (if-let [denials (seq (filter (complement :would-allow?) read-pass))]
      (let [worst (apply max-key :retry-after-ms denials)]
        {:allowed?       false
         :retry-after-ms (:retry-after-ms worst)
         :limit          (:limit worst)})
      (do
        (storage/transact!
         store
         (vec (for [{:keys [window existing decision]} read-pass]
                (bucket-tx existing identity-eid window
                           (:new-tokens decision) now-ms-val))))
        {:allowed? true
         :retry-after-ms 0}))))
