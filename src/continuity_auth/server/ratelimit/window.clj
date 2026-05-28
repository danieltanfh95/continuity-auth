(ns continuity-auth.server.ratelimit.window
  "Token-bucket rate limiter, two scopes.

  - Per-caller buckets: one per (identity, window), keyed
    \"<identity-eid>|<window>\".
  - Class buckets (back-pressure): one per (tier, window), keyed
    \"tier:<tier>|<window>\", shared by all callers of a tier. A request
    must pass BOTH its per-caller buckets and (when configured) its class
    buckets. `check!` evaluates a seq of resolved bucket specs against a
    single snapshot and allows iff every spec allows.

  Algorithm (per bucket):
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

(defn class-bucket-key
  "Class (back-pressure) slot key for `(tier, window)`. The `\"tier:\"`
  prefix can never collide with a per-caller key, whose prefix is a
  numeric identity eid."
  ^String [tier window]
  (str "tier:" (name tier) "|" (name window)))

(defn leak-rate-per-sec
  "Derive the steady-state leak rate from a window's capacity and
  duration. `(capacity / window-seconds)` keeps long-run throughput
  identical to the prior sliding-window scheme."
  ^double [capacity window-seconds]
  (if (and (pos? (long capacity)) (pos? (long window-seconds)))
    (/ (double capacity) (double window-seconds))
    0.0))

(defn normalize-cell
  "Normalize a per-(tier, window) limit cell to
  `{:capacity <long>, :leak-per-sec <double>}`. A bare number is a
  capacity whose leak rate is derived as `capacity / window-seconds`.
  A map may carry an explicit `:leak-per-sec`; if absent it is derived.
  Idempotent: a normalized map round-trips unchanged."
  [cell window-seconds]
  (if (map? cell)
    (let [cap (long (or (:capacity cell) 0))]
      {:capacity     cap
       :leak-per-sec (double (or (:leak-per-sec cell)
                                 (leak-rate-per-sec cap window-seconds)))})
    (let [cap (long cell)]
      {:capacity     cap
       :leak-per-sec (leak-rate-per-sec cap window-seconds)})))

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
  "Indexed pull of the token-bucket entity at `bucket-key-str`. Returns
  `{:db/id ..., :tokens ..., :last-refill-ms ...}` or nil if no entity
  exists at the slot yet."
  [store snap bucket-key-str]
  (let [b (storage/pull store snap [:bucket/key bucket-key-str]
                        [:db/id :bucket/tokens :bucket/last-refill-ms])]
    (when (:db/id b)
      {:db/id          (:db/id b)
       :tokens         (:bucket/tokens b)
       :last-refill-ms (:bucket/last-refill-ms b)})))

(defn- bucket-tx
  "Build the transact payload for writing the new bucket state from a
  resolved spec (`:bucket-key`, `:scope`, `:identity-eid`, `:window`) and
  its (possibly nil) existing entity. Class-scope buckets carry no
  `:bucket/identity`."
  [{:keys [bucket-key scope identity-eid window]} existing new-tokens now-ms-val]
  (if existing
    {:db/id                 (:db/id existing)
     :bucket/tokens         (double new-tokens)
     :bucket/last-refill-ms (long now-ms-val)}
    (cond-> {:bucket/key            bucket-key
             :bucket/window         window
             :bucket/scope          scope
             :bucket/tokens         (double new-tokens)
             :bucket/last-refill-ms (long now-ms-val)}
      (= scope :identity) (assoc :bucket/identity (long identity-eid)))))

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
        bk         (bucket-key identity-eid window)
        existing   (read-bucket store snap bk)
        spec       {:bucket-key bk :scope :identity
                    :identity-eid identity-eid :window window}
        d          (decision (:tokens existing)
                             (:last-refill-ms existing)
                             capacity leak-rate window-ms now-ms-val)]
    (when (:allowed? d)
      (storage/transact!
       store
       [(bucket-tx spec existing (:new-tokens d) now-ms-val)]))
    {:allowed?       (:allowed? d)
     :retry-after-ms (:retry-after-ms d)
     :tokens-after   (:new-tokens d)
     :limit          (long capacity)}))

(defn identity-specs
  "Build per-caller bucket specs for `identity-eid` across `windows`.
  `limits` maps window-keyword → cell (a bare capacity number or a
  `{:capacity :leak-per-sec}` map); a missing entry is capacity 0 (always
  throttles). `windows` is a seq of `{:window <kw>, :seconds <long>}`."
  [identity-eid windows limits]
  (mapv (fn [{:keys [window seconds]}]
          (let [{:keys [capacity leak-per-sec]}
                (normalize-cell (get limits window 0) seconds)]
            {:bucket-key   (bucket-key identity-eid window)
             :scope        :identity
             :identity-eid (long identity-eid)
             :tier         nil
             :window       window
             :window-ms    (* 1000 (long seconds))
             :capacity     capacity
             :leak-per-sec leak-per-sec}))
        windows))

(defn class-specs
  "Build class (back-pressure) bucket specs for `tier` across `windows`.
  `class-limits` maps tier-keyword → {window-keyword → cell}. Returns
  specs only for the windows that have a configured cap for this tier;
  an empty seq when the tier has no class cap at all."
  [tier windows class-limits]
  (let [tier-caps (get class-limits tier)]
    (if (empty? tier-caps)
      []
      (into []
            (keep (fn [{:keys [window seconds]}]
                    (when-let [cell (get tier-caps window)]
                      (let [{:keys [capacity leak-per-sec]}
                            (normalize-cell cell seconds)]
                        {:bucket-key   (class-bucket-key tier window)
                         :scope        :class
                         :identity-eid nil
                         :tier         tier
                         :window       window
                         :window-ms    (* 1000 (long seconds))
                         :capacity     capacity
                         :leak-per-sec leak-per-sec}))))
            windows))))

(defn check!
  "Evaluate a seq of resolved bucket `specs` (see `identity-specs` /
  `class-specs`) against a single snapshot. The request is allowed only
  if EVERY spec allows. On allow, every bucket is upserted with one fewer
  token in a single transaction. On any deny, NOTHING is written (no
  bucket is penalized for another's denial) and the most-restrictive
  outcome is returned, tagged with the denying `:scope`.

    allow → {:allowed? true,  :retry-after-ms 0}
    deny  → {:allowed? false, :retry-after-ms <long>, :limit <long>,
             :scope (:identity | :class)}"
  [store specs ^java.util.Date now]
  (let [now-ms-val (now-ms now)
        snap       (storage/snapshot store)
        read-pass
        (mapv (fn [{:keys [window-ms capacity leak-per-sec bucket-key] :as spec}]
                (let [existing (read-bucket store snap bucket-key)
                      d        (decision (:tokens existing)
                                         (:last-refill-ms existing)
                                         capacity leak-per-sec window-ms now-ms-val)]
                  (assoc spec
                         :existing       existing
                         :decision       d
                         :would-allow?   (:allowed? d)
                         :retry-after-ms (:retry-after-ms d))))
              specs)]
    (if-let [denials (seq (remove :would-allow? read-pass))]
      (let [worst (apply max-key :retry-after-ms denials)]
        {:allowed?       false
         :retry-after-ms (:retry-after-ms worst)
         :limit          (:capacity worst)
         :scope          (:scope worst)})
      (do
        (when (seq read-pass)
          (storage/transact!
           store
           (mapv (fn [{:keys [existing decision] :as spec}]
                   (bucket-tx spec existing (:new-tokens decision) now-ms-val))
                 read-pass)))
        {:allowed? true
         :retry-after-ms 0}))))

(defn check-many
  "Backward-compatible wrapper: check only the per-caller buckets for one
  identity across `windows` under `limits`. Delegates to `check!`.

  `windows` is a seq of `{:window <keyword>, :seconds <long>}`. `limits`
  maps window-keyword → cell (bare capacity or `{:capacity :leak-per-sec}`);
  a missing or zero entry always throttles."
  [store identity-eid windows limits ^java.util.Date now]
  (check! store (identity-specs identity-eid windows limits) now))
