(ns continuity-auth.server.ratelimit.window
  "Sliding-window-counter rate limiter.

  Algorithm (per identity, per window-size W):
    - Maintain at most two buckets at any time: the *current* bucket
      starting at floor(now / W) * W, and the *previous* bucket
      starting W earlier.
    - The approximated count over the last W seconds is:
        approx = current.count
               + previous.count * (W - elapsed_in_current) / W
    - On each request, compute approx; if approx + 1 > limit, throttle;
      otherwise increment the current bucket.

  Properties:
    - O(1) per check (two indexed lookups + at most one transact).
    - Bounded error vs. a precise sliding-log oracle (worst case ~0.3%
      at the bucket boundary; smaller as elapsed approaches W).
    - Concurrency: the read-then-write is not strictly atomic. Under
      high concurrency we may let through (concurrent_writers - 1)
      extra requests above the limit. For our threat model
      (opportunistic abuse) this is acceptable. If exactness is later
      required, a Datalevin transact-fn can serialize the
      check-and-increment.

  All times are `java.util.Date`; window-size is supplied as a seconds
  count alongside its keyword name."
  (:require
   [continuity-auth.server.storage.protocol :as storage]))

(defn- now-ms ^long [^java.util.Date d] (.getTime d))

(defn align-to-window
  "Return the java.util.Date marking the start of the W-second-aligned
  bucket containing `t`."
  ^java.util.Date [^java.util.Date t window-seconds]
  (let [t-ms     (now-ms t)
        w-ms     (* 1000 (long window-seconds))
        aligned  (* w-ms (quot t-ms w-ms))]
    (java.util.Date. (long aligned))))

(defn elapsed-in-current-window
  "Return the elapsed seconds (a double in [0, window-seconds)) since
  the current bucket started."
  ^double [^java.util.Date now ^java.util.Date current-start]
  (/ (double (- (now-ms now) (now-ms current-start)))
     1000.0))

(defn weighted-approx-count
  "Compute the sliding-window approximation."
  ^double [current-count previous-count elapsed-seconds window-seconds]
  (let [w           (double window-seconds)
        weight-prev (max 0.0 (- 1.0 (/ (double elapsed-seconds) w)))]
    (+ (double current-count)
       (* (double previous-count) weight-prev))))

(defn- find-bucket
  "Return the bucket for (identity, window, start) or nil."
  [store snap identity-eid window start-date]
  (let [buckets (storage/find-buckets store snap identity-eid window)]
    (some (fn [b]
            (when (and (some? (:bucket/start b))
                       (= (now-ms start-date)
                          (now-ms (:bucket/start b))))
              b))
          buckets)))

(defn check-and-increment!
  "Check if a new request would exceed `limit` for `window` and, if not,
  increment the current bucket. Returns:

    {:allowed? true  :approx-count <float> :limit <long> :remaining <long>}
    {:allowed? false :approx-count <float> :limit <long>
     :retry-after-ms <long>}

  When `:allowed? true`, the bucket has been incremented. When `false`,
  no write occurs.

  `window` is a keyword (e.g. :1m); `window-seconds` is its size in
  seconds (e.g. 60). `limit` is the maximum number of requests within
  the trailing window-seconds period; a limit of 0 always throttles.
  Time is `now` (`java.util.Date`)."
  [store identity-eid window window-seconds limit ^java.util.Date now]
  ;; Note: `limit` and `window-seconds` are intentionally unhinted to keep
  ;; the arglist under the 4-primitive limit Clojure imposes on primitive-
  ;; tagged fns. They are coerced to long where needed below.
  (let [snap          (storage/snapshot store)
        current-start (align-to-window now window-seconds)
        prev-start    (java.util.Date. (- (now-ms current-start)
                                          (* 1000 (long window-seconds))))
        current       (find-bucket store snap identity-eid window current-start)
        previous      (find-bucket store snap identity-eid window prev-start)
        current-cnt   (or (:bucket/count current)  0)
        prev-cnt      (or (:bucket/count previous) 0)
        elapsed       (elapsed-in-current-window now current-start)
        approx        (weighted-approx-count current-cnt prev-cnt elapsed window-seconds)
        retry-ms      (max 0 (- (* 1000 (long window-seconds))
                                (long (Math/round (* 1000.0 elapsed)))))]
    (cond
      ;; A limit of zero or below means: never allow.
      (<= (long limit) 0)
      {:allowed? false :approx-count approx :limit limit :retry-after-ms retry-ms}

      (>= (+ approx 1.0) (double (inc (long limit))))
      {:allowed? false :approx-count approx :limit limit :retry-after-ms retry-ms}

      :else
      (let [tx (if current
                 [{:db/id        (:db/id current)
                   :bucket/count (inc current-cnt)}]
                 [{:bucket/identity identity-eid
                   :bucket/window   window
                   :bucket/start    current-start
                   :bucket/count    1}])]
        (storage/transact! store tx)
        {:allowed?      true
         :approx-count  (inc approx)
         :limit         limit
         :remaining     (max 0 (- (long limit) (long (Math/ceil (inc approx)))))}))))

(defn check-many
  "Check multiple windows. Returns the most-restrictive outcome — the
  request is allowed only if ALL windows allow. If any throttles, that
  decision is returned with the maximum `retry-after-ms`. When all
  allow, increments are performed for each window.

  `windows` is a seq of `{:window <keyword>, :seconds <long>}`. `limits`
  is a map of window-keyword to integer limit, typically produced by
  `tier/limits-for`; a missing entry is treated as 0 (always throttle)."
  [store identity-eid windows limits ^java.util.Date now]
  ;; Pre-pass: read-only check across all windows. We make this a
  ;; two-phase pass to avoid partial increments that wouldn't be
  ;; matched by a denial-of-service rollback. We DO leave a small
  ;; race window between the read-pass and the write-pass; acceptable
  ;; per the doc string of `check-and-increment!`.
  (let [snap (storage/snapshot store)
        read-pass
        (mapv (fn [{:keys [window seconds] :as w}]
                (let [limit         (get limits window 0)
                      current-start (align-to-window now seconds)
                      prev-start    (java.util.Date. (- (now-ms current-start)
                                                        (* 1000 (long seconds))))
                      current       (find-bucket store snap identity-eid window current-start)
                      previous      (find-bucket store snap identity-eid window prev-start)
                      cc (or (:bucket/count current) 0)
                      pc (or (:bucket/count previous) 0)
                      e  (elapsed-in-current-window now current-start)
                      a  (weighted-approx-count cc pc e seconds)
                      retry-ms (max 0 (- (* 1000 (long seconds))
                                         (long (Math/round (* 1000.0 e)))))]
                  (assoc w
                         :limit limit
                         :approx-count a
                         :current current
                         :current-start current-start
                         :retry-after-ms retry-ms
                         :would-allow? (and (pos? limit)
                                             (< (+ a 1.0) (double (inc limit)))))))
              windows)]
    (if-let [denials (seq (filter (complement :would-allow?) read-pass))]
      (let [{:keys [approx-count limit retry-after-ms]}
            (apply max-key :retry-after-ms denials)]
        {:allowed?       false
         :approx-count   approx-count
         :limit          limit
         :retry-after-ms retry-after-ms})
      (do
        (storage/transact!
         store
         (vec (for [{:keys [window current current-start]} read-pass]
                (if current
                  {:db/id        (:db/id current)
                   :bucket/count (inc (or (:bucket/count current) 0))}
                  {:bucket/identity identity-eid
                   :bucket/window   window
                   :bucket/start    current-start
                   :bucket/count    1}))))
        {:allowed? true}))))
