(ns continuity-auth.server.ratelimit.tier
  "Tier projection from (score, host-linked?, ever-tracked?) and tier→limit
  lookup.

  Tier and limits are pure functions of the identity's current state — we
  compute them at read time rather than storing them. This makes tier
  transitions continuous and reversible: a penalized identity that decays
  back above the threshold automatically returns to :tracked.

  Defaults match the ontology §6 table; both thresholds and limits are
  configurable via the :scoring and :ratelimit maps of config.edn.")

(def default-thresholds
  "Defaults projected onto (score, host-linked?, ever-tracked?). See
  ontology §6."
  {:tracked-from-score              0.3
   :tracked-from-host-linked-score  0.5
   :banned-from-score               0.05})

(def default-limits
  "Per-tier limits for each named window. The most restrictive limit
  across windows is the binding constraint at /verify time."
  {:anonymous  {:1m 1   :5m 5    :1d 100}
   :tracked    {:1m 30  :5m 120  :1d 5000}
   :penalized  {:1m 0   :5m 1    :1d 20}
   :banned     {:1m 0   :5m 0    :1d 1}})

(defn project
  "Compute the tier keyword from `(score, host-linked?, ever-tracked?)`
  using `thresholds`. Returns one of :anonymous, :tracked, :penalized,
  :banned.

  Decision order (mutually exclusive):
    score < :banned-from-score                     → :banned
    score < :tracked-from-score AND ever-tracked?  → :penalized
    host-linked?  AND score >= :tracked-from-host-linked-score
                                                   → :tracked
    not host-linked? AND score >= :tracked-from-score
                                                   → :tracked
    otherwise                                      → :anonymous"
  ([identity-info]
   (project identity-info default-thresholds))
  ([{:keys [score host-linked? ever-tracked?]} thresholds]
   (let [s   (double (or score 0.0))
         hl? (boolean host-linked?)
         et? (boolean ever-tracked?)
         t   thresholds]
     (cond
       (< s (:banned-from-score t))
       :banned

       (and et? (< s (:tracked-from-score t)))
       :penalized

       (and hl? (>= s (:tracked-from-host-linked-score t)))
       :tracked

       (and (not hl?) (>= s (:tracked-from-score t)))
       :tracked

       :else :anonymous))))

(defn limits-for
  "Return the limits map for a tier under `all-limits`."
  ([tier]
   (limits-for tier default-limits))
  ([tier all-limits]
   (get all-limits tier (:anonymous all-limits))))

(defn limit-for
  "Return the integer limit for `(tier, window)`."
  ^long
  ([tier window]
   (limit-for tier window default-limits))
  ([tier window all-limits]
   (long (get (limits-for tier all-limits) window 0))))
