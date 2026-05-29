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
    otherwise                                      → :anonymous

  IP-bounce hard floor (v7): if `:ip-bounce-strikes` (the read-time-decayed
  strike load) is at or above `:tier-floor-strikes`, the tier is capped at
  :penalized regardless of the computed tier (a :banned result still stands).
  This is the undilutable backstop — an aged, high-score identity cannot earn
  its way out of an active IP-bounce penalty, which the multiplicative
  `bounce-pen` score term alone would let it do. Both keys arrive in the
  info map; the cutoff is sourced from the `:scoring` config. When
  `:tier-floor-strikes` is absent the floor never triggers (pre-v7 callers)."
  ([identity-info]
   (project identity-info default-thresholds))
  ([{:keys [score host-linked? ever-tracked? ip-bounce-strikes tier-floor-strikes]}
    thresholds]
   (let [s       (double (or score 0.0))
         hl?     (boolean host-linked?)
         et?     (boolean ever-tracked?)
         t       thresholds
         base    (cond
                   (< s (:banned-from-score t))
                   :banned

                   (and et? (< s (:tracked-from-score t)))
                   :penalized

                   (and hl? (>= s (:tracked-from-host-linked-score t)))
                   :tracked

                   (and (not hl?) (>= s (:tracked-from-score t)))
                   :tracked

                   :else :anonymous)
         strikes (double (or ip-bounce-strikes 0.0))
         floor-n (if tier-floor-strikes (double tier-floor-strikes)
                     Double/POSITIVE_INFINITY)]
     (if (and (>= strikes floor-n) (not= base :banned))
       :penalized
       base))))

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

(def default-priority-weights
  "Per-tier scheduling weight surfaced in the verify response as
  `:priority_weight`. Values mirror the `:1m` capacity ratio so a host
  doing weighted fair queuing matches the relative service rates this
  service grants. The numbers are advisory: continuity-auth itself does
  not enforce priority; the host backend may consult them or ignore them."
  {:anonymous  1.0
   :tracked    30.0
   :penalized  0.0
   :banned     0.0})

(defn priority-weight
  "Return the numeric scheduling weight for `tier` under `weights` (or
  the defaults). Tiers absent from the map default to 1.0 (the
  anonymous-tier weight) rather than 0, on the grounds that an unknown
  tier should not be treated as banned."
  ^double
  ([tier]
   (priority-weight tier default-priority-weights))
  ([tier weights]
   (double (get weights tier 1.0))))
