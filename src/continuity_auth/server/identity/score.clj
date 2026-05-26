(ns continuity-auth.server.identity.score
  "Pure score-delta calculus.

  The trust score is a single number in [0.0, 1.0] per identity. Each
  observation contributes a delta; the score is the clamped sum. Decay
  is applied lazily (on read) by the tier projector — this namespace
  only produces deltas for discrete events.

  Defaults match the table in `docs/ontology.md` §6. They are
  configurable at startup via the :scoring map in config.edn.")

(def default-deltas
  "Default magnitudes for each kind of trust event. Negative magnitudes
  reduce trust; positive magnitudes increase it."
  {:pubkey-match           +0.05
   :host-link-committed    +0.30
   :ip-mismatch            -0.02
   :fp-mismatch            -0.05
   :all-mismatch           -0.10
   :anomaly                -0.05
   :erasure-requested       0.0
   :admin-reset             0.0
   :bootstrap               0.0
   :decay                   0.0})    ; computed separately from decay-toward

(def ^:const score-min 0.0)
(def ^:const score-max 1.0)
(def ^:const score-neutral 0.5)
(def ^:const default-decay-toward score-neutral)
(def ^:const default-decay-rate-per-day 0.01)

(defn clamp
  "Clamp `score` to [score-min, score-max]."
  ^double [score]
  (-> score double (max score-min) (min score-max)))

(defn axis-mismatch->reasons
  "Map a set of mismatched-axis keywords to a sequence of trust-event
  reason keywords. The empty set yields the empty sequence (an exact
  match contributes no penalty)."
  [axes]
  (let [axes (set axes)]
    (cond
      (empty? axes)                 []
      (= axes #{:ip})               [:ip-mismatch]
      (= axes #{:fp})               [:fp-mismatch]
      (= axes #{:ip :fp})           [:all-mismatch]
      :else                         (mapv #(keyword (str (name %) "-mismatch")) axes))))

(defn delta-for-reasons
  "Sum of deltas for the given trust-event reasons under `deltas`."
  ^double [deltas reasons]
  (double (reduce + 0.0 (map #(get deltas % 0.0) reasons))))

(defn apply-delta
  "Apply `delta` to `current-score`, clamped."
  ^double [current-score delta]
  (clamp (+ (double current-score) (double delta))))

(defn decay
  "Lazily compute the decay-adjusted score given `current-score`,
  `seconds-since-last-event`, and decay parameters. Decay drifts the
  score toward `decay-toward` at `rate-per-day`. Returns the decayed
  score, clamped."
  ^double [current-score seconds-since-last-event
           {:keys [decay-toward decay-rate-per-day]
            :or {decay-toward       default-decay-toward
                 decay-rate-per-day default-decay-rate-per-day}}]
  (let [days        (/ (double seconds-since-last-event) 86400.0)
        max-step    (* days (double decay-rate-per-day))
        gap         (- (double decay-toward) (double current-score))
        step        (if (>= (Math/abs gap) max-step)
                      (* (Math/signum gap) max-step)
                      gap)]
    (clamp (+ (double current-score) step))))

(defn classify-axis-match
  "Classify the relationship between an incoming tuple and the closest
  existing tuple in the same pubkey-anchored cluster.

  Returns a map:
    :exact?         — true iff incoming.ip = existing.ip-hash AND
                                incoming.fp = existing.fp
    :mismatch-axes  — set of axes that differ (subset of #{:ip :fp})

  When the incoming tuple is the FIRST in its cluster (no existing
  tuples), the caller should treat that as :all-mismatch (a brand-new
  tuple for an existing pubkey is a strong signal, e.g., the user moved
  device or network).

  This function does not consider :pubkey — the pubkey axis is always
  'matched' in the verify path (otherwise we would not be on the verify
  path).

  Note: `(:ip incoming)` is the IP-hash (HMAC-SHA256 hex) — see
  `continuity-auth.server.crypto.ip-hmac`. Equality is preserved under
  a fixed keystore key, so cluster grouping is unchanged."
  [incoming closest]
  (let [ip-same? (= (:ip incoming)        (:tuple/ip-hash closest))
        fp-same? (java.security.MessageDigest/isEqual
                  ^bytes (:fp-digest incoming)
                  ^bytes (:tuple/fp-digest closest))
        mismatch (cond-> #{}
                   (not ip-same?) (conj :ip)
                   (not fp-same?) (conj :fp))]
    {:exact? (empty? mismatch)
     :mismatch-axes mismatch}))

(defn axes-vs-cluster
  "Walk `cluster-tuples` and return the smallest mismatch-axes set
  achievable against any single tuple in the cluster. The 'closest'
  tuple is the one minimizing the size of the mismatch set; ties broken
  by recency (most recently seen wins).

  If the cluster is empty, returns `#{:ip :fp}` (all-mismatch)."
  [incoming cluster-tuples]
  (if (empty? cluster-tuples)
    {:closest nil :mismatch-axes #{:ip :fp}}
    (let [scored (->> cluster-tuples
                      (map (fn [t]
                             (let [{:keys [mismatch-axes]}
                                   (classify-axis-match incoming t)]
                               {:tuple t
                                :mismatch-axes mismatch-axes
                                :size (count mismatch-axes)
                                :last-seen (or (some-> (:tuple/last-seen t)
                                                       .getTime)
                                               0)})))
                      (sort-by (juxt :size #(- (:last-seen %)))))
          best (first scored)]
      {:closest       (:tuple best)
       :mismatch-axes (:mismatch-axes best)})))
