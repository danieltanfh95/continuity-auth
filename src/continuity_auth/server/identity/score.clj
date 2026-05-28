(ns continuity-auth.server.identity.score
  "Spaced-continuity trust weighting.

  Trust is not a running sum of per-verify deltas; it is a *memory weight*
  recomputed at read time from a small per-identity sketch, in the spirit of
  the spacing effect (cf. `agent-lineage-evolution` succession
  `domain/weight.clj`): a key seen long ago and again recently is more
  load-bearing than one seen frequently in a short burst. Spaced recurrence
  dominates raw frequency, which makes earned trust expensive to farm.

  The sketch (stored on the identity, updated O(1) per verify):
    :clean-count       long    — pubkey-matched verifies (continuity signal)
    :spacing           double  — Σ ln(1+gap_days) over returns after a dormant gap
    :created-at-ms     long    — first-seen epoch ms (span anchor)
    :last-clean-at-ms  long    — last reinforcing verify (decay + gap detection)
    :violation-count   long    — axis-mismatch / anomaly observations

  Formula (constants in `default-scoring`, overridable via config `:scoring`):

    freq   = min(√clean-count, freq-cap)
    span   = (1 + ln(1 + span-days))^span-exponent
    gap    = 1 + spacing
    within = (span-days < span-min-days) ? within-burst-penalty : 1.0
    decay  = 0.5 ^ (idle-days / decay-half-life-days)
    base   = freq · span · gap · within · decay
    earned = 1 − 2^(−base / squash-scale)
    vrate  = violation-count / (violation-count + clean-count)
    score  = clamp01( (floor + (1−floor)·earned) · (1 − violation-k·vrate) )

  Banned/penalized are reached via the violation term, not absence of
  history: a fresh, clean key lands at the score floor (≈ :anonymous), never
  :banned.

  `base-weight`, `score-of`, `spacing-credit` are pure. This namespace also
  hosts the pure axis-classification used by the merge path
  (`classify-axis-match`, `axes-vs-cluster`, `axis-mismatch->reasons`).")

(def ^:const score-min 0.0)
(def ^:const score-max 1.0)

(def default-scoring
  "Calibrated weight constants. See `.plans/spaced-continuity-trust-model.md`
  §Calibration record for the scenario table these were tuned against."
  {:freq-cap             4.0     ; raw volume saturates fast (anti-farming)
   :span-exponent        1.5     ; calendar-longevity curve
   :within-burst-penalty 0.5     ; halve a single-burst (cram) identity
   :span-min-days        1.0     ; below this span, treat as a burst
   :gap-min-days         0.25    ; 6h: shorter gaps accrue no spacing
   :decay-half-life-days 30.0    ; idle trust halves in a month
   :squash-scale         60.0    ; weight→[0,1] squash scale (W0)
   :score-floor          0.1     ; fresh clean key floor (anonymous band)
   :violation-k          1.0})   ; violation-rate erosion strength

(defn clamp
  "Clamp `score` to [score-min, score-max]."
  ^double [score]
  (-> score double (max score-min) (min score-max)))

(defn- ms->days ^double [^long ms]
  (/ (double ms) 86400000.0))

(defn spacing-credit
  "Increment to `:spacing` for a clean verify arriving `now-ms` after the
  prior clean verify at `last-clean-ms`. Returns 0.0 when the gap is at or
  below `:gap-min-days` (rapid-fire requests accrue no spacing)."
  ^double [^long last-clean-ms ^long now-ms cfg]
  (let [gap-days (ms->days (- now-ms last-clean-ms))]
    (if (> gap-days (double (:gap-min-days cfg)))
      (Math/log (+ 1.0 gap-days))
      0.0)))

(defn base-weight
  "Pure spacing-effect base weight (pre-squash) from the identity sketch at
  `now-ms`. Higher = more trusted."
  ^double [{:keys [clean-count spacing created-at-ms last-clean-at-ms]} ^long now-ms cfg]
  (let [n         (double (or clean-count 0))
        sp        (double (or spacing 0.0))
        freq      (Math/min (Math/sqrt n) (double (:freq-cap cfg)))
        span-days (Math/max 0.0 (ms->days (- now-ms (long (or created-at-ms now-ms)))))
        span-term (Math/pow (+ 1.0 (Math/log (+ 1.0 span-days)))
                            (double (:span-exponent cfg)))
        gap-term  (+ 1.0 sp)
        within    (if (< span-days (double (:span-min-days cfg)))
                    (double (:within-burst-penalty cfg))
                    1.0)
        idle-days (Math/max 0.0 (ms->days (- now-ms (long (or last-clean-at-ms now-ms)))))
        decay     (Math/pow 0.5 (/ idle-days (double (:decay-half-life-days cfg))))]
    (* freq span-term gap-term within decay)))

(defn score-of
  "Derived trust score in [0.0, 1.0] from the identity sketch at `now-ms`.
  Consumed by the tier projector."
  ^double [{:keys [clean-count violation-count] :as sketch} ^long now-ms cfg]
  (let [b      (base-weight sketch now-ms cfg)
        w0     (double (:squash-scale cfg))
        floor  (double (:score-floor cfg))
        earned (- 1.0 (Math/pow 2.0 (- (/ b w0))))
        n      (double (or clean-count 0))
        v      (double (or violation-count 0))
        denom  (+ n v)
        vrate  (if (pos? denom) (/ v denom) 0.0)
        s      (* (+ floor (* (- 1.0 floor) earned))
                  (- 1.0 (* (double (:violation-k cfg)) vrate)))]
    (clamp s)))

(defn sketch-update
  "Apply one clean (pubkey-matched) verify at `now-ms` to the identity
  sketch, O(1). `violation?` is true when the event also carries an
  axis mismatch (ip/fp), which feeds the violation-rate erosion term but
  does NOT stop the verify from reinforcing continuity. Returns the
  updated sketch (epoch-ms fields); `:created-at-ms` is left untouched.

    clean-count       += 1
    spacing           += spacing-credit(last-clean-at, now)   ; 0 if gap ≤ gap-min
    last-clean-at-ms  =  now-ms
    violation-count   += (violation? 1 0)

  Pure: the caller transacts the resulting fields."
  [{:keys [clean-count spacing last-clean-at-ms violation-count] :as sketch}
   ^long now-ms violation? cfg]
  (let [credit (spacing-credit (long (or last-clean-at-ms now-ms)) now-ms cfg)]
    (assoc sketch
           :clean-count      (inc (long (or clean-count 0)))
           :spacing          (+ (double (or spacing 0.0)) credit)
           :last-clean-at-ms now-ms
           :violation-count  (+ (long (or violation-count 0)) (if violation? 1 0)))))

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
