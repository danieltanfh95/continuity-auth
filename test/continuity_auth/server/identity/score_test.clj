(ns continuity-auth.server.identity.score-test
  "Pure spaced-continuity weight tests. Trust is a memory weight recomputed
  from an O(1) sketch: spaced recurrence dominates massed frequency, fresh
  clean keys land at the score floor (≈ :anonymous), and :banned is reached
  only via the violation term — never absence of history."
  (:require
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [continuity-auth.server.identity.score :as score]))

(def ^:private cfg score/default-scoring)
(def ^:private DAY 86400000)

(defn- close? [a b]
  (< (Math/abs (- (double a) (double b))) 1e-9))

(deftest clamp-keeps-range
  (is (= 0.0 (score/clamp -0.5)))
  (is (= 1.0 (score/clamp 1.5)))
  (is (= 0.5 (score/clamp 0.5))))

;; -- spacing-credit --------------------------------------------------------

(deftest spacing-credit-rewards-gaps-above-min
  (testing "a gap longer than gap-min accrues ln(1+gap_days)"
    (is (close? (Math/log (+ 1.0 2.0))                       ; 2-day gap
                (score/spacing-credit 0 (* 2 DAY) cfg))))
  (testing "a gap at or below gap-min (6h) accrues nothing — rapid-fire"
    (is (= 0.0 (score/spacing-credit 0 (long (* 0.25 DAY)) cfg)))
    (is (= 0.0 (score/spacing-credit 0 (long (* 0.1 DAY)) cfg)))
    (is (= 0.0 (score/spacing-credit 0 0 cfg))))
  (testing "longer gaps accrue strictly more credit"
    (is (< (score/spacing-credit 0 (* 1 DAY) cfg)
           (score/spacing-credit 0 (* 30 DAY) cfg)))))

;; -- base-weight / score-of ------------------------------------------------

(deftest fresh-clean-key-lands-at-floor
  (testing "clean-count 0 (unproven) derives exactly the score floor"
    (is (close? (:score-floor cfg)
                (score/score-of {:clean-count 0 :spacing 0.0 :violation-count 0
                                 :created-at-ms 0 :last-clean-at-ms 0}
                                0 cfg))))
  (testing "a single bootstrap verify sits just above the floor, in the anonymous band"
    (let [s (score/score-of {:clean-count 1 :spacing 0.0 :violation-count 0
                             :created-at-ms 0 :last-clean-at-ms 0}
                            0 cfg)]
      (is (< (:score-floor cfg) s 0.2)))))

(deftest spaced-beats-massed-at-equal-count
  (testing "at identical clean-count, span and idle, spaced recurrence scores higher"
    (let [now    (* 30 DAY)
          base   {:clean-count 12 :violation-count 0
                  :created-at-ms 0 :last-clean-at-ms now}
          massed (score/score-of (assoc base :spacing 0.0) now cfg)
          spaced (score/score-of (assoc base :spacing (* 11 (Math/log 4))) now cfg)]
      (is (> spaced massed)
          "spacing (1+Σln(1+gap)) lifts the weight above pure frequency"))))

(deftest bot-cram-stays-anonymous
  (testing "thousands of massed hits in an hour cannot buy out of the anonymous band"
    (let [s (score/score-of {:clean-count 5000 :spacing 0.0 :violation-count 0
                             :created-at-ms 0 :last-clean-at-ms (* 3600 1000)}
                            (* 3600 1000) cfg)]
      (is (< s 0.3) "frequency saturates at √-cap; no span, no spacing ⇒ < tracked"))))

(deftest sustained-spaced-reaches-tracked
  (testing "a daily-clean key over two weeks crosses the tracked threshold"
    (let [s (score/score-of {:clean-count 14 :spacing (* 13 (Math/log 2)) :violation-count 0
                             :created-at-ms 0 :last-clean-at-ms (* 14 DAY)}
                            (* 14 DAY) cfg)]
      (is (>= s 0.3)))))

(deftest idle-decays-but-does-not-collapse
  (testing "an established key idle for 60 days decays yet stays above tracked"
    (let [sketch {:clean-count 14 :spacing (* 13 (Math/log 2)) :violation-count 0
                  :created-at-ms 0 :last-clean-at-ms (* 14 DAY)}
          active (score/score-of sketch (* 14 DAY) cfg)
          idle   (score/score-of sketch (* 74 DAY) cfg)]   ; +60 days idle
      (is (< idle active) "idle decay strictly lowers the score")
      (is (>= idle 0.3)  "two half-lives of decay still leaves it tracked"))))

(deftest violations-erode-via-rate
  (testing "violation-rate scales the score down; all-violations approaches banned"
    (let [clean {:clean-count 14 :spacing (* 13 (Math/log 2)) :violation-count 0
                 :created-at-ms 0 :last-clean-at-ms (* 14 DAY)}
          half  (assoc clean :violation-count 14)            ; vrate 0.5
          s-clean (score/score-of clean (* 14 DAY) cfg)
          s-half  (score/score-of half  (* 14 DAY) cfg)]
      (is (close? (* 0.5 s-clean) s-half)
          "vrate 0.5 halves the (floor+earned) product")
      (is (< s-half s-clean)))))

;; -- sketch-update ---------------------------------------------------------

(deftest sketch-update-clean-reinforces
  (testing "a clean verify after a spaced gap increments count and accrues spacing"
    (let [s0 {:clean-count 3 :spacing 0.5 :violation-count 1
              :created-at-ms 0 :last-clean-at-ms 0}
          s1 (score/sketch-update s0 (* 2 DAY) #{} "ipA" cfg)]
      (is (= 4 (:clean-count s1)))
      (is (close? (+ 0.5 (Math/log 3.0)) (:spacing s1)) "spacing += ln(1+2)")
      (is (= (* 2 DAY) (:last-clean-at-ms s1)))
      (is (= 1 (:violation-count s1)) "no violation on a clean exact verify")
      (is (= 0 (:created-at-ms s1)) "span anchor untouched"))))

(deftest sketch-update-violation-increments-and-still-reinforces
  (testing "a mismatch verify counts as both continuity (clean) and a violation"
    (let [s0 {:clean-count 3 :spacing 0.5 :violation-count 1
              :created-at-ms 0 :last-clean-at-ms 0}
          s1 (score/sketch-update s0 (* 2 DAY) #{:ip} "ipA" cfg)]
      (is (= 4 (:clean-count s1)) "still a pubkey-matched reinforcement")
      (is (= 2 (:violation-count s1)) "violation-count bumped"))))

(deftest sketch-update-rapid-fire-accrues-no-spacing
  (testing "a sub-gap-min return increments count but not spacing"
    (let [s0 {:clean-count 3 :spacing 0.5 :violation-count 0
              :created-at-ms 0 :last-clean-at-ms 0}
          s1 (score/sketch-update s0 (long (* 0.1 DAY)) #{} "ipA" cfg)]
      (is (= 4 (:clean-count s1)))
      (is (close? 0.5 (:spacing s1)) "no spacing credit for rapid-fire"))))

;; -- IP-bounce velocity + durable strikes (v7) ----------------------------

(defn- run-events
  "Fold a sequence of [now-ms ip-hash mismatch-axes] events through
  sketch-update, starting from `s0`."
  [s0 events]
  (reduce (fn [s [t ip axes]] (score/sketch-update s t axes ip cfg)) s0 events))

(deftest legacy-sketch-has-no-bounce-penalty
  (testing "a pre-v7 sketch (no IP fields) derives the same score as before — bpen = 1"
    (let [sk {:clean-count 50 :spacing 5.0 :violation-count 0
              :created-at-ms 0 :last-clean-at-ms (* 30 DAY)}
          now (* 30 DAY)]
      (is (= 0.0 (score/strikes-now sk now cfg)) "no strikes, no anchor ⇒ 0")
      ;; bpen factor is exactly 1.0 when strikes-now is 0, so score is the
      ;; pure pre-v7 (floor+earned)·(1−vrate) value.
      (is (close? (let [b (score/base-weight sk now cfg)
                        earned (- 1.0 (Math/pow 2.0 (- (/ b (:squash-scale cfg)))))]
                    (+ (:score-floor cfg) (* (- 1.0 (:score-floor cfg)) earned)))
                  (score/score-of sk now cfg))))))

(deftest seeding-last-ip-counts-no-change
  (testing "the first stable-fp verify only records last-ip-hash; no churn, no change"
    (let [s0 {:clean-count 0 :spacing 0.0 :violation-count 0
              :created-at-ms 0 :last-clean-at-ms 0}
          s1 (score/sketch-update s0 0 #{} "ipA" cfg)]
      (is (= "ipA" (:last-ip-hash s1)))
      (is (= 0 (:last-ip-change-at-ms s1)))
      (is (= 0.0 (:ip-churn s1)) "seeding accrues no velocity")
      (is (= 0 (:ip-bounce-strikes s1))))))

(deftest fp-mismatch-does-not-accrue-churn
  (testing "a device+network change (fp unstable) is the :fp signal, not IP-bounce"
    (let [s0 (score/sketch-update {:clean-count 0 :spacing 0.0 :violation-count 0
                                   :created-at-ms 0 :last-clean-at-ms 0}
                                  0 #{} "ipA" cfg)
          ;; 200 changes every 60s but EACH carries an fp mismatch
          sN (run-events s0 (for [i (range 1 201)] [(* i 60000) (str "ip" i) #{:ip :fp}]))]
      (is (close? 0.0 (:ip-churn sN)) "fp-gate blocks churn accrual")
      (is (= 0 (:ip-bounce-strikes sN))))))

(deftest slow-roamer-never-strikes
  (testing "a legit roamer (IP change every 30 min, ~2/hr) stays far below threshold"
    (let [s0 (score/sketch-update {:clean-count 0 :spacing 0.0 :violation-count 0
                                   :created-at-ms 0 :last-clean-at-ms 0}
                                  0 #{} "ipA" cfg)
          ;; 48 changes over 24h, all stable-fp IP mismatches
          sN (run-events s0 (for [i (range 1 49)] [(* i 1800000) (str "ip" i) #{:ip}]))]
      (is (< (:ip-churn sN) (:churn-strike-threshold cfg)) "equilibrium churn well under threshold")
      (is (= 0 (:ip-bounce-strikes sN))))))

(deftest rapid-bouncer-accrues-strike
  (testing "fast IP rotation under a stable fp crosses the threshold and strikes"
    (let [s0 (score/sketch-update {:clean-count 0 :spacing 0.0 :violation-count 0
                                   :created-at-ms 0 :last-clean-at-ms 0}
                                  0 #{} "ipA" cfg)
          ;; 120 changes every 60s ≈ 2h of bouncing (rate 60/hr → churn ≫ 60)
          sN (run-events s0 (for [i (range 1 121)] [(* i 60000) (str "ip" i) #{:ip}]))]
      (is (>= (:ip-churn sN) (:churn-strike-threshold cfg)) "churn crosses threshold")
      (is (>= (:ip-bounce-strikes sN) 1) "at least one durable strike"))))

(deftest strike-accrual-respects-cooldown
  (testing "one continuous bouncing session yields ≤ 1 strike per cooldown window"
    (let [s0 (score/sketch-update {:clean-count 0 :spacing 0.0 :violation-count 0
                                   :created-at-ms 0 :last-clean-at-ms 0}
                                  0 #{} "ipA" cfg)
          ;; 5h of relentless 60s-interval bouncing; cooldown is 6h → exactly 1 strike
          sN (run-events s0 (for [i (range 1 301)] [(* i 60000) (str "ip" i) #{:ip}]))]
      (is (= 1 (:ip-bounce-strikes sN))
          "cooldown gates a single 5h (< 6h) session to one strike"))))

(deftest strikes-decay-on-slow-half-life
  (testing "strikes decay read-side; 2 fresh strikes clear the floor after ~1 half-life idle"
    (let [base {:ip-bounce-strikes 2}]
      (is (close? 2.0 (score/strikes-now (assoc base :last-strike-at-ms 0) 0 cfg))
          "no idle ⇒ full strike load")
      (is (close? 1.0 (score/strikes-now (assoc base :last-strike-at-ms 0)
                                         (* 14 DAY) cfg))
          "one 14-day half-life halves the load")
      (is (< (score/strikes-now (assoc base :last-strike-at-ms 0) (* 14 DAY) cfg)
             (:tier-floor-strikes cfg))
          "after a half-life, decayed strikes drop below the tier-floor"))))

(deftest bounce-pen-erodes-aged-high-trust-score
  (testing "fresh strikes multiplicatively erode even an aged, high-earned score"
    (let [aged {:clean-count 200 :spacing 20.0 :violation-count 0
                :created-at-ms 0 :last-clean-at-ms (* 60 DAY)}
          now  (* 60 DAY)
          clean   (score/score-of aged now cfg)
          struck  (score/score-of (assoc aged :ip-bounce-strikes 2
                                         :last-strike-at-ms now) now cfg)]
      (is (> clean 0.8) "aged daily-clean key is high-trust")
      (is (< struck clean) "two fresh strikes erode it")
      ;; bpen at 2 strikes = 1 − 0.9·(1 − 0.5^1) = 0.55
      (is (close? (* clean 0.55) struck)))))

;; -- axis classification (unchanged) --------------------------------------

(deftest axis-mismatch-mapping
  (is (= []                  (score/axis-mismatch->reasons #{})))
  (is (= [:ip-mismatch]      (score/axis-mismatch->reasons #{:ip})))
  (is (= [:fp-mismatch]      (score/axis-mismatch->reasons #{:fp})))
  (is (= [:all-mismatch]     (score/axis-mismatch->reasons #{:ip :fp}))))

(deftest axes-vs-cluster-empty
  (is (= {:closest nil :mismatch-axes #{:ip :fp}}
         (score/axes-vs-cluster {:ip "1.1.1.1"
                                  :fp-digest (byte-array 32)}
                                 []))))

(deftest axes-vs-cluster-exact-match-found
  (let [fp (byte-array (range 32))
        t  {:db/id 1 :tuple/ip-hash "1.1.1.1" :tuple/fp-digest fp
            :tuple/last-seen (java.util.Date.)}
        result (score/axes-vs-cluster {:ip "1.1.1.1" :fp-digest fp}
                                       [t])]
    (is (= #{} (:mismatch-axes result)))))

(deftest axes-vs-cluster-prefers-most-recent-on-tie
  (let [fp-a (byte-array (repeat 32 1))
        fp-b (byte-array (repeat 32 2))
        old  {:db/id 1 :tuple/ip-hash "1.1.1.1" :tuple/fp-digest fp-a
              :tuple/last-seen (java.util.Date. 1000)}
        new  {:db/id 2 :tuple/ip-hash "1.1.1.1" :tuple/fp-digest fp-b
              :tuple/last-seen (java.util.Date. 99999)}
        result (score/axes-vs-cluster {:ip "1.1.1.1" :fp-digest fp-b}
                                       [old new])]
    (is (= #{} (:mismatch-axes result)))
    (is (= 2 (:db/id (:closest result))))))

;; -- properties -----------------------------------------------------------

(def ^:private gen-sketch
  (gen/let [clean (gen/choose 0 100000)
            spacing (gen/double* {:min 0.0 :max 200.0 :NaN? false :infinite? false})
            viol  (gen/choose 0 100000)
            span-days (gen/choose 0 3650)
            idle-days (gen/choose 0 3650)]
    {:clean-count clean
     :spacing spacing
     :violation-count viol
     :created-at-ms 0
     :last-clean-at-ms (* (- span-days idle-days) DAY)
     :now-ms (* span-days DAY)}))

(defspec p-score-bounded 500
  (prop/for-all [m gen-sketch]
    (let [s (score/score-of m (:now-ms m) cfg)]
      (and (>= s 0.0) (<= s 1.0)))))

(defspec p-score-monotone-in-clean-count 300
  ;; More clean verifies (all else equal) never lowers the score.
  (prop/for-all [m    gen-sketch
                 bump (gen/choose 1 1000)]
    (let [now (:now-ms m)
          lo  (score/score-of m now cfg)
          hi  (score/score-of (update m :clean-count + bump) now cfg)]
      (>= (+ hi 1e-12) lo))))

(defspec p-score-monotone-in-spacing 300
  ;; More accumulated spacing (all else equal) never lowers the score.
  (prop/for-all [m     gen-sketch
                 extra (gen/double* {:min 0.0 :max 100.0 :NaN? false :infinite? false})]
    (let [now (:now-ms m)
          lo  (score/score-of m now cfg)
          hi  (score/score-of (update m :spacing + extra) now cfg)]
      (>= (+ hi 1e-12) lo))))

(defspec p-spacing-beats-massed 200
  ;; At equal clean-count/span/idle, any positive spacing scores ≥ zero spacing.
  (prop/for-all [m       gen-sketch
                 spacing (gen/double* {:min 0.0 :max 100.0 :NaN? false :infinite? false})]
    (let [now    (:now-ms m)
          base   (assoc m :violation-count 0)
          massed (score/score-of (assoc base :spacing 0.0) now cfg)
          spaced (score/score-of (assoc base :spacing spacing) now cfg)]
      (>= (+ spaced 1e-12) massed))))
