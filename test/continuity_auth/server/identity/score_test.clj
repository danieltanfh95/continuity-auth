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
          s1 (score/sketch-update s0 (* 2 DAY) false cfg)]
      (is (= 4 (:clean-count s1)))
      (is (close? (+ 0.5 (Math/log 3.0)) (:spacing s1)) "spacing += ln(1+2)")
      (is (= (* 2 DAY) (:last-clean-at-ms s1)))
      (is (= 1 (:violation-count s1)) "no violation on a clean exact verify")
      (is (= 0 (:created-at-ms s1)) "span anchor untouched"))))

(deftest sketch-update-violation-increments-and-still-reinforces
  (testing "a mismatch verify counts as both continuity (clean) and a violation"
    (let [s0 {:clean-count 3 :spacing 0.5 :violation-count 1
              :created-at-ms 0 :last-clean-at-ms 0}
          s1 (score/sketch-update s0 (* 2 DAY) true cfg)]
      (is (= 4 (:clean-count s1)) "still a pubkey-matched reinforcement")
      (is (= 2 (:violation-count s1)) "violation-count bumped"))))

(deftest sketch-update-rapid-fire-accrues-no-spacing
  (testing "a sub-gap-min return increments count but not spacing"
    (let [s0 {:clean-count 3 :spacing 0.5 :violation-count 0
              :created-at-ms 0 :last-clean-at-ms 0}
          s1 (score/sketch-update s0 (long (* 0.1 DAY)) false cfg)]
      (is (= 4 (:clean-count s1)))
      (is (close? 0.5 (:spacing s1)) "no spacing credit for rapid-fire"))))

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
