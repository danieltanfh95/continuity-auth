(ns continuity-auth.server.identity.score-test
  "Pure score-delta calculus tests."
  (:require
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [continuity-auth.server.identity.score :as score]))

(deftest clamp-keeps-range
  (is (= 0.0 (score/clamp -0.5)))
  (is (= 1.0 (score/clamp 1.5)))
  (is (= 0.5 (score/clamp 0.5))))

(defn- close? [a b]
  (< (Math/abs (- (double a) (double b))) 1e-9))

(deftest apply-delta-bounded
  (is (close? 0.55 (score/apply-delta 0.5  0.05)))
  (is (close? 0.0  (score/apply-delta 0.0 -0.05)))
  (is (close? 1.0  (score/apply-delta 1.0  0.05))))

(deftest axis-mismatch-mapping
  (is (= []                  (score/axis-mismatch->reasons #{})))
  (is (= [:ip-mismatch]      (score/axis-mismatch->reasons #{:ip})))
  (is (= [:fp-mismatch]      (score/axis-mismatch->reasons #{:fp})))
  (is (= [:all-mismatch]     (score/axis-mismatch->reasons #{:ip :fp}))))

(deftest delta-for-reasons-default
  (let [d score/default-deltas]
    (is (close? 0.05  (score/delta-for-reasons d [:pubkey-match])))
    (is (close? 0.03  (score/delta-for-reasons d [:pubkey-match :ip-mismatch])))
    (is (close? -0.05 (score/delta-for-reasons d [:fp-mismatch])))
    (is (close? -0.05 (score/delta-for-reasons d [:pubkey-match :all-mismatch])))))

(deftest decay-toward-neutral
  (testing "decay moves below-neutral score up"
    (let [s (score/decay 0.0 86400 {})]   ; one day, default 0.01/day
      (is (< 0.0 s 0.02))))
  (testing "decay moves above-neutral score down"
    (let [s (score/decay 1.0 86400 {})]
      (is (< 0.98 s 1.0))))
  (testing "score at neutral is unchanged by decay"
    (is (= 0.5 (score/decay 0.5 86400 {}))))
  (testing "zero seconds = no change"
    (is (= 0.42 (score/decay 0.42 0 {})))))

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

(defspec p-apply-delta-bounded 500
  (prop/for-all [s     (gen/double* {:min 0.0 :max 1.0 :NaN? false :infinite? false})
                 delta (gen/double* {:min -2.0 :max 2.0 :NaN? false :infinite? false})]
    (let [s' (score/apply-delta s delta)]
      (and (>= s' 0.0) (<= s' 1.0)))))

(defspec p-decay-bounded 200
  (prop/for-all [s    (gen/double* {:min 0.0 :max 1.0 :NaN? false :infinite? false})
                 secs (gen/choose 0 (* 86400 365))]   ; 0 to 1 year
    (let [s' (score/decay s secs {})]
      (and (>= s' 0.0) (<= s' 1.0)))))

(defspec p-decay-never-overshoots-neutral 200
  ;; Decay drifts toward 0.5; it must not cross 0.5 in one step.
  (prop/for-all [s    (gen/double* {:min 0.0 :max 1.0 :NaN? false :infinite? false})
                 secs (gen/choose 0 (* 86400 365))]
    (let [s' (score/decay s secs {})]
      (if (< s 0.5)
        (<= s s' 0.5)
        (if (> s 0.5)
          (<= 0.5 s' s)
          true)))))
