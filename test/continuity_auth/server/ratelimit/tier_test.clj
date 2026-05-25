(ns continuity-auth.server.ratelimit.tier-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [continuity-auth.server.ratelimit.tier :as tier]))

(deftest banned-below-005
  (is (= :banned (tier/project {:score 0.04 :host-linked? false :ever-tracked? false})))
  (is (= :banned (tier/project {:score 0.04 :host-linked? true  :ever-tracked? true}))))

(deftest penalized-below-tracked-when-ever-tracked
  (is (= :penalized (tier/project {:score 0.20 :host-linked? false :ever-tracked? true}))))

(deftest anonymous-default-state
  (testing "low score, no host-link, never tracked → anonymous"
    (is (= :anonymous (tier/project {:score 0.20 :host-linked? false :ever-tracked? false})))))

(deftest tracked-via-score
  (is (= :tracked (tier/project {:score 0.3 :host-linked? false :ever-tracked? false}))))

(deftest tracked-via-host-link-requires-higher-score
  (testing "host-linked but score below 0.5 → still anonymous"
    (is (= :anonymous (tier/project {:score 0.4 :host-linked? true :ever-tracked? false}))))
  (testing "host-linked + score >= 0.5 → tracked"
    (is (= :tracked (tier/project {:score 0.5 :host-linked? true :ever-tracked? false})))))

(deftest limit-defaults-most-restrictive-at-banned
  (is (zero? (tier/limit-for :banned :1m)))
  (is (zero? (tier/limit-for :banned :5m)))
  (is (pos?  (tier/limit-for :tracked :1m))))

;; -- properties ----------------------------------------------------------

(defspec p-project-total 200
  (prop/for-all [s   (gen/double* {:min 0.0 :max 1.0 :NaN? false :infinite? false})
                 hl? gen/boolean
                 et? gen/boolean]
    (#{:anonymous :tracked :penalized :banned}
     (tier/project {:score s :host-linked? hl? :ever-tracked? et?}))))

(defspec p-banned-score-always-banned 100
  (prop/for-all [s   (gen/double* {:min 0.0 :max 0.0499 :NaN? false :infinite? false})
                 hl? gen/boolean
                 et? gen/boolean]
    (= :banned (tier/project {:score s :host-linked? hl? :ever-tracked? et?}))))

(defspec p-tracked-not-anonymous-when-high-score-no-hl 100
  (prop/for-all [s (gen/double* {:min 0.31 :max 1.0 :NaN? false :infinite? false})]
    (= :tracked
       (tier/project {:score s :host-linked? false :ever-tracked? false}))))
