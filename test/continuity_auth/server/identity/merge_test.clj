(ns continuity-auth.server.identity.merge-test
  "Tests for the identity merge / classification logic, exercised against
  an embedded Datalevin instance so that the indexed lookups run for real."
  (:require
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [continuity-auth.server.identity.merge :as merge]
   [continuity-auth.server.identity.score :as score]
   [continuity-auth.server.storage.datalevin :as dtlv]
   [continuity-auth.server.storage.protocol :as storage])
  (:import
   (java.nio.file Files)
   (java.nio.file.attribute FileAttribute)
   (java.util Date)))

;; -- temp storage helper ---------------------------------------------------

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "cauth-merge-test-" (into-array FileAttribute [])))

(defn- delete-recursively [^java.nio.file.Path p]
  (let [f (.toFile p)]
    (when (.isDirectory f)
      (doseq [c (.listFiles f)]
        (delete-recursively (.toPath c))))
    (.delete f)))

(defn- with-store [f]
  (let [dir   (temp-dir)
        store (dtlv/open (.toString dir))]
    (try (f store)
         (finally (storage/close store) (delete-recursively dir)))))

(defn- random-bytes ^bytes [n]
  (let [b (byte-array n)]
    (.nextBytes (java.security.SecureRandom.) b)
    b))

(defn- bootstrap! [store ip fp pubkey-bytes pubkey-id]
  (let [tx (merge/bootstrap-tx
            {:ip ip :fp-digest fp}
            {:bytes pubkey-bytes :alg :ed25519 :id pubkey-id}
            (Date.)
            score/default-scoring)
        report (storage/transact! store tx)
        snap (storage/snapshot store)
        pk   (storage/find-pubkey-by-thumbprint store snap pubkey-id)]
    {:tx-report report
     :pubkey    pk
     :snap      snap}))

;; -- bootstrap ------------------------------------------------------------

(deftest bootstrap-creates-three-entities
  (with-store
    (fn [store]
      (let [pkb (random-bytes 32)
            pid (random-bytes 32)
            {:keys [pubkey snap]} (bootstrap! store "1.1.1.1"
                                              (random-bytes 32) pkb pid)]
        (is (some? pubkey))
        (is (some? (:pubkey/identity pubkey)))
        (let [n (count (storage/q store snap
                                  '[:find [?t ...]
                                    :where [?t :tuple/identity _]]
                                  []))]
          (is (= 1 n) "bootstrap creates exactly one tuple"))))))

(deftest two-bootstraps-create-two-identities
  (with-store
    (fn [store]
      (bootstrap! store "1.1.1.1" (random-bytes 32) (random-bytes 32) (random-bytes 32))
      (bootstrap! store "2.2.2.2" (random-bytes 32) (random-bytes 32) (random-bytes 32))
      (let [snap (storage/snapshot store)
            n (count (storage/q store snap
                                '[:find [?i ...]
                                  :where [?i :identity/id _]]
                                []))]
        (is (= 2 n))))))

(deftest bootstrap-with-same-ip-still-separate-identities
  (testing "ontology §7: bootstrap never merges across IP/fp — only pubkey-anchored merges"
    (with-store
      (fn [store]
        (let [shared-ip "203.0.113.1"
              shared-fp (random-bytes 32)]
          (bootstrap! store shared-ip shared-fp (random-bytes 32) (random-bytes 32))
          (bootstrap! store shared-ip shared-fp (random-bytes 32) (random-bytes 32))
          (let [snap (storage/snapshot store)
                n (count (storage/q store snap
                                    '[:find [?i ...]
                                      :where [?i :identity/id _]]
                                    []))]
            (is (= 2 n) "two bootstraps with identical IP+fp yield two identities")))))))

;; -- classify path --------------------------------------------------------

(deftest classify-exact-observation
  (with-store
    (fn [store]
      (let [ip "10.0.0.1"
            fp (random-bytes 32)
            {:keys [pubkey]} (bootstrap! store ip fp
                                          (random-bytes 32) (random-bytes 32))
            snap (storage/snapshot store)
            result (merge/classify store snap
                                    {:ip ip :fp-digest fp} pubkey (Date.))]
        (is (= :exact-observation (:kind result)))
        (is (= #{} (:mismatch-axes result)))))))

(deftest classify-new-tuple-ip-mismatch
  (with-store
    (fn [store]
      (let [ip "10.0.0.1"
            ip2 "10.0.0.2"
            fp (random-bytes 32)
            {:keys [pubkey]} (bootstrap! store ip fp
                                          (random-bytes 32) (random-bytes 32))
            snap (storage/snapshot store)
            result (merge/classify store snap
                                    {:ip ip2 :fp-digest fp} pubkey (Date.))]
        (is (= :new-tuple (:kind result)))
        (is (= #{:ip} (:mismatch-axes result)))))))

(deftest classify-new-tuple-fp-mismatch
  (with-store
    (fn [store]
      (let [ip "10.0.0.1"
            fp  (random-bytes 32)
            fp2 (random-bytes 32)
            {:keys [pubkey]} (bootstrap! store ip fp
                                          (random-bytes 32) (random-bytes 32))
            snap (storage/snapshot store)
            result (merge/classify store snap
                                    {:ip ip :fp-digest fp2} pubkey (Date.))]
        (is (= :new-tuple (:kind result)))
        (is (= #{:fp} (:mismatch-axes result)))))))

(deftest classify-new-tuple-all-mismatch
  (with-store
    (fn [store]
      (let [{:keys [pubkey]} (bootstrap! store "10.0.0.1" (random-bytes 32)
                                          (random-bytes 32) (random-bytes 32))
            snap (storage/snapshot store)
            result (merge/classify store snap
                                    {:ip "172.16.0.1" :fp-digest (random-bytes 32)}
                                    pubkey (Date.))]
        (is (= :new-tuple (:kind result)))
        (is (= #{:ip :fp} (:mismatch-axes result)))))))

(deftest classify-detects-cross-cluster-fp-but-does-not-merge
  (with-store
    (fn [store]
      (let [shared-fp (random-bytes 32)]
        (bootstrap! store "10.0.0.1" shared-fp (random-bytes 32) (random-bytes 32))
        (let [{:keys [pubkey]} (bootstrap! store "10.0.0.2" (random-bytes 32)
                                            (random-bytes 32) (random-bytes 32))
              snap   (storage/snapshot store)
              result (merge/classify store snap
                                      {:ip "10.0.0.2" :fp-digest shared-fp}
                                      pubkey (Date.))]
          (is (= :new-tuple (:kind result)))
          (is (true? (-> result :cross-cluster :fp))
              "cross-cluster fp-match should be flagged as advisory"))))))

(deftest classify-revoked-pubkey
  (with-store
    (fn [store]
      (let [{:keys [pubkey]} (bootstrap! store "1.1.1.1" (random-bytes 32)
                                          (random-bytes 32) (random-bytes 32))
            _      (storage/transact! store [{:db/id (:db/id pubkey)
                                              :pubkey/revoked-at (Date.)}])
            snap   (storage/snapshot store)
            pubkey (storage/find-pubkey-by-thumbprint
                     store snap (:pubkey/id pubkey))
            result (merge/classify store snap
                                    {:ip "1.1.1.1" :fp-digest (random-bytes 32)}
                                    pubkey (Date.))]
        (is (= :revoked-pubkey (:kind result)))))))

(deftest classify-future-dated-revoked-at-is-still-valid
  ;; A future-dated :pubkey/revoked-at is the in-grace state from rotation
  ;; (ontology §4). It must NOT be treated as revoked yet.
  (with-store
    (fn [store]
      (let [{:keys [pubkey]} (bootstrap! store "1.1.1.1" (random-bytes 32)
                                          (random-bytes 32) (random-bytes 32))
            future (Date. (+ (System/currentTimeMillis) 3600000))
            _      (storage/transact! store [{:db/id (:db/id pubkey)
                                              :pubkey/revoked-at future}])
            snap   (storage/snapshot store)
            pubkey (storage/find-pubkey-by-thumbprint
                     store snap (:pubkey/id pubkey))
            result (merge/classify store snap
                                    {:ip "1.1.1.1" :fp-digest (random-bytes 32)}
                                    pubkey (Date.))]
        (is (not= :revoked-pubkey (:kind result))
            "in-grace pubkey must not be treated as revoked")))))

(deftest classify-orphan-pubkey
  ;; Synthesize a pubkey record with no :pubkey/identity to simulate the
  ;; invariant-violation case (which should normally be unreachable in
  ;; production).
  (with-store
    (fn [store]
      (let [snap (storage/snapshot store)
            result (merge/classify store snap
                                    {:ip "1.1.1.1" :fp-digest (random-bytes 32)}
                                    {:db/id 123 :pubkey/id (random-bytes 32)}
                                    (Date.))]
        (is (= :orphan-pubkey (:kind result)))))))

;; -- classification-tx semantics ------------------------------------------

;; A sketch for an established key: 10 clean verifies, two weeks old, last
;; seen two days ago, no prior violations. `now` is two days after the last
;; clean verify so the spaced gap accrues credit.
(def ^:private now-ms (System/currentTimeMillis))
(def ^:private established-sketch
  {:clean-count      10
   :spacing          5.0
   :violation-count  0
   :created-at-ms    (- now-ms (* 14 86400000))
   :last-clean-at-ms (- now-ms (*  2 86400000))})
(def ^:private now-date (java.util.Date. now-ms))

(deftest classification-tx-exact-observation-reinforces-sketch
  (testing "an exact observation increments clean-count, accrues spacing, raises score"
    (let [classification {:kind            :exact-observation
                          :identity-eid    1
                          :existing-tuple  {:db/id 100
                                             :tuple/observation-count 3}
                          :mismatch-axes   #{}
                          :cross-cluster   {:ip false :fp false}}
          tx (merge/classification-tx classification
                                       {:ip "1.1.1.1" :fp-digest (byte-array 32)}
                                       established-sketch score/default-scoring now-date)
          identity-update (first (filter #(= 1 (:db/id %)) tx))
          trust-event     (first (filter :trust-event/identity tx))
          score-before    (score/score-of established-sketch now-ms score/default-scoring)]
      (is (= 11 (:identity/clean-count identity-update)) "clean-count++")
      (is (> (:identity/spacing identity-update) 5.0) "spacing accrues the 2-day gap")
      (is (= 0 (:identity/violation-count identity-update)) "no violation on an exact match")
      (is (>= (:identity/score identity-update) score-before)
          "spaced reinforcement never lowers the score")
      (is (>= (:trust-event/delta trust-event) 0.0))
      (is (= :pubkey-match (:trust-event/reason trust-event))))))

(deftest classification-tx-new-tuple-ip-mismatch-reinforces-and-flags
  (testing "a single-axis IP-mismatch still reinforces continuity AND records a violation"
    (let [classification {:kind          :new-tuple
                          :identity-eid  42
                          :existing-tuple nil
                          :mismatch-axes  #{:ip}
                          :cross-cluster  {:ip false :fp false}
                          :pubkey-eid     7}
          tx (merge/classification-tx classification
                                       {:ip "1.1.1.1" :fp-digest (byte-array 32)}
                                       established-sketch score/default-scoring now-date)
          tuple-create (first (filter :tuple/id tx))
          identity-update (first (filter #(= 42 (:db/id %)) tx))]
      (is (some? tuple-create))
      (is (= 42 (:tuple/identity tuple-create)))
      (is (= 7  (:tuple/pubkey tuple-create)))
      (is (= 11 (:identity/clean-count identity-update))
          "a roaming user (new IP, same key) still reinforces the cluster")
      (is (= 1 (:identity/violation-count identity-update))
          "the axis mismatch is recorded as a violation"))))

(deftest classification-tx-new-tuple-all-mismatch-erodes-vs-clean
  (testing "all-axis mismatch records a violation that strictly lowers score vs the clean counterfactual"
    (let [classification {:kind          :new-tuple
                          :identity-eid  42
                          :existing-tuple nil
                          :mismatch-axes  #{:ip :fp}
                          :cross-cluster  {:ip false :fp false}
                          :pubkey-eid     7}
          tx (merge/classification-tx classification
                                       {:ip "1.1.1.1" :fp-digest (byte-array 32)}
                                       established-sketch score/default-scoring now-date)
          identity-update (first (filter #(= 42 (:db/id %)) tx))
          ;; counterfactual: same sketch update but treated as clean (no violation)
          clean-after (score/score-of
                       (score/sketch-update established-sketch now-ms false score/default-scoring)
                       now-ms score/default-scoring)]
      (is (= 1 (:identity/violation-count identity-update)))
      (is (< (:identity/score identity-update) clean-after)
          "the violation term erodes the score below the clean-path score"))))

;; -- properties -----------------------------------------------------------

(def ^:private gen-ip
  (gen/let [a (gen/choose 1 254)
            b (gen/choose 0 254)
            c (gen/choose 0 254)
            d (gen/choose 1 254)]
    (str a "." b "." c "." d)))

(def ^:private gen-fp
  (gen/fmap byte-array (gen/vector (gen/choose 0 255) 32)))

(defspec p-score-bounded-after-arbitrary-sequence 30
  (prop/for-all [arrivals (gen/vector
                            (gen/tuple gen-ip gen-fp)
                            1 12)]
    (let [dir (temp-dir)]
      (try
        (let [store (dtlv/open (.toString dir))]
          (try
            (let [pkb (random-bytes 32)
                  pid (random-bytes 32)
                  [bootstrap-ip bootstrap-fp] (first arrivals)]
              (bootstrap! store bootstrap-ip bootstrap-fp pkb pid)
              (doseq [[ip fp] (rest arrivals)]
                (let [snap (storage/snapshot store)
                      pubkey (storage/find-pubkey-by-thumbprint store snap pid)
                      result (merge/classify store snap
                                              {:ip ip :fp-digest fp} pubkey
                                              (Date.))]
                  (when (#{:exact-observation :new-tuple} (:kind result))
                    (let [now   (Date.)
                          ident (storage/pull
                                  store snap (:identity-eid result)
                                  [:identity/clean-count :identity/spacing
                                   :identity/violation-count :identity/created-at
                                   :identity/last-clean-at])
                          sketch (merge/identity->sketch ident (.getTime now))
                          tx (merge/classification-tx
                               result
                               {:ip ip :fp-digest fp}
                               sketch
                               score/default-scoring
                               now)]
                      (storage/transact! store tx)))))
              (let [snap (storage/snapshot store)
                    scores (storage/q store snap
                                       '[:find [?s ...]
                                         :where [_ :identity/score ?s]]
                                       [])]
                (every? #(<= 0.0 % 1.0) scores)))
            (finally (storage/close store))))
        (finally (delete-recursively dir))))))

(defspec p-cluster-grows-only-via-ls 30
  (prop/for-all [n-arrivals (gen/choose 1 8)
                 base-ip   gen-ip
                 base-fp   gen-fp]
    (let [dir (temp-dir)]
      (try
        (let [store (dtlv/open (.toString dir))
              pkb   (random-bytes 32)
              pid   (random-bytes 32)]
          (try
            (bootstrap! store base-ip base-fp pkb pid)
            ;; All subsequent arrivals use a DIFFERENT pubkey thumbprint
            ;; (i.e., bootstrap calls). The original cluster must never
            ;; grow.
            (dotimes [_ n-arrivals]
              (bootstrap! store base-ip base-fp
                          (random-bytes 32) (random-bytes 32)))
            (let [snap (storage/snapshot store)
                  cluster-tuples (storage/q
                                   store snap
                                   '[:find [?t ...]
                                     :in $ ?p
                                     :where
                                     [?p :pubkey/identity ?i]
                                     [?t :tuple/identity ?i]]
                                   [[:pubkey/id pid]])]
              (= 1 (count cluster-tuples)))
            (finally (storage/close store))))
        (finally (delete-recursively dir))))))
