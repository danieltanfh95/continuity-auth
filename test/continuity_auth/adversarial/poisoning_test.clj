(ns continuity-auth.adversarial.poisoning-test
  "Adversarial tests demonstrating continuity-auth's security guarantees
  against trust-vector poisoning attacks.

  Each test names a concrete attack from the threat model (plan §A,
  ontology §2) and asserts that the system correctly resists it.

  These tests are tagged `:adversarial` so they can be run as a
  dedicated suite via `clojure -M:test --focus :adversarial`.

  Attacks covered:
    1. IP collision: attacker shares a victim's IP. Must NOT merge clusters.
    2. fp collision: attacker spoofs victim's fingerprint. Must NOT merge.
    3. Combined IP+fp collision without LS-key. Must NOT merge.
    4. LS-key compromise to attempt to gain victim's tier (rejected unless
       attacker actually has the private key, which is non-extractable on
       client and so this scenario is only reachable via XSS — out of
       continuity-auth's threat model)."
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.server.identity.merge :as merge]
   [continuity-auth.server.identity.score :as score]
   [continuity-auth.server.storage.datalevin :as dtlv]
   [continuity-auth.server.storage.protocol :as storage])
  (:import
   (java.nio.file Files)
   (java.nio.file.attribute FileAttribute)
   (java.security SecureRandom)
   (java.util Date)))

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "cauth-adv-" (into-array FileAttribute [])))

(defn- delete-recursively [^java.nio.file.Path p]
  (let [f (.toFile p)]
    (when (.isDirectory f)
      (doseq [c (.listFiles f)] (delete-recursively (.toPath c))))
    (.delete f)))

(defn- with-store [f]
  (let [dir (temp-dir)
        store (dtlv/open (.toString dir))]
    (try (f store)
         (finally (storage/close store) (delete-recursively dir)))))

(defn- rand-bytes ^bytes [n]
  (let [b (byte-array n)]
    (.nextBytes (SecureRandom.) b)
    b))

(defn- bootstrap! [store ip fp]
  (let [pkb (rand-bytes 32)
        pid (rand-bytes 32)
        tx  (merge/bootstrap-tx
             {:ip ip :fp-digest fp}
             {:bytes pkb :alg :ed25519 :id pid}
             (Date.))]
    (storage/transact! store tx)
    {:pid pid :ip ip :fp fp}))

(defn- identity-of-pubkey [store snap pid]
  (-> (storage/find-pubkey-by-thumbprint store snap pid)
      :pubkey/identity
      :db/id
      (or (-> (storage/find-pubkey-by-thumbprint store snap pid)
              :pubkey/identity))))

(defn- count-tuples-in-identity [store snap identity-eid]
  (count (storage/q store snap
                     '[:find [?t ...]
                       :in $ ?i
                       :where [?t :tuple/identity ?i]]
                     [identity-eid])))

;; -- attacks --------------------------------------------------------------

(deftest ^:adversarial ip-collision-does-not-merge
  (testing "Two identities sharing an IP remain distinct"
    (with-store
      (fn [store]
        (let [shared-ip "10.0.0.42"
              victim    (bootstrap! store shared-ip (rand-bytes 32))
              attacker  (bootstrap! store shared-ip (rand-bytes 32))
              snap      (storage/snapshot store)
              vid       (identity-of-pubkey store snap (:pid victim))
              aid       (identity-of-pubkey store snap (:pid attacker))]
          (is (not= vid aid)
              "shared IP must NOT cause cluster merge"))))))

(deftest ^:adversarial fp-collision-does-not-merge
  (testing "Two identities sharing a fingerprint remain distinct"
    (with-store
      (fn [store]
        (let [shared-fp (rand-bytes 32)
              victim    (bootstrap! store "1.2.3.4" shared-fp)
              attacker  (bootstrap! store "5.6.7.8" shared-fp)
              snap      (storage/snapshot store)
              vid       (identity-of-pubkey store snap (:pid victim))
              aid       (identity-of-pubkey store snap (:pid attacker))]
          (is (not= vid aid)
              "shared fingerprint digest must NOT cause cluster merge"))))))

(deftest ^:adversarial combined-ip-fp-collision-without-pubkey-does-not-merge
  (testing "Even with both IP and fp matching, an attacker without the
            victim's signing key creates a separate cluster"
    (with-store
      (fn [store]
        (let [victim-ip "10.0.0.42"
              victim-fp (rand-bytes 32)
              victim    (bootstrap! store victim-ip victim-fp)
              attacker  (bootstrap! store victim-ip victim-fp)
              snap      (storage/snapshot store)
              vid       (identity-of-pubkey store snap (:pid victim))
              aid       (identity-of-pubkey store snap (:pid attacker))]
          (is (not= vid aid)
              "ip+fp match without pubkey match must NOT merge clusters")
          (is (= 1 (count-tuples-in-identity store snap vid))
              "victim cluster unaffected")
          (is (= 1 (count-tuples-in-identity store snap aid))
              "attacker cluster has its own tuple only"))))))

(deftest ^:adversarial classify-records-cross-cluster-advisory-but-does-not-merge
  (testing "When a /verify request matches another cluster's IP/fp,
            the cross-cluster advisory is logged but no merge occurs"
    (with-store
      (fn [store]
        (let [shared-fp (rand-bytes 32)
              victim    (bootstrap! store "10.0.0.42" shared-fp)
              attacker  (bootstrap! store "5.6.7.8" (rand-bytes 32))
              snap      (storage/snapshot store)
              pubkey    (storage/find-pubkey-by-thumbprint store snap (:pid attacker))
              ;; Attacker /verify with their own signing key, but claiming
              ;; the victim's fingerprint.
              result    (merge/classify store snap
                                         {:ip "5.6.7.8" :fp-digest shared-fp}
                                         pubkey (Date.))]
          (is (true? (-> result :cross-cluster :fp))
              "cross-cluster fp-match must be flagged for ops review")
          (let [vid (identity-of-pubkey store snap (:pid victim))
                aid (identity-of-pubkey store snap (:pid attacker))]
            (is (not= vid aid))
            (is (= 1 (count-tuples-in-identity store snap vid))
                "victim cluster unchanged after attacker's classify")))))))

(deftest ^:adversarial ls-key-roaming-within-cluster
  (testing "A user roaming networks (IP change) stays in their cluster,
            with a small score penalty per the score model"
    (with-store
      (fn [store]
        (let [user  (bootstrap! store "10.0.0.1" (rand-bytes 32))
              snap0 (storage/snapshot store)
              pubkey (storage/find-pubkey-by-thumbprint store snap0 (:pid user))
              ;; Same user, same key, new IP.
              result (merge/classify store snap0
                                      {:ip "172.16.0.1" :fp-digest (:fp user)}
                                      pubkey (Date.))]
          (is (= :new-tuple (:kind result))
              "a new IP is a new tuple in the same cluster")
          (is (= #{:ip} (:mismatch-axes result))
              "only IP mismatched; fp matches")
          ;; Validate the cluster gained a tuple (not lost continuity).
          (let [tx (merge/classification-tx
                    result
                    {:ip "172.16.0.1" :fp-digest (:fp user)}
                    0.5
                    score/default-deltas
                    (Date.))]
            (storage/transact! store tx)
            (let [snap1 (storage/snapshot store)
                  iid   (identity-of-pubkey store snap1 (:pid user))
                  n     (count-tuples-in-identity store snap1 iid)]
              (is (= 2 n) "cluster now has 2 tuples (original + new IP)"))))))))

(deftest ^:adversarial revoked-key-cannot-verify
  (testing "A revoked pubkey is rejected by classify"
    (with-store
      (fn [store]
        (let [user   (bootstrap! store "10.0.0.1" (rand-bytes 32))
              snap0  (storage/snapshot store)
              pubkey (storage/find-pubkey-by-thumbprint store snap0 (:pid user))
              _      (storage/transact! store
                                         [{:db/id (:db/id pubkey)
                                           :pubkey/revoked-at (Date.)}])
              snap1  (storage/snapshot store)
              pubkey (storage/find-pubkey-by-thumbprint store snap1 (:pid user))
              result (merge/classify store snap1
                                      {:ip "10.0.0.1" :fp-digest (:fp user)}
                                      pubkey (Date.))]
          (is (= :revoked-pubkey (:kind result))))))))
