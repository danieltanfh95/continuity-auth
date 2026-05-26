(ns continuity-auth.server.replay.nonce-test
  "Replay-cache unit and adversarial tests.

  These exercise:
    - novel-nonce admission
    - duplicate-nonce rejection (the core replay defense)
    - TTL-based expiry via sweep
    - the sweeper thread starts and stops cleanly"
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.server.replay.nonce :as nonce]
   [continuity-auth.server.storage.datalevin :as dtlv]
   [continuity-auth.server.storage.protocol :as storage])
  (:import
   (java.nio.file Files)
   (java.nio.file.attribute FileAttribute)
   (java.util Date)))

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "cauth-nonce-test-" (into-array FileAttribute [])))

(defn- delete-recursively [^java.nio.file.Path p]
  (let [f (.toFile p)]
    (when (.isDirectory f)
      (doseq [child (.listFiles f)]
        (delete-recursively (.toPath child))))
    (.delete f)))

(defn- with-store [f]
  (let [dir   (temp-dir)
        store (dtlv/open (.toString dir))]
    (try
      (f store)
      (finally
        (storage/close store)
        (delete-recursively dir)))))

(defn- random-nonce ^bytes []
  (let [b (byte-array 16)]
    (.nextBytes (java.security.SecureRandom.) b)
    b))

;; -- correctness ------------------------------------------------------------

(deftest novel-nonce-accepted
  (with-store
    (fn [store]
      (let [n   (random-nonce)
            now (Date.)]
        (is (= :ok (nonce/check-and-record! store n 120 now)))))))

(deftest duplicate-nonce-rejected
  (with-store
    (fn [store]
      (let [n   (random-nonce)
            now (Date.)]
        (is (= :ok     (nonce/check-and-record! store n 120 now)))
        (is (= :replay (nonce/check-and-record! store n 120 now)))))))

(deftest distinct-nonces-do-not-collide
  (with-store
    (fn [store]
      (dotimes [_ 200]
        (let [n (random-nonce)]
          (is (= :ok (nonce/check-and-record! store n 120 (Date.))))))
      (is (= :replay
             (nonce/check-and-record!
              store
              ;; reuse the nonce of a known entry — this should be a replay
              (let [n (random-nonce)]
                (nonce/check-and-record! store n 120 (Date.))
                n)
              120 (Date.)))))))

;; -- TTL / sweep -----------------------------------------------------------

(deftest expired-nonces-can-be-reused-after-sweep
  (with-store
    (fn [store]
      (let [n        (random-nonce)
            past     (Date. (- (.getTime (Date.)) 600000))   ; -10 min
            ;; Insert directly with an already-passed expiry so we can
            ;; exercise the sweeper as if real time had elapsed.
            h        (nonce/nonce-hash n)]
        (storage/transact! store [{:nonce/hash       h
                                   :nonce/expires-at past}])
        (is (true? (storage/nonce-seen? store (storage/snapshot store) h))
            "nonce is present pre-sweep")
        (let [reclaimed (nonce/sweep! store (Date.))]
          (is (= 1 reclaimed)))
        (is (false? (storage/nonce-seen? store (storage/snapshot store) h))
            "nonce is gone post-sweep")
        (is (= :ok (nonce/check-and-record! store n 120 (Date.)))
            "the same nonce can be recorded once it has been swept")))))

;; -- sweeper thread lifecycle ----------------------------------------------

(deftest sweeper-thread-starts-and-stops
  (with-store
    (fn [store]
      (let [stop (nonce/start-sweeper! store 1)]
        (try
          (is (fn? stop))
          (finally
            (stop)))))))

;; -- adversarial: parallel replay attempt ----------------------------------

(deftest concurrent-replay-attempts-rejected
  ;; The single-writer model serializes the transact calls; only one
  ;; can win. The losers must see :replay.
  (with-store
    (fn [store]
      (let [n  (random-nonce)
            n  (vec n)             ; immutable copy for fn closure
            ba (byte-array n)
            attempts 16
            futures (doall
                     (for [_ (range attempts)]
                       (future (nonce/check-and-record! store ba 120 (Date.)))))
            results (mapv deref futures)
            oks    (count (filter #(= :ok %) results))
            replays (count (filter #(= :replay %) results))]
        (is (= 1 oks)
            (str "exactly one writer must win; got " oks " :ok results"))
        (is (= (dec attempts) replays))))))
