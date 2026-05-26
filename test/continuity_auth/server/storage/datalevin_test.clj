(ns continuity-auth.server.storage.datalevin-test
  "Storage layer integration tests against an embedded Datalevin env.

  Each test opens a fresh temp directory, runs its assertions, and closes
  the connection. Datalevin requires file-backed storage; we use a
  tmpdir per test to avoid cross-test contamination."
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.server.storage.datalevin :as dtlv]
   [continuity-auth.server.storage.protocol :as protocol]
   [continuity-auth.server.storage.schema :as schema])
  (:import
   (java.nio.file Files)
   (java.nio.file.attribute FileAttribute)
   (java.util UUID)))

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "cauth-test-" (into-array FileAttribute [])))

(defn- delete-recursively [^java.nio.file.Path p]
  (let [f (.toFile p)]
    (when (.isDirectory f)
      (doseq [child (.listFiles f)]
        (delete-recursively (.toPath child))))
    (.delete f)))

(defn- with-fresh-store [f]
  (let [dir   (temp-dir)
        store (dtlv/open (.toString dir))]
    (try
      (f store)
      (finally
        (protocol/close store)
        (delete-recursively dir)))))

;; -- schema version interlock ----------------------------------------------

(deftest schema-version-installed-on-fresh-db
  (with-fresh-store
    (fn [store]
      (is (= :installed
             (dtlv/ensure-schema-version! store schema/schema-version))))))

(deftest schema-version-ok-on-equal-version
  (with-fresh-store
    (fn [store]
      (dtlv/ensure-schema-version! store schema/schema-version)
      (is (= :ok
             (dtlv/ensure-schema-version! store schema/schema-version))))))

(deftest schema-version-pending-upgrade-when-code-newer
  (with-fresh-store
    (fn [store]
      (dtlv/ensure-schema-version! store 1)
      (is (= :pending-upgrade
             (dtlv/ensure-schema-version! store 2))))))

(deftest schema-version-throws-when-db-ahead
  (with-fresh-store
    (fn [store]
      (dtlv/ensure-schema-version! store 5)
      (is (thrown? clojure.lang.ExceptionInfo
                   (dtlv/ensure-schema-version! store 4))))))

;; -- identity + tuple + pubkey CRUD ---------------------------------------

(defn- now [] (java.util.Date.))

(deftest can-insert-and-query-identity
  (with-fresh-store
    (fn [store]
      (let [id   (UUID/randomUUID)
            now0 (now)
            _    (protocol/transact!
                  store
                  [{:identity/id            id
                    :identity/created-at    now0
                    :identity/last-event-at now0
                    :identity/score         0.5
                    :identity/ever-tracked? false}])
            snap (protocol/snapshot store)
            ident (protocol/pull store snap
                                 [:identity/id id]
                                 [:db/id :identity/id :identity/score])]
        (is (= id (:identity/id ident)))
        (is (= 0.5 (:identity/score ident)))))))

(deftest can-find-tuples-by-axis
  (with-fresh-store
    (fn [store]
      (let [iid (UUID/randomUUID)
            tid (UUID/randomUUID)
            pid (byte-array (repeat 32 1))
            fpd (byte-array (repeat 32 2))
            n0  (now)]
        (protocol/transact!
         store
         [{:db/id                          -1
           :identity/id                    iid
           :identity/created-at            n0
           :identity/last-event-at         n0
           :identity/score                 0.5
           :identity/ever-tracked?         false}
          {:db/id                          -2
           :pubkey/id                      pid
           :pubkey/identity                -1
           :pubkey/bytes                   (byte-array 32)
           :pubkey/alg                     :ed25519
           :pubkey/created-at              n0}
          {:tuple/id                       tid
           :tuple/identity                 -1
           :tuple/ip                       "192.0.2.1"
           :tuple/fp-digest                fpd
           :tuple/pubkey                   -2
           :tuple/first-seen               n0
           :tuple/last-seen                n0
           :tuple/observation-count        1}])
        (let [snap (protocol/snapshot store)
              by-ip (protocol/find-tuples-by-ip store snap "192.0.2.1")]
          (testing "lookup by IP"
            (is (= 1 (count by-ip)))
            (is (= "192.0.2.1" (-> by-ip first :tuple/ip)))))

        (let [snap (protocol/snapshot store)
              found (protocol/find-pubkey-by-thumbprint store snap pid)]
          (testing "find-pubkey-by-thumbprint"
            (is (some? found))
            (is (= :ed25519 (:pubkey/alg found)))))))))

;; -- nonce cache --------------------------------------------------------

(deftest nonce-seen-roundtrip
  (with-fresh-store
    (fn [store]
      (let [h     (byte-array (repeat 32 0xab))
            until (java.util.Date. (+ (.getTime (now)) 60000))]
        (let [snap (protocol/snapshot store)]
          (is (false? (protocol/nonce-seen? store snap h))))
        (protocol/transact! store [{:nonce/hash       h
                                    :nonce/expires-at until}])
        (let [snap (protocol/snapshot store)]
          (is (true? (protocol/nonce-seen? store snap h))))))))

(deftest sweep-expired-nonces
  (with-fresh-store
    (fn [store]
      (let [past   (java.util.Date. (- (.getTime (now)) 60000))
            future (java.util.Date. (+ (.getTime (now)) 60000))
            h-old  (byte-array (repeat 32 1))
            h-new  (byte-array (repeat 32 2))]
        (protocol/transact! store
                            [{:nonce/hash       h-old
                              :nonce/expires-at past}
                             {:nonce/hash       h-new
                              :nonce/expires-at future}])
        (let [retracted (protocol/sweep-expired! store :nonce/hash
                                                 :nonce/expires-at (now))]
          (is (= 1 retracted)))
        (let [snap (protocol/snapshot store)]
          (is (false? (protocol/nonce-seen? store snap h-old)))
          (is (true?  (protocol/nonce-seen? store snap h-new))))))))

;; -- async transact ------------------------------------------------------

(deftest transact-async-completes
  (with-fresh-store
    (fn [store]
      (let [iid (UUID/randomUUID)
            n0  (now)
            fut (protocol/transact-async!
                 store
                 [{:identity/id            iid
                   :identity/created-at    n0
                   :identity/last-event-at n0
                   :identity/score         0.5
                   :identity/ever-tracked? false}])
            report @fut]
        (is (some? report))
        (is (-> (protocol/pull store (protocol/snapshot store)
                               [:identity/id iid]
                               [:identity/id])
                :identity/id
                (= iid)))))))
