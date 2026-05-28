(ns continuity-auth.server.storage.migrations.runner-test
  "Schema-migration integration tests.

  The v2→v3 migration walks every `:tuple/ip` entity, computes
  `HMAC-SHA256(ip)` under a runtime keystore secret, transacts the hash
  to `:tuple/ip-hash`, and retracts the legacy `:tuple/ip` attribute.

  The legacy `:tuple/ip` attribute is no longer present in the
  production schema map, so seeding a v2 store requires opening
  Datalevin directly with a schema map that includes it. After seeding
  we close the connection and re-open via `dtlv/open` (production
  schema) — Datalevin's persisted attribute store retains the legacy
  attribute so the migration's Datalog query still resolves entities
  with `[?e :tuple/ip ?ip]`."
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.server.crypto.ip-hmac :as ip-hmac]
   [continuity-auth.server.storage.datalevin :as dtlv]
   [continuity-auth.server.storage.migrations.runner :as runner]
   [continuity-auth.server.storage.protocol :as protocol]
   [continuity-auth.server.storage.schema :as schema]
   [datalevin.core :as d])
  (:import
   (java.nio.file Files)
   (java.nio.file.attribute FileAttribute)
   (java.util Date UUID)))

;; -- fixtures ------------------------------------------------------------

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "cauth-mig-" (into-array FileAttribute [])))

(defn- delete-recursively [^java.nio.file.Path p]
  (let [f (.toFile p)]
    (when (.isDirectory f)
      (doseq [c (.listFiles f)]
        (delete-recursively (.toPath c))))
    (.delete f)))

(def ^:private legacy-schema-v2
  "Schema as it existed at v2 — same as the current schema except
  `:tuple/ip` (plaintext indexed string) is present and
  `:tuple/ip-hash` is absent. Used only to seed a pre-v3 fixture
  store."
  (-> schema/schema
      (dissoc :tuple/ip-hash)
      (assoc :tuple/ip {:db/valueType :db.type/string
                        :db/index     true})))

(defn- seed-v2-store!
  "Open `path` with the legacy v2 schema, transact `:schema/version 2`
  and one tuple per IP in `ips`. Closes the connection before
  returning."
  [path ips]
  (let [conn (d/get-conn path legacy-schema-v2
                         {:validate-data? true :auto-entity-time? false})]
    (try
      (let [now (Date.)
            tx  (into [{:schema/version 2}]
                      (mapcat
                       (fn [i ip]
                         (let [iid    (UUID/randomUUID)
                               tid    (UUID/randomUUID)
                               i-eid  (- (+ 1 (* 2 i)))
                               t-eid  (- (+ 2 (* 2 i)))]
                           [{:db/id                  i-eid
                             :identity/id            iid
                             :identity/created-at    now
                             :identity/last-event-at now
                             :identity/score         0.5
                             :identity/ever-tracked? false}
                            {:db/id                  t-eid
                             :tuple/id               tid
                             :tuple/identity         i-eid
                             :tuple/ip               ip
                             :tuple/fp-digest        (byte-array 32 (unchecked-byte i))
                             :tuple/first-seen       now
                             :tuple/last-seen        now
                             :tuple/observation-count 1}]))
                       (range)
                       ips))]
        (d/transact! conn tx))
      (finally
        (d/close conn)))))

(def ^:private fixed-key
  (byte-array (map byte (range 32))))

;; -- tests --------------------------------------------------------------

(deftest v2-to-v3-migration-rehashes-every-tuple-ip
  (testing "Every :tuple/ip is retracted; every entity gains a
            :tuple/ip-hash equal to HMAC-SHA256(ip) under the keystore
            secret; schema-version moves to 3."
    (let [dir (temp-dir)
          path (.toString dir)
          ips ["203.0.113.1" "203.0.113.2" "198.51.100.7"]]
      (try
        (seed-v2-store! path ips)
        (let [storage (dtlv/open path)]
          (try
            (let [result (runner/migrate! storage {:ip-hmac-key fixed-key} 3)]
              (is (contains? #{:upgraded :installed} result)))

            (let [snap (protocol/snapshot storage)]
              (testing ":tuple/ip is fully retracted from every entity"
                (let [leftover (protocol/q storage snap
                                           '[:find ?e ?ip
                                             :where [?e :tuple/ip ?ip]]
                                           [])]
                  (is (empty? leftover))))

              (testing "each seeded IP now has a corresponding
                        :tuple/ip-hash matching the expected HMAC hex"
                (doseq [ip ips]
                  (let [expected (ip-hmac/hmac-ip-hex fixed-key ip)
                        found    (protocol/q storage snap
                                             '[:find ?e
                                               :in $ ?h
                                               :where [?e :tuple/ip-hash ?h]]
                                             [expected])]
                    (is (= 1 (count found))
                        (str "expected exactly one tuple for IP " ip)))))

              (testing "schema-version is now 3"
                (let [v (->> (protocol/q storage snap
                                         '[:find [?v ...]
                                           :where [_ :schema/version ?v]]
                                         [])
                             sort last)]
                  (is (= 3 v)))))
            (finally
              (protocol/close storage))))
        (finally
          (delete-recursively dir))))))

(deftest v2-to-v3-migration-is-idempotent
  (testing "Re-running the migration on a v3 store is a no-op: it
            returns :ok and does not alter any tuple."
    (let [dir  (temp-dir)
          path (.toString dir)]
      (try
        (seed-v2-store! path ["203.0.113.42"])
        (let [storage (dtlv/open path)]
          (try
            (runner/migrate! storage {:ip-hmac-key fixed-key} 3)
            (let [snap1   (protocol/snapshot storage)
                  hashes1 (->> (protocol/q storage snap1
                                           '[:find [?h ...]
                                             :where [_ :tuple/ip-hash ?h]]
                                           [])
                               set)
                  result2 (runner/migrate! storage {:ip-hmac-key fixed-key} 3)
                  snap2   (protocol/snapshot storage)
                  hashes2 (->> (protocol/q storage snap2
                                           '[:find [?h ...]
                                             :where [_ :tuple/ip-hash ?h]]
                                           [])
                               set)]
              (is (= :ok result2))
              (is (= hashes1 hashes2)))
            (finally
              (protocol/close storage))))
        (finally
          (delete-recursively dir))))))

(deftest v2-to-v3-migration-rejects-missing-key
  (testing "If the migration runs with no :ip-hmac-key in ctx, it
            throws — refusing to silently leave the store half-migrated."
    (let [dir  (temp-dir)
          path (.toString dir)]
      (try
        (seed-v2-store! path ["203.0.113.99"])
        (let [storage (dtlv/open path)]
          (try
            (is (thrown? clojure.lang.ExceptionInfo
                         (runner/migrate! storage {} 3)))
            (finally
              (protocol/close storage))))
        (finally
          (delete-recursively dir))))))

(deftest v2-to-v3-migration-batches-large-stores
  (testing "Seed > batch boundary tuples to exercise the batched loop.
            Batch size is 1000; we use 1050 to ensure two passes."
    (let [dir  (temp-dir)
          path (.toString dir)
          n    1050
          ips  (map #(str "203.0.113." (mod % 256)) (range n))]
      (try
        (seed-v2-store! path ips)
        (let [storage (dtlv/open path)]
          (try
            (runner/migrate! storage {:ip-hmac-key fixed-key} 3)
            (let [snap   (protocol/snapshot storage)
                  hashed (->> (protocol/q storage snap
                                          '[:find ?e
                                            :where [?e :tuple/ip-hash _]]
                                          [])
                              count)
                  legacy (->> (protocol/q storage snap
                                          '[:find ?e
                                            :where [?e :tuple/ip _]]
                                          [])
                              count)]
              (is (= n hashed))
              (is (zero? legacy)))
            (finally
              (protocol/close storage))))
        (finally
          (delete-recursively dir))))))

(deftest v3-to-v4-migration-adds-bucket-scope
  (testing "v3→v4 is additive: stamps version 4, no data rewrite, and the
            new :bucket/scope attribute becomes writable (class buckets)."
    (let [dir  (temp-dir)
          path (.toString dir)]
      (try
        ;; Seed a v3 store: legacy v2 fixture, then migrate up to v3.
        (seed-v2-store! path ["203.0.113.7"])
        (let [storage (dtlv/open path)]
          (try
            (runner/migrate! storage {:ip-hmac-key fixed-key} 3)
            (let [result (runner/migrate! storage {} 4)]
              (is (= :upgraded result))
              (testing "schema-version is now 4"
                (let [v (->> (protocol/q storage (protocol/snapshot storage)
                                         '[:find [?v ...]
                                           :where [_ :schema/version ?v]] [])
                             sort last)]
                  (is (= 4 v))))
              (testing "a class bucket (scope :class, no :bucket/identity) writes cleanly"
                (protocol/transact! storage
                                    [{:bucket/key            "tier:anonymous|1m"
                                      :bucket/window         :1m
                                      :bucket/scope          :class
                                      :bucket/tokens         1.0
                                      :bucket/last-refill-ms 0}])
                (let [scope (->> (protocol/q storage (protocol/snapshot storage)
                                             '[:find [?s ...]
                                               :where
                                               [?b :bucket/key "tier:anonymous|1m"]
                                               [?b :bucket/scope ?s]] [])
                                 first)]
                  (is (= :class scope))))
              (testing "re-running v3→v4 is idempotent (:ok)"
                (is (= :ok (runner/migrate! storage {} 4)))))
            (finally
              (protocol/close storage))))
        (finally
          (delete-recursively dir))))))

(deftest v4-to-v5-migration-adds-trust-sketch
  (testing "v4→v5 is additive: stamps version 5, no data rewrite, and the
            new spaced-continuity sketch attrs become writable."
    (let [dir  (temp-dir)
          path (.toString dir)]
      (try
        ;; Seed a v4 store: legacy v2 fixture, then migrate up through v4.
        (seed-v2-store! path ["203.0.113.9"])
        (let [storage (dtlv/open path)]
          (try
            (runner/migrate! storage {:ip-hmac-key fixed-key} 4)
            (let [result (runner/migrate! storage {} 5)]
              (is (= :upgraded result))
              (testing "schema-version is now 5"
                (let [v (->> (protocol/q storage (protocol/snapshot storage)
                                         '[:find [?v ...]
                                           :where [_ :schema/version ?v]] [])
                             sort last)]
                  (is (= 5 v))))
              (testing "an identity with the trust sketch writes cleanly"
                (protocol/transact! storage
                                    [{:identity/id              (random-uuid)
                                      :identity/clean-count     7
                                      :identity/spacing         4.2
                                      :identity/violation-count 1
                                      :identity/last-clean-at   (java.util.Date.)
                                      :identity/score           0.6}])
                (let [clean (->> (protocol/q storage (protocol/snapshot storage)
                                             '[:find [?c ...]
                                               :where [?i :identity/clean-count ?c]] [])
                                 first)]
                  (is (= 7 clean))))
              (testing "re-running v4→v5 is idempotent (:ok)"
                (is (= :ok (runner/migrate! storage {} 5)))))
            (finally
              (protocol/close storage))))
        (finally
          (delete-recursively dir))))))
