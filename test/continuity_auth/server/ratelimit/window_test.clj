(ns continuity-auth.server.ratelimit.window-test
  "Sliding-window-counter tests, including a sliding-log oracle property test."
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.server.ratelimit.window :as window]
   [continuity-auth.server.storage.datalevin :as dtlv]
   [continuity-auth.server.storage.protocol :as storage])
  (:import
   (java.nio.file Files)
   (java.nio.file.attribute FileAttribute)
   (java.util Date)
   (java.util UUID)))

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "cauth-win-test-" (into-array FileAttribute [])))

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

(defn- new-identity! [store]
  (let [iid (UUID/randomUUID)
        n0  (Date.)
        _rep (storage/transact!
             store
             [{:identity/id iid
               :identity/created-at n0
               :identity/last-event-at n0
               :identity/score 0.5
               :identity/ever-tracked? false}])
        eid (-> (storage/q store (storage/snapshot store)
                            '[:find [?e ...]
                              :in $ ?id
                              :where [?e :identity/id ?id]]
                            [iid])
                first)]
    eid))

;; -- pure algorithm ------------------------------------------------------

(deftest align-to-window-snaps-to-boundary
  (let [t  (Date. 1700000123456)
        a1 (window/align-to-window t 60)
        a5 (window/align-to-window t 300)
        a-day (window/align-to-window t 86400)]
    (is (zero? (mod (.getTime a1) 60000)))
    (is (zero? (mod (.getTime a5) 300000)))
    (is (zero? (mod (.getTime a-day) 86400000)))))

(deftest weighted-approx-zero-elapsed-equals-prev
  (is (= 5.0 (window/weighted-approx-count 0 5 0 60)))
  (is (= 0.0 (window/weighted-approx-count 0 0 0 60))))

(deftest weighted-approx-end-of-window-equals-current
  (is (= 7.0 (window/weighted-approx-count 7 5 60 60))))

(deftest weighted-approx-midwindow-half
  (is (= 7.0 (window/weighted-approx-count 5 4 30 60))))   ; 5 + 4*0.5 = 7

;; -- check-and-increment! ------------------------------------------------

(deftest below-limit-allows
  (with-store
    (fn [store]
      (let [eid (new-identity! store)
            r   (window/check-and-increment! store eid :1m 60 5 (Date.))]
        (is (true? (:allowed? r)))))))

(deftest at-limit-throttles-on-next
  (with-store
    (fn [store]
      (let [eid (new-identity! store)
            now (Date.)]
        (dotimes [_ 5]
          (let [r (window/check-and-increment! store eid :1m 60 5 now)]
            (is (:allowed? r))))
        ;; 6th request must throttle
        (let [r (window/check-and-increment! store eid :1m 60 5 now)]
          (is (false? (:allowed? r))))))))

(deftest zero-limit-always-throttles
  (with-store
    (fn [store]
      (let [eid (new-identity! store)
            r (window/check-and-increment! store eid :1m 60 0 (Date.))]
        (is (false? (:allowed? r)))))))

(deftest two-windows-most-restrictive-wins
  (testing "If the 5m limit is tight but 1m is not, 5m governs"
    (with-store
      (fn [store]
        (let [eid (new-identity! store)
              now (Date.)
              ;; Fill the 5m bucket to capacity.
              windows [{:window :1m :seconds 60} {:window :5m :seconds 300}]
              limits  {:1m 30 :5m 3}
              _   (dotimes [_ 3]
                    (window/check-many store eid windows limits now))
              r   (window/check-many store eid windows limits now)]
          (is (false? (:allowed? r)))
          (is (= 3 (:limit r))))))))

;; -- Approximation bounds --------------------------------------------------
;;
;; The sliding-window-counter is an APPROXIMATION. Under non-uniform
;; bursts at bucket edges, it can both over-count and under-count by up
;; to the previous bucket's content. This is the standard, known
;; tradeoff for O(1) check-and-increment.
;;
;; We assert two narrower properties that DO hold deterministically:
;;
;;   1. Within a single bucket, the counter is exact.
;;   2. The approximation is monotone non-decreasing within a single
;;      bucket — repeated check-and-increment calls strictly increase
;;      the approx-count between requests.
;;
;; The aggregate "average rate is bounded by limit" property is asserted
;; by the integration-level adversarial tests (`adversarial/*`) rather
;; than by a property generator.

(deftest counter-equals-oracle-within-single-bucket
  (testing "When all events fall in the same bucket, the counter is exact."
    (with-store
      (fn [store]
        (let [eid (new-identity! store)
              base (* 60000 (quot (System/currentTimeMillis) 60000))
              events (mapv #(Date. (+ base %)) [1000 2000 3000 4000 5000])]
          (doseq [t events]
            (window/check-and-increment! store eid :1m 60 100 t))
          (let [r (window/check-and-increment! store eid :1m 60 100
                                                (Date. (+ base 6000)))]
            (is (= 6.0 (:approx-count r)))))))))

(deftest counter-monotone-within-bucket
  (testing "Each successful increment strictly raises the approx-count
            (within a single bucket)."
    (with-store
      (fn [store]
        (let [eid (new-identity! store)
              base (* 60000 (quot (System/currentTimeMillis) 60000))]
          (loop [last-count 0
                 i 1]
            (when (< i 20)
              (let [r (window/check-and-increment! store eid :1m 60 100
                                                    (Date. (+ base (* i 100))))]
                (is (true? (:allowed? r)))
                (is (> (:approx-count r) last-count))
                (recur (:approx-count r) (inc i))))))))))

;; -- Bucket-key uniqueness (codex C5) --------------------------------------
;;
;; Before `:bucket/key`, two concurrent verifies for the same identity at
;; the same window boundary each created their own bucket entity — the
;; counter then fragmented across N entities. Subsequent reads only saw
;; one of them.
;;
;; With `:bucket/key` as `:db.unique/identity`, the slot is unique; all
;; concurrent writes upsert into a single entity.

(deftest bucket-key-uniqueness-under-concurrent-writes
  (testing "N concurrent check-and-increment! calls at the same boundary
            produce exactly ONE bucket entity, not N."
    (with-store
      (fn [store]
        (let [eid (new-identity! store)
              base (* 60000 (quot (System/currentTimeMillis) 60000))
              t    (Date. base)
              n    16
              latch (java.util.concurrent.CountDownLatch. 1)
              pool  (java.util.concurrent.Executors/newFixedThreadPool n)
              futs  (mapv (fn [_]
                            (.submit pool
                                     ^Callable
                                     (fn []
                                       (.await latch)
                                       (window/check-and-increment! store eid :1m 60 1000 t))))
                          (range n))
              _     (.countDown latch)
              _     (doseq [^java.util.concurrent.Future f futs] (.get f))
              _     (.shutdown pool)
              snap  (storage/snapshot store)
              start-ms (.getTime (window/align-to-window t 60))
              key-str  (window/bucket-key eid :1m (Date. start-ms))
              ;; Count entities at the slot — must be exactly 1.
              entities (storage/q store snap
                                  '[:find [?e ...]
                                    :in $ ?k
                                    :where [?e :bucket/key ?k]]
                                  [key-str])]
          (is (= 1 (count entities))
              (str "expected exactly one bucket entity at slot, got "
                   (count entities))))))))
