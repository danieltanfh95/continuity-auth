(ns continuity-auth.server.ratelimit.window-test
  "Token-bucket-per-window rate-limiter tests."
  (:require
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
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
        _ (storage/transact!
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

;; -- pure-fn unit tests --------------------------------------------------

(deftest leak-rate-derives-capacity-over-seconds
  (is (= 0.5 (window/leak-rate-per-sec 30 60)))     ; 30/60 = 0.5/sec
  (is (= 1.0 (window/leak-rate-per-sec 60 60)))
  (is (= 0.0 (window/leak-rate-per-sec 0 60)))      ; capacity 0 → no leak
  (is (= 0.0 (window/leak-rate-per-sec 30 0))))     ; window 0 → guard

(deftest refill-caps-at-capacity
  (testing "Refill is bounded above by capacity, never overshoots"
    ;; capacity 10, leak-rate 1/sec, idle 1 hour → still capped at 10.
    (is (= 10.0 (window/refill 5.0 0 10 1.0 (* 60 60 1000))))))

(deftest refill-additive-when-below-cap
  (testing "Refill adds elapsed-ms * leak / 1000 when below capacity"
    ;; 5 tokens + 2 seconds * 1/sec = 7 tokens (< capacity 10).
    (is (= 7.0 (window/refill 5.0 0 10 1.0 2000)))))

(deftest refill-floor-at-zero-elapsed
  (testing "Zero elapsed-ms refills nothing"
    (is (= 3.0 (window/refill 3.0 1000 10 1.0 1000)))))

(deftest decision-fresh-bucket-allowed
  (testing "First request to a fresh bucket is allowed; tokens drop by 1"
    (let [d (window/decision nil nil 10 1.0 60000 1000)]
      (is (true? (:allowed? d)))
      (is (zero? (:retry-after-ms d)))
      (is (= 9.0 (:new-tokens d))))))

(deftest decision-empty-bucket-denied
  (testing "Empty bucket denies; retry derived from leak rate"
    ;; tokens=0, no time elapsed, capacity=10, leak=1/sec.
    ;; Need 1 token; leak 1/sec → 1000 ms wait.
    (let [d (window/decision 0.0 1000 10 1.0 60000 1000)]
      (is (false? (:allowed? d)))
      (is (= 1000 (:retry-after-ms d))))))

(deftest decision-zero-capacity-always-denies
  (testing "Capacity 0 returns deny with retry = window-ms"
    (let [d (window/decision nil nil 0 0.0 60000 1000)]
      (is (false? (:allowed? d)))
      (is (= 60000 (:retry-after-ms d))))))

(deftest decision-fractional-refill-rounds-up
  (testing "Retry-after-ms rounds up so polled clients don't beat the leak"
    ;; tokens 0.3, leak 1/sec → need 0.7 more tokens → 700 ms ceil.
    (let [d (window/decision 0.3 0 10 1.0 60000 0)]
      (is (false? (:allowed? d)))
      (is (= 700 (:retry-after-ms d))))))

;; -- consume-token! end-to-end (with store) ------------------------------

(deftest below-capacity-allows
  (with-store
    (fn [store]
      (let [eid (new-identity! store)
            r   (window/consume-token! store eid :1m 60 5 (Date.))]
        (is (true? (:allowed? r)))
        (is (= 4.0 (:tokens-after r)))))))

(deftest burst-to-capacity-then-throttle
  (with-store
    (fn [store]
      (let [eid (new-identity! store)
            now (Date.)]
        (dotimes [_ 5]
          (let [r (window/consume-token! store eid :1m 60 5 now)]
            (is (:allowed? r))))
        ;; 6th request must throttle.
        (let [r (window/consume-token! store eid :1m 60 5 now)]
          (is (false? (:allowed? r)))
          ;; Leak-rate is 5/60 ≈ 0.0833/sec → one token in ~12000 ms.
          ;; Need (1 - 0) / 0.0833 = 12000 ms.
          (is (= 12000 (:retry-after-ms r))))))))

(deftest zero-capacity-always-throttles
  (with-store
    (fn [store]
      (let [eid (new-identity! store)
            r   (window/consume-token! store eid :1m 60 0 (Date.))]
        (is (false? (:allowed? r)))
        ;; Zero capacity → retry = window-ms (60000).
        (is (= 60000 (:retry-after-ms r)))))))

(deftest refill-recovers-after-idle
  (testing "After waiting one leak-time, a denied caller becomes allowed"
    (with-store
      (fn [store]
        (let [eid (new-identity! store)
              t0  (Date. 0)
              ;; capacity 1, leak 1/sec.
              _   (window/consume-token! store eid :1m 1 1 t0)
              ;; Immediately retry → denied.
              r1  (window/consume-token! store eid :1m 1 1 t0)
              ;; 1 second later → token leaked back; allowed.
              r2  (window/consume-token! store eid :1m 1 1 (Date. 1000))]
          (is (false? (:allowed? r1)))
          (is (true? (:allowed? r2))))))))

;; -- check-many (multi-window) -------------------------------------------

(deftest two-windows-most-restrictive-wins
  (testing "If the 5m capacity is tight but 1m is not, 5m governs"
    (with-store
      (fn [store]
        (let [eid (new-identity! store)
              now (Date.)
              windows [{:window :1m :seconds 60} {:window :5m :seconds 300}]
              limits  {:1m 30 :5m 3}]
          ;; Exhaust the :5m bucket (capacity 3).
          (dotimes [_ 3]
            (let [r (window/check-many store eid windows limits now)]
              (is (true? (:allowed? r)))))
          ;; 4th must throttle on :5m.
          (let [r (window/check-many store eid windows limits now)]
            (is (false? (:allowed? r)))
            (is (= 3 (:limit r)))))))))

(deftest check-many-allow-leaves-all-buckets-with-one-less-token
  (testing "All windows' buckets are consumed on allow"
    (with-store
      (fn [store]
        (let [eid (new-identity! store)
              now (Date.)
              windows [{:window :1m :seconds 60} {:window :5m :seconds 300}]
              limits  {:1m 10 :5m 100}]
          (window/check-many store eid windows limits now)
          ;; After one allowed request, each bucket should hold capacity - 1.
          (let [snap (storage/snapshot store)
                b1m (storage/pull store snap
                                   [:bucket/key (window/bucket-key eid :1m)]
                                   [:bucket/tokens])
                b5m (storage/pull store snap
                                   [:bucket/key (window/bucket-key eid :5m)]
                                   [:bucket/tokens])]
            (is (= 9.0 (:bucket/tokens b1m)))
            (is (= 99.0 (:bucket/tokens b5m)))))))))

(deftest check-many-deny-does-not-consume
  (testing "When any window denies, no bucket is consumed"
    (with-store
      (fn [store]
        (let [eid (new-identity! store)
              now (Date.)
              windows [{:window :1m :seconds 60} {:window :5m :seconds 300}]
              limits  {:1m 10 :5m 0}]   ; :5m always throttles
          (window/check-many store eid windows limits now)
          (let [snap (storage/snapshot store)
                b1m (storage/pull store snap
                                   [:bucket/key (window/bucket-key eid :1m)]
                                   [:bucket/tokens])]
            ;; :1m bucket should be nil (no entity written) because :5m denied.
            (is (nil? (:bucket/tokens b1m)))))))))

;; -- normalize-cell ------------------------------------------------------

(deftest normalize-cell-bare-derives-leak
  (testing "A bare number is capacity; leak derived as capacity/window-seconds"
    (is (= {:capacity 30 :leak-per-sec 0.5} (window/normalize-cell 30 60)))
    (is (= {:capacity 0  :leak-per-sec 0.0} (window/normalize-cell 0 60)))))

(deftest normalize-cell-map-passes-explicit-leak
  (testing "A map with :leak-per-sec is used verbatim (independent of capacity)"
    (is (= {:capacity 10 :leak-per-sec 5.0}
           (window/normalize-cell {:capacity 10 :leak-per-sec 5.0} 60)))))

(deftest normalize-cell-map-without-leak-derives
  (testing "A map lacking :leak-per-sec derives it from capacity/window-seconds"
    (is (= {:capacity 120 :leak-per-sec 0.4}
           (window/normalize-cell {:capacity 120} 300)))))

(deftest normalize-cell-idempotent
  (testing "Normalizing an already-normalized cell round-trips"
    (let [n (window/normalize-cell 30 60)]
      (is (= n (window/normalize-cell n 60))))))

;; -- class-bucket keys + specs -------------------------------------------

(deftest class-bucket-key-prefixed
  (is (= "tier:anonymous|1m" (window/class-bucket-key :anonymous :1m)))
  (testing "class keys never collide with per-caller (numeric-prefixed) keys"
    (is (not= (window/class-bucket-key :anonymous :1m)
              (window/bucket-key 1 :1m)))))

(deftest class-specs-empty-when-no-cap
  (let [windows [{:window :1m :seconds 60}]]
    (is (= [] (window/class-specs :tracked windows {})))
    (is (= [] (window/class-specs :tracked windows nil)))
    (is (= [] (window/class-specs :tracked windows {:anonymous {:1m 2000}})))))

(deftest class-specs-only-configured-windows
  (testing "Only windows with a configured cap produce specs"
    (let [windows [{:window :1m :seconds 60} {:window :5m :seconds 300}]
          specs   (window/class-specs :anonymous windows {:anonymous {:1m 2000}})]
      (is (= 1 (count specs)))
      (is (= :class (:scope (first specs))))
      (is (= :anonymous (:tier (first specs))))
      (is (nil? (:identity-eid (first specs))))
      (is (= "tier:anonymous|1m" (:bucket-key (first specs))))
      (is (= 2000 (:capacity (first specs)))))))

;; -- check! with class caps (back-pressure) ------------------------------

(def ^:private win-1m [{:window :1m :seconds 60}])

(defn- anon-check!
  "Per-caller (high) + class cap for the anonymous tier on :1m."
  [store eid class-cap now]
  (window/check! store
                 (into (window/identity-specs eid win-1m {:1m 100})
                       (window/class-specs :anonymous win-1m
                                           {:anonymous {:1m class-cap}}))
                 now))

(deftest class-cap-throttles-aggregate-across-identities
  (testing "A class cap denies once the shared tier bucket is exhausted,
            even though no single caller hit its own budget"
    (with-store
      (fn [store]
        (let [id1 (new-identity! store)
              id2 (new-identity! store)
              now (Date.)]
          ;; class cap 3; id1 spends all three (caller budget is 100).
          (dotimes [_ 3]
            (is (:allowed? (anon-check! store id1 3 now))))
          ;; id2's first-ever call is denied by the CLASS bucket.
          (let [r (anon-check! store id2 3 now)]
            (is (false? (:allowed? r)))
            (is (= :class (:scope r)))
            ;; class deny must NOT consume id2's per-caller bucket.
            (let [snap (storage/snapshot store)
                  b    (storage/pull store snap
                                     [:bucket/key (window/bucket-key id2 :1m)]
                                     [:bucket/tokens])]
              (is (nil? (:bucket/tokens b))))))))))

(deftest caller-deny-tagged-identity-scope
  (testing "A per-caller bucket denial is tagged :identity, not :class"
    (with-store
      (fn [store]
        (let [eid (new-identity! store)
              now (Date.)
              ;; caller :1m capacity 1, no class cap.
              specs (window/identity-specs eid win-1m {:1m 1})]
          (is (:allowed? (window/check! store specs now)))
          (let [r (window/check! store specs now)]
            (is (false? (:allowed? r)))
            (is (= :identity (:scope r)))))))))

(deftest check!-allow-writes-both-caller-and-class-buckets
  (with-store
    (fn [store]
      (let [eid (new-identity! store)
            now (Date.)]
        (is (:allowed? (anon-check! store eid 3 now)))
        (let [snap  (storage/snapshot store)
              caller (storage/pull store snap
                                   [:bucket/key (window/bucket-key eid :1m)]
                                   [:bucket/tokens :bucket/scope])
              klass  (storage/pull store snap
                                   [:bucket/key (window/class-bucket-key :anonymous :1m)]
                                   [:bucket/tokens :bucket/scope :bucket/identity])]
          (is (= 99.0 (:bucket/tokens caller)))
          (is (= :identity (:bucket/scope caller)))
          (is (= 2.0 (:bucket/tokens klass)))
          (is (= :class (:bucket/scope klass)))
          (testing "class bucket carries no :bucket/identity"
            (is (nil? (:bucket/identity klass)))))))))

(deftest independent-leak-rate-from-map-cell
  (testing "A {:capacity :leak-per-sec} cell uses the explicit leak, not
            capacity/window-seconds"
    (with-store
      (fn [store]
        (let [eid   (new-identity! store)
              now   (Date.)
              ;; capacity 10, leak 5/sec (NOT 10/60). Burst 10, 11th denied.
              specs (window/identity-specs eid win-1m
                                           {:1m {:capacity 10 :leak-per-sec 5.0}})]
          (dotimes [_ 10]
            (is (:allowed? (window/check! store specs now))))
          (let [r (window/check! store specs now)]
            (is (false? (:allowed? r)))
            ;; one token at 5/sec = 200 ms (vs ~6000 ms if leak were derived).
            (is (= 200 (:retry-after-ms r)))))))))

;; -- property tests ------------------------------------------------------
;;
;; Invariants over a sequence of consume calls with arbitrary capacity,
;; leak-rate, and time gaps:
;;   - tokens never exceed capacity
;;   - tokens never go below 0
;;   - allowed? ⇒ retry-after-ms = 0
;;   - !allowed? ⇒ retry-after-ms > 0   (for positive capacity)

(defspec p-tokens-never-exceed-capacity 100
  (prop/for-all
   [tokens-before (gen/double* {:min 0.0 :max 100.0 :NaN? false :infinite? false})
    elapsed-ms    (gen/large-integer* {:min 0 :max 100000000})
    capacity      (gen/choose 1 100)
    leak-num      (gen/double* {:min 0.01 :max 100.0 :NaN? false :infinite? false})]
   (let [after (window/refill tokens-before 0 capacity leak-num elapsed-ms)]
     (<= after (double capacity)))))

(defspec p-tokens-never-negative 100
  (prop/for-all
   [tokens-before (gen/double* {:min 0.0 :max 100.0 :NaN? false :infinite? false})
    capacity      (gen/choose 1 100)
    leak-num      (gen/double* {:min 0.01 :max 100.0 :NaN? false :infinite? false})]
   (let [d (window/decision tokens-before 0 capacity leak-num 60000 0)]
     (>= (:new-tokens d) 0.0))))

(defspec p-allowed-iff-retry-zero 100
  (prop/for-all
   [tokens-before (gen/double* {:min 0.0 :max 100.0 :NaN? false :infinite? false})
    capacity      (gen/choose 1 100)
    leak-num      (gen/double* {:min 0.01 :max 100.0 :NaN? false :infinite? false})]
   (let [d (window/decision tokens-before 0 capacity leak-num 60000 0)]
     (if (:allowed? d)
       (zero? (:retry-after-ms d))
       (pos? (:retry-after-ms d))))))

(defspec p-zero-capacity-always-denies 50
  (prop/for-all
   [tokens-before (gen/double* {:min 0.0 :max 100.0 :NaN? false :infinite? false})
    elapsed-ms    (gen/large-integer* {:min 0 :max 100000000})]
   (let [d (window/decision tokens-before 0 0 0.0 60000 elapsed-ms)]
     (false? (:allowed? d)))))

;; -- Bucket-key uniqueness under concurrent writes -----------------------
;;
;; Token-bucket keys are now stable across time per (identity, window).
;; N concurrent writes at the same slot must upsert into a single entity,
;; not fragment into N.

(deftest bucket-key-uniqueness-under-concurrent-writes
  (testing "N concurrent consume-token! calls produce exactly ONE bucket
            entity, not N."
    (with-store
      (fn [store]
        (let [eid  (new-identity! store)
              t    (Date.)
              n    16
              latch (java.util.concurrent.CountDownLatch. 1)
              pool  (java.util.concurrent.Executors/newFixedThreadPool n)
              futs  (mapv (fn [_]
                            (.submit pool
                                     ^Callable
                                     (fn []
                                       (.await latch)
                                       (window/consume-token! store eid :1m 60 1000 t))))
                          (range n))
              _     (.countDown latch)
              _     (doseq [^java.util.concurrent.Future f futs] (.get f))
              _     (.shutdown pool)
              snap  (storage/snapshot store)
              key-str  (window/bucket-key eid :1m)
              ;; Count entities at the slot — must be exactly 1.
              entities (storage/q store snap
                                  '[:find [?e ...]
                                    :in $ ?k
                                    :where [?e :bucket/key ?k]]
                                  [key-str])]
          (is (= 1 (count entities))
              (str "expected exactly one bucket entity at slot, got "
                   (count entities))))))))
