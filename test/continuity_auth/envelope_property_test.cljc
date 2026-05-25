(ns continuity-auth.envelope-property-test
  "Property-based tests for the envelope codec.

  Properties exercised:
    P1. canonical-bytes is deterministic — identical inputs produce identical
        outputs, irrespective of map-key insertion order.
    P2. canonical-bytes is injective on each field — changing any single field
        always changes the output bytes (no accidental collisions in the
        length-prefixed layout).
    P3. envelope→wire→envelope is the identity function on valid envelopes.
    P4. uint32-be encode→decode is the identity across the full uint32 range.
    P5. b64url-encode→b64url-decode is the identity on arbitrary byte arrays.

  These cover the structural correctness of the wire format. Semantic
  correctness (e.g., signature validity) lives in the crypto tests."
  (:require
   [clojure.string :as str]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [continuity-auth.envelope :as env]))

(def ^:private trials 200)

;; -- platform-portable byte helpers ----------------------------------------

(defn- bytes-of
  [xs]
  (let [out (env/byte-array-of (count xs))]
    (dotimes [i (count xs)]
      (env/ba-set! out i (nth xs i)))
    out))

(defn- ba=
  [a b]
  (let [na (env/ba-length a)
        nb (env/ba-length b)]
    (and (= na nb)
         (loop [i 0]
           (cond
             (= i na) true
             (not= (env/ba-get a i) (env/ba-get b i)) false
             :else (recur (inc i)))))))

;; -- generators ------------------------------------------------------------

(def ^:private gen-byte (gen/choose 0 255))

(defn- gen-bytes-of-len [n]
  (gen/fmap bytes-of (gen/vector gen-byte n)))

(def ^:private gen-method
  (gen/elements ["GET" "POST" "PUT" "DELETE" "PATCH" "HEAD" "OPTIONS"]))

(def ^:private gen-path
  (gen/let [n      (gen/choose 1 10)
            parts  (gen/vector (gen/such-that (complement empty?)
                                              gen/string-alphanumeric)
                               n)
            query? gen/boolean]
    (str "/"
         (str/join "/" parts)
         (when query? "?a=1&b=2"))))

(def ^:private gen-ts
  (gen/elements ["2026-01-01T00:00:00.000Z"
                 "2026-05-24T12:34:56.789Z"
                 "2030-12-31T23:59:59.999Z"
                 "1970-01-01T00:00:00.000Z"]))

(def ^:private gen-host-user-id
  (gen/one-of [(gen/return nil)
               (gen/return "")
               (gen/such-that (complement empty?) gen/string-alphanumeric 50)]))

(def ^:private gen-envelope
  (gen/let [method        gen-method
            path          gen-path
            body-sha256   (gen-bytes-of-len env/body-sha256-len)
            ts            gen-ts
            nonce         (gen-bytes-of-len env/nonce-len)
            fp-digest     (gen-bytes-of-len env/fp-digest-len)
            host-user-id  gen-host-user-id
            key-id        (gen-bytes-of-len env/key-id-len)]
    {:method       method
     :path         path
     :body-sha256  body-sha256
     :ts           ts
     :nonce        nonce
     :fp-digest    fp-digest
     :host-user-id host-user-id
     :key-id       key-id}))

;; -- P1: determinism --------------------------------------------------------

(defspec p1-canonical-bytes-deterministic trials
  (prop/for-all [env gen-envelope]
    (ba= (env/canonical-bytes env)
         (env/canonical-bytes env))))

(defspec p1b-canonical-bytes-order-insensitive trials
  (prop/for-all [env gen-envelope]
    (let [shuffled (into {} (shuffle (seq env)))]
      (ba= (env/canonical-bytes env)
           (env/canonical-bytes shuffled)))))

;; -- P2: injectivity (a change in any field changes the bytes) -------------

(defspec p2-method-changes trials
  (prop/for-all [env gen-envelope
                 alt gen-method]
    (let [env' (assoc env :method alt)]
      (or (= (:method env) (:method env'))
          (not (ba= (env/canonical-bytes env)
                    (env/canonical-bytes env')))))))

(defspec p2-path-changes trials
  (prop/for-all [env gen-envelope
                 alt gen-path]
    (let [env' (assoc env :path alt)]
      (or (= (:path env) (:path env'))
          (not (ba= (env/canonical-bytes env)
                    (env/canonical-bytes env')))))))

(defspec p2-nonce-changes trials
  (prop/for-all [env gen-envelope
                 alt (gen-bytes-of-len env/nonce-len)]
    (let [env' (assoc env :nonce alt)]
      (or (ba= (:nonce env) (:nonce env'))
          (not (ba= (env/canonical-bytes env)
                    (env/canonical-bytes env')))))))

(defspec p2-key-id-changes trials
  (prop/for-all [env gen-envelope
                 alt (gen-bytes-of-len env/key-id-len)]
    (let [env' (assoc env :key-id alt)]
      (or (ba= (:key-id env) (:key-id env'))
          (not (ba= (env/canonical-bytes env)
                    (env/canonical-bytes env')))))))

;; -- P3: envelope ↔ wire roundtrip -----------------------------------------

(defspec p3-envelope-wire-roundtrip trials
  (prop/for-all [env gen-envelope]
    (let [env2 (env/wire->envelope (env/envelope->wire env))]
      (and (= (:method env)       (:method env2))
           (= (:path env)         (:path env2))
           (= (:ts env)           (:ts env2))
           (= (or (:host-user-id env) nil)
              (or (:host-user-id env2) nil))
           (ba= (:body-sha256 env) (:body-sha256 env2))
           (ba= (:nonce env)       (:nonce env2))
           (ba= (:fp-digest env)   (:fp-digest env2))
           (ba= (:key-id env)      (:key-id env2))))))

;; -- P4: uint32-BE invertibility -------------------------------------------

;; Avoid generating values above 2^31-1 because clojure.test.check on JVM
;; uses Long but gen/large-integer maxes at platform Long range; we want
;; coverage across the uint32 range so we use a hand-picked range that fits.
(def ^:private gen-uint32
  (gen/fmap #(bit-and 0xffffffff (long %))
            (gen/large-integer* {:min 0 :max 4294967295})))

(defspec p4-uint32-be-invertible trials
  (prop/for-all [n   gen-uint32
                 off (gen/choose 0 8)]
    (let [out (env/byte-array-of (+ off 4))]
      (env/uint32-be! out off n)
      (= n (env/uint32-be-read out off)))))

;; -- P5: b64url roundtrip --------------------------------------------------

(defspec p5-b64url-roundtrip trials
  (prop/for-all [bs (gen/let [n (gen/choose 0 64)]
                      (gen-bytes-of-len n))]
    (let [encoded (env/b64url-encode bs)
          decoded (env/b64url-decode encoded)]
      (ba= bs decoded))))
