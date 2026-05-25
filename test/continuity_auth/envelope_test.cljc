(ns continuity-auth.envelope-test
  "Unit tests for the canonical signing-input codec.

  Critical invariants exercised here:
    1. canonical-bytes is byte-deterministic for identical inputs
    2. envelope ↔ wire roundtrips losslessly
    3. validation rejects malformed envelopes early
    4. uint32-be encoding/decoding inverts cleanly across the full uint32 range"
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.envelope :as env]))

;; -- byte-array helpers (platform-agnostic for tests) ----------------------

(defn- ba=
  "Compare two platform byte arrays elementwise."
  [a b]
  (let [na (env/ba-length a)
        nb (env/ba-length b)]
    (and (= na nb)
         (loop [i 0]
           (cond
             (= i na) true
             (not= (env/ba-get a i) (env/ba-get b i)) false
             :else (recur (inc i)))))))

(defn- hex
  "Lowercase hex-string of a byte array."
  [ba]
  (let [n (env/ba-length ba)]
    (loop [i 0 acc ""]
      (if (= i n)
        acc
        (let [b (env/ba-get ba i)
              h (if (< b 16)
                  (str "0" #?(:clj (Integer/toHexString b)
                              :cljs (.toString b 16)))
                  #?(:clj (Integer/toHexString b)
                     :cljs (.toString b 16)))]
          (recur (inc i) (str acc h)))))))

(defn- from-hex
  "Parse a hex string into a platform byte array."
  [s]
  (let [n   (quot (count s) 2)
        out (env/byte-array-of n)]
    (dotimes [i n]
      (let [hi (subs s (* 2 i) (+ (* 2 i) 2))
            v  #?(:clj  (Integer/parseInt hi 16)
                  :cljs (js/parseInt hi 16))]
        (env/ba-set! out i v)))
    out))

(defn- bytes-of
  "Build a byte array from a vector of ints."
  [xs]
  (let [out (env/byte-array-of (count xs))]
    (dotimes [i (count xs)]
      (env/ba-set! out i (nth xs i)))
    out))

;; -- uint32-BE encoding ----------------------------------------------------

(deftest uint32-be-encode-known-values
  (testing "zero"
    (let [out (env/byte-array-of 4)]
      (env/uint32-be! out 0 0)
      (is (= "00000000" (hex out)))))
  (testing "small"
    (let [out (env/byte-array-of 4)]
      (env/uint32-be! out 0 1)
      (is (= "00000001" (hex out)))))
  (testing "16-bit boundary"
    (let [out (env/byte-array-of 4)]
      (env/uint32-be! out 0 65536)
      (is (= "00010000" (hex out)))))
  (testing "max uint32"
    (let [out (env/byte-array-of 4)]
      (env/uint32-be! out 0 4294967295)
      (is (= "ffffffff" (hex out))))))

(deftest uint32-be-roundtrip
  (doseq [n [0 1 255 256 65535 65536 16777215 16777216 4294967294 4294967295]]
    (let [out (env/byte-array-of 4)]
      (env/uint32-be! out 0 n)
      (is (= n (env/uint32-be-read out 0)) (str "roundtrip " n)))))

(deftest uint32-be-rejects-out-of-range
  (let [out (env/byte-array-of 4)]
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                 (env/uint32-be! out 0 -1)))
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                 (env/uint32-be! out 0 4294967296)))))

;; -- canonical-bytes fixtures ----------------------------------------------

(def ^:private test-body-sha
  (from-hex "0000000000000000000000000000000000000000000000000000000000000000"))

(def ^:private test-nonce
  (from-hex "0102030405060708090a0b0c0d0e0f10"))

(def ^:private test-fp
  (from-hex "1111111111111111111111111111111111111111111111111111111111111111"))

(def ^:private test-key-id
  (from-hex "2222222222222222222222222222222222222222222222222222222222222222"))

(def ^:private test-env
  {:method        "POST"
   :path          "/v1/verify"
   :body-sha256   test-body-sha
   :ts            "2026-05-24T12:34:56.789Z"
   :nonce         test-nonce
   :fp-digest     test-fp
   :host-user-id  "alice"
   :key-id        test-key-id})

(deftest canonical-bytes-deterministic
  (let [a (env/canonical-bytes test-env)
        b (env/canonical-bytes test-env)]
    (is (ba= a b))
    (is (= (hex a) (hex b)))))

(deftest canonical-bytes-known-prefix
  (testing "starts with the literal version tag 'FPL2\\n'"
    (let [bs (env/canonical-bytes test-env)]
      (is (= 0x46 (env/ba-get bs 0))) ; F
      (is (= 0x50 (env/ba-get bs 1))) ; P
      (is (= 0x4c (env/ba-get bs 2))) ; L
      (is (= 0x32 (env/ba-get bs 3))) ; 2
      (is (= 0x0a (env/ba-get bs 4))))) ; \n
  (testing "first uint32 after tag is len(method)"
    (let [bs (env/canonical-bytes test-env)]
      (is (= 4 (env/uint32-be-read bs 5))) ; len("POST")
      (is (= 0x50 (env/ba-get bs 9)))      ; 'P'
      (is (= 0x4f (env/ba-get bs 10)))     ; 'O'
      (is (= 0x53 (env/ba-get bs 11)))     ; 'S'
      (is (= 0x54 (env/ba-get bs 12)))))) ; 'T'

(deftest canonical-bytes-host-user-id-empty
  (testing "missing host-user-id encodes len=0, no body bytes"
    (let [env-no-host (dissoc test-env :host-user-id)
          env-empty   (assoc test-env :host-user-id "")
          a (env/canonical-bytes env-no-host)
          b (env/canonical-bytes env-empty)]
      (is (ba= a b)
          "absent and empty host-user-id must produce identical bytes"))))

(deftest canonical-bytes-changes-with-each-field
  (testing "different method → different bytes"
    (is (not (ba= (env/canonical-bytes test-env)
                  (env/canonical-bytes (assoc test-env :method "GET"))))))
  (testing "different path → different bytes"
    (is (not (ba= (env/canonical-bytes test-env)
                  (env/canonical-bytes (assoc test-env :path "/v1/bootstrap"))))))
  (testing "different ts → different bytes"
    (is (not (ba= (env/canonical-bytes test-env)
                  (env/canonical-bytes (assoc test-env :ts "2026-05-24T12:34:57.000Z"))))))
  (testing "different host-user-id → different bytes"
    (is (not (ba= (env/canonical-bytes test-env)
                  (env/canonical-bytes (assoc test-env :host-user-id "bob")))))))

;; -- validation ------------------------------------------------------------

(deftest validate-missing-keys
  (doseq [k env/required-envelope-keys]
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                 (env/validate (dissoc test-env k)))
        (str "missing " k " must throw"))))

(deftest validate-wrong-length-fields
  (testing "body-sha256 must be 32 bytes"
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                 (env/validate (assoc test-env :body-sha256 (bytes-of [0 1 2]))))))
  (testing "nonce must be 16 bytes"
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                 (env/validate (assoc test-env :nonce (bytes-of [0]))))))
  (testing "fp-digest must be 32 bytes"
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                 (env/validate (assoc test-env :fp-digest (bytes-of (range 31)))))))
  (testing "key-id must be 32 bytes"
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                 (env/validate (assoc test-env :key-id (bytes-of [])))))))

(deftest validate-utf8-overflow
  (testing "absurd method length rejected"
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                 (env/canonical-bytes
                  (assoc test-env :method
                         (apply str (repeat 1000 "A")))))))
  (testing "absurd path length rejected"
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                 (env/canonical-bytes
                  (assoc test-env :path
                         (apply str (repeat 5000 "/"))))))))

;; -- envelope ↔ wire roundtrip --------------------------------------------

(deftest envelope-wire-roundtrip-without-signature
  (let [wire (env/envelope->wire test-env)
        env2 (env/wire->envelope wire)]
    (is (= (:method test-env)       (:method env2)))
    (is (= (:path test-env)         (:path env2)))
    (is (= (:ts test-env)           (:ts env2)))
    (is (= (:host-user-id test-env) (:host-user-id env2)))
    (is (ba= test-body-sha          (:body-sha256 env2)))
    (is (ba= test-nonce             (:nonce env2)))
    (is (ba= test-fp                (:fp-digest env2)))
    (is (ba= test-key-id            (:key-id env2)))))

(deftest envelope-wire-roundtrip-with-signature
  (let [sig  (from-hex (apply str (repeat 64 "ab")))
        env  (assoc test-env :alg :ed25519 :signature sig)
        wire (env/envelope->wire env)
        env2 (env/wire->envelope wire)]
    (is (= :ed25519 (:alg env2)))
    (is (ba= sig (:signature env2)))))

(deftest wire-version-mismatch
  (let [wire (assoc (env/envelope->wire test-env) :v "FPL999\n")]
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                 (env/wire->envelope wire)))))

(deftest wire-missing-version-rejected
  (testing "the :v tag is mandatory; absence is an error, not silent FPL1 acceptance"
    (let [wire (dissoc (env/envelope->wire test-env) :v)]
      (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs js/Error)
                   (env/wire->envelope wire))))))

;; -- base64url -------------------------------------------------------------

(deftest b64url-known-vectors
  (testing "empty"
    (is (= "" (env/b64url-encode (env/byte-array-of 0))))
    (is (zero? (env/ba-length (env/b64url-decode "")))))
  (testing "single byte"
    (is (= "AA" (env/b64url-encode (bytes-of [0]))))
    (is (ba= (bytes-of [0]) (env/b64url-decode "AA"))))
  (testing "url-safe alphabet"
    (let [bs (bytes-of [0xfb 0xff 0xff])]
      (is (= "-___" (env/b64url-encode bs)))
      (is (ba= bs (env/b64url-decode "-___"))))))
