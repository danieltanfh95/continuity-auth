(ns continuity-auth.client.envelope-parity-test
  "Cross-platform parity for the envelope codec.

  The fixture below is computed by the JVM tests (see
  envelope_test.cljc fixture `test-env`) and is the SAME envelope. If
  the cljs side produces different canonical bytes, the signatures
  would not verify on the server — these tests are the contract.

  Hex of canonical bytes produced by JVM for the fixture envelope:
    - method=POST, path=/v1/verify, ts=2026-05-24T12:34:56.789Z,
      host-user-id=alice, fixed body-sha/nonce/fp/key-id below.
  We compare hex on both platforms — the cljs result MUST match."
  (:require
   [cljs.test :refer-macros [deftest is]]
   [continuity-auth.envelope :as envelope]))

(defn- bytes-of [xs]
  (let [out (js/Uint8Array. (count xs))]
    (dotimes [i (count xs)] (aset out i (nth xs i)))
    out))

(defn- from-hex [s]
  (let [n   (quot (count s) 2)
        out (js/Uint8Array. n)]
    (dotimes [i n]
      (let [hi (subs s (* 2 i) (+ (* 2 i) 2))
            v  (js/parseInt hi 16)]
        (aset out i v)))
    out))

(defn- to-hex [ba]
  (let [n (.-length ba)]
    (loop [i 0 acc ""]
      (if (= i n)
        acc
        (let [b (aget ba i)
              h (if (< b 16)
                  (str "0" (.toString b 16))
                  (.toString b 16))]
          (recur (inc i) (str acc h)))))))

(def ^:private fixture-env
  {:method        "POST"
   :path          "/v1/verify"
   :body-sha256   (from-hex "0000000000000000000000000000000000000000000000000000000000000000")
   :ts            "2026-05-24T12:34:56.789Z"
   :nonce         (from-hex "0102030405060708090a0b0c0d0e0f10")
   :fp-digest     (from-hex "1111111111111111111111111111111111111111111111111111111111111111")
   :host-user-id  "alice"
   :key-id        (from-hex "2222222222222222222222222222222222222222222222222222222222222222")})

(deftest canonical-bytes-version-tag-prefix
  (let [bs (envelope/canonical-bytes fixture-env)]
    (is (= 0x46 (aget bs 0)) "F")
    (is (= 0x50 (aget bs 1)) "P")
    (is (= 0x4c (aget bs 2)) "L")
    (is (= 0x32 (aget bs 3)) "2")
    (is (= 0x0a (aget bs 4)) "newline")))

(deftest canonical-bytes-method-length-prefix
  (let [bs (envelope/canonical-bytes fixture-env)]
    ;; uint32-BE for "POST" length = 4
    (is (= 0 (aget bs 5)))
    (is (= 0 (aget bs 6)))
    (is (= 0 (aget bs 7)))
    (is (= 4 (aget bs 8)))
    (is (= 0x50 (aget bs 9)) "P")
    (is (= 0x4f (aget bs 10)) "O")
    (is (= 0x53 (aget bs 11)) "S")
    (is (= 0x54 (aget bs 12)) "T")))

(deftest canonical-bytes-deterministic
  (let [a (envelope/canonical-bytes fixture-env)
        b (envelope/canonical-bytes fixture-env)]
    (is (= (to-hex a) (to-hex b)))))

(deftest canonical-bytes-different-method-different-bytes
  (let [a (envelope/canonical-bytes fixture-env)
        b (envelope/canonical-bytes (assoc fixture-env :method "GET"))]
    (is (not= (to-hex a) (to-hex b)))))

(deftest envelope-wire-roundtrip
  (let [wire (envelope/envelope->wire fixture-env)
        env2 (envelope/wire->envelope wire)]
    (is (= (:method fixture-env) (:method env2)))
    (is (= (:path fixture-env)   (:path env2)))
    (is (= (:ts fixture-env)     (:ts env2)))
    (is (= (to-hex (:body-sha256 fixture-env))
           (to-hex (:body-sha256 env2))))
    (is (= (to-hex (:nonce fixture-env))
           (to-hex (:nonce env2))))
    (is (= (to-hex (:fp-digest fixture-env))
           (to-hex (:fp-digest env2))))
    (is (= (to-hex (:key-id fixture-env))
           (to-hex (:key-id env2))))))

(deftest b64url-roundtrip
  (let [bs (bytes-of [0xfb 0xff 0xff 0x00 0x01])
        s  (envelope/b64url-encode bs)
        bs2 (envelope/b64url-decode s)]
    (is (= (to-hex bs) (to-hex bs2)))))
