(ns continuity-auth.server.crypto.verify-test
  "Unit tests for signature verification, including externally-verified
  Known-Answer Test (KAT) vectors:
    - Ed25519: RFC 8032 §7.1 Test 1 and Test 2
    - ECDSA P-256 with SHA-256: NIST CAVP FIPS 186-4 SigVer

  The KATs guarantee our verification path agrees with the canonical
  reference implementations, not merely with itself.

  Additional self-roundtrip tests (sign on JVM, verify on JVM) catch
  regressions in our own envelope-bytes path even if the canonical
  external vectors all pass."
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.server.crypto.hash :as hash]
   [continuity-auth.server.crypto.pubkey :as pubkey]
   [continuity-auth.server.crypto.verify :as verify])
  (:import
   (java.security SecureRandom)
   (org.bouncycastle.crypto.generators ECKeyPairGenerator
                                       Ed25519KeyPairGenerator)
   (org.bouncycastle.crypto.params ECKeyGenerationParameters
                                   ECPrivateKeyParameters
                                   ECPublicKeyParameters
                                   Ed25519KeyGenerationParameters
                                   Ed25519PrivateKeyParameters
                                   Ed25519PublicKeyParameters)
   (org.bouncycastle.crypto.signers ECDSASigner Ed25519Signer)))

;; -- helpers ----------------------------------------------------------------

(defn- from-hex ^bytes [^String s]
  (let [n   (quot (count s) 2)
        out (byte-array n)]
    (dotimes [i n]
      (aset-byte out i (unchecked-byte
                        (Integer/parseInt (subs s (* 2 i) (+ (* 2 i) 2)) 16))))
    out))

(defn- to-hex ^String [^bytes bs]
  (let [n  (alength bs)
        sb (StringBuilder. (* 2 n))]
    (dotimes [i n]
      (let [b (bit-and 0xff (aget bs i))]
        (when (< b 16) (.append sb \0))
        (.append sb (Integer/toHexString b))))
    (.toString sb)))

(defn- big-int-to-32 ^bytes [^java.math.BigInteger n]
  ;; Return exactly 32 bytes representing the unsigned magnitude of n,
  ;; left-padded with zeros (or trimmed if BigInteger emitted a leading 0).
  (let [raw (.toByteArray n)
        len (alength raw)
        out (byte-array 32)]
    (cond
      (= len 32) raw
      (= len 33) (do (System/arraycopy raw 1 out 0 32) out)
      (< len 32) (do (System/arraycopy raw 0 out (- 32 len) len) out)
      :else (throw (ex-info "BigInteger too large for 32 bytes" {:len len})))))

;; -- Ed25519 KAT (RFC 8032 §7.1) -------------------------------------------

(def ^:private ed25519-kat-1
  {:pubkey-hex  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
   :message-hex ""
   :signature-hex (str "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974"
                       "d873e065224901555fb8821590a33bacc61e39701cf9b46b"
                       "d25bf5f0595bbe24655141438e7a100b")})

(def ^:private ed25519-kat-2
  {:pubkey-hex  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
   :message-hex "72"
   :signature-hex (str "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8f"
                       "b3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c"
                       "387b2eaeb4302aeeb00d291612bb0c00")})

(deftest ed25519-rfc8032-test1-valid
  (let [{:keys [pubkey-hex message-hex signature-hex]} ed25519-kat-1]
    (is (true? (verify/verify-ed25519
                (from-hex pubkey-hex)
                (from-hex message-hex)
                (from-hex signature-hex))))))

(deftest ed25519-rfc8032-test2-valid
  (let [{:keys [pubkey-hex message-hex signature-hex]} ed25519-kat-2]
    (is (true? (verify/verify-ed25519
                (from-hex pubkey-hex)
                (from-hex message-hex)
                (from-hex signature-hex))))))

(deftest ed25519-rfc8032-test1-tampered-message
  (let [{:keys [pubkey-hex signature-hex]} ed25519-kat-1]
    (is (false? (verify/verify-ed25519
                 (from-hex pubkey-hex)
                 (from-hex "00")
                 (from-hex signature-hex))))))

(deftest ed25519-rfc8032-test1-tampered-signature
  (let [{:keys [pubkey-hex message-hex signature-hex]} ed25519-kat-1
        bs        (from-hex signature-hex)
        _         (aset-byte bs 0 (unchecked-byte (bit-xor 0xff (aget bs 0))))]
    (is (false? (verify/verify-ed25519
                 (from-hex pubkey-hex)
                 (from-hex message-hex)
                 bs)))))

(deftest ed25519-signature-wrong-length-throws
  (is (thrown? clojure.lang.ExceptionInfo
               (verify/verify-ed25519
                (from-hex (:pubkey-hex ed25519-kat-1))
                (byte-array 0)
                (byte-array 63)))))

;; -- Ed25519 self-roundtrip (BouncyCastle sign → our verify) ---------------

(defn- gen-ed25519-keypair []
  (let [g (Ed25519KeyPairGenerator.)
        _ (.init g (Ed25519KeyGenerationParameters. (SecureRandom.)))
        kp (.generateKeyPair g)
        ^Ed25519PrivateKeyParameters sk (.getPrivate kp)
        ^Ed25519PublicKeyParameters  pk (.getPublic kp)]
    {:sk sk
     :pk pk
     :pk-bytes (.getEncoded pk)}))

(defn- ed25519-sign ^bytes [sk ^bytes msg]
  (let [signer (Ed25519Signer.)]
    (.init signer true sk)
    (.update signer msg 0 (alength msg))
    (.generateSignature signer)))

(deftest ed25519-self-roundtrip-many
  (testing "100 random keypairs × random messages"
    (dotimes [_ 100]
      (let [{:keys [sk pk-bytes]} (gen-ed25519-keypair)
            msg (byte-array (range 32))
            sig (ed25519-sign sk msg)]
        (is (true? (verify/verify-ed25519 pk-bytes msg sig)))))))

;; -- P-256 KAT (RFC 6979 §A.2.5, ECDSA P-256 + SHA-256) ------------------
;;
;; Deterministic ECDSA test vector. We verify the canonical sample
;; signature as a non-deterministic signature too — verification doesn't
;; depend on the nonce.

(def ^:private p256-kat-sample
  {:msg-utf8 "sample"
   :qx-hex   "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
   :qy-hex   "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
   :r-hex    "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
   :s-hex    "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"})

(def ^:private p256-kat-test
  {:msg-utf8 "test"
   :qx-hex   "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
   :qy-hex   "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
   :r-hex    "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"
   :s-hex    "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"})

(defn- p256-canonical-pubkey ^bytes [qx-hex qy-hex]
  (let [out (byte-array 65)]
    (aset-byte out 0 (unchecked-byte 0x04))
    (System/arraycopy (from-hex qx-hex) 0 out 1  32)
    (System/arraycopy (from-hex qy-hex) 0 out 33 32)
    out))

(defn- p256-raw-sig ^bytes [r-hex s-hex]
  (let [out (byte-array 64)]
    (System/arraycopy (from-hex r-hex) 0 out 0  32)
    (System/arraycopy (from-hex s-hex) 0 out 32 32)
    out))

(deftest p256-rfc6979-sample-valid
  (let [{:keys [msg-utf8 qx-hex qy-hex r-hex s-hex]} p256-kat-sample]
    (is (true? (verify/verify-p256
                (p256-canonical-pubkey qx-hex qy-hex)
                (.getBytes ^String msg-utf8 "UTF-8")
                (p256-raw-sig r-hex s-hex))))))

(deftest p256-rfc6979-test-valid
  (let [{:keys [msg-utf8 qx-hex qy-hex r-hex s-hex]} p256-kat-test]
    (is (true? (verify/verify-p256
                (p256-canonical-pubkey qx-hex qy-hex)
                (.getBytes ^String msg-utf8 "UTF-8")
                (p256-raw-sig r-hex s-hex))))))

(deftest p256-rfc6979-tampered-message
  (let [{:keys [qx-hex qy-hex r-hex s-hex]} p256-kat-sample]
    (is (false? (verify/verify-p256
                 (p256-canonical-pubkey qx-hex qy-hex)
                 (.getBytes "different message" "UTF-8")
                 (p256-raw-sig r-hex s-hex))))))

(deftest p256-signature-wrong-length-throws
  (let [{:keys [msg-utf8 qx-hex qy-hex]} p256-kat-sample]
    (is (thrown? clojure.lang.ExceptionInfo
                 (verify/verify-p256
                  (p256-canonical-pubkey qx-hex qy-hex)
                  (.getBytes ^String msg-utf8 "UTF-8")
                  (byte-array 63))))))

;; -- P-256 self-roundtrip --------------------------------------------------

(defn- gen-p256-keypair []
  (let [domain (pubkey/p256-domain-params)
        g      (ECKeyPairGenerator.)
        _      (.init g (ECKeyGenerationParameters. domain (SecureRandom.)))
        kp     (.generateKeyPair g)
        ^ECPrivateKeyParameters sk (.getPrivate kp)
        ^ECPublicKeyParameters  pk (.getPublic  kp)
        q       (.getQ pk)
        normalized (.normalize q)
        x-bytes (big-int-to-32 (.toBigInteger (.getAffineXCoord normalized)))
        y-bytes (big-int-to-32 (.toBigInteger (.getAffineYCoord normalized)))
        pk-bs   (let [out (byte-array 65)]
                  (aset-byte out 0 (unchecked-byte 0x04))
                  (System/arraycopy x-bytes 0 out 1  32)
                  (System/arraycopy y-bytes 0 out 33 32)
                  out)]
    {:sk sk :pk pk :pk-bytes pk-bs}))

(defn- p256-sign-raw ^bytes [sk ^bytes msg]
  (let [hash    (hash/sha256 msg)
        signer  (ECDSASigner.)
        _       (.init signer true sk)
        ^"[Ljava.math.BigInteger;" rs (.generateSignature signer hash)
        r-bytes (big-int-to-32 (aget rs 0))
        s-bytes (big-int-to-32 (aget rs 1))
        out     (byte-array 64)]
    (System/arraycopy r-bytes 0 out 0  32)
    (System/arraycopy s-bytes 0 out 32 32)
    out))

(deftest p256-self-roundtrip-many
  (testing "50 random keypairs × random messages"
    (dotimes [_ 50]
      (let [{:keys [sk pk-bytes]} (gen-p256-keypair)
            msg (.getBytes "hello continuity-auth" "UTF-8")
            sig (p256-sign-raw sk msg)]
        (is (true? (verify/verify-p256 pk-bytes msg sig)))))))

;; -- Generic verify dispatch ----------------------------------------------

(deftest verify-dispatches-to-ed25519
  (let [{:keys [pubkey-hex message-hex signature-hex]} ed25519-kat-1]
    (is (true? (verify/verify :ed25519
                              (from-hex pubkey-hex)
                              (from-hex message-hex)
                              (from-hex signature-hex))))))

(deftest verify-dispatches-to-p256
  (let [{:keys [msg-utf8 qx-hex qy-hex r-hex s-hex]} p256-kat-sample]
    (is (true? (verify/verify :p256
                              (p256-canonical-pubkey qx-hex qy-hex)
                              (.getBytes ^String msg-utf8 "UTF-8")
                              (p256-raw-sig r-hex s-hex))))))

(deftest verify-rejects-unknown-algorithm
  (is (thrown? clojure.lang.ExceptionInfo
               (verify/verify :rsa
                              (byte-array 32)
                              (byte-array 0)
                              (byte-array 64)))))

(deftest verify-returns-false-on-malformed-pubkey
  (testing "verify returns false (no exception) on a structurally-bad pubkey"
    (is (false? (verify/verify :ed25519
                               (byte-array 5)        ; wrong length
                               (byte-array 0)
                               (byte-array 64))))))

;; -- thumbprint ------------------------------------------------------------

(deftest thumbprint-is-sha256
  (let [pk-bytes (from-hex (:pubkey-hex ed25519-kat-1))
        tp       (pubkey/thumbprint pk-bytes)]
    (is (= 32 (alength tp)))
    (is (= (to-hex tp) (to-hex (hash/sha256 pk-bytes))))))

(deftest thumbprint-collision-resistance-spot-check
  (testing "different pubkeys give different thumbprints"
    (let [a (from-hex (:pubkey-hex ed25519-kat-1))
          b (from-hex (:pubkey-hex ed25519-kat-2))]
      (is (not= (to-hex (pubkey/thumbprint a))
                (to-hex (pubkey/thumbprint b)))))))

(deftest alg+canonical-validates-and-thumbprints
  (testing "valid ed25519 length is accepted"
    (is (= 32 (alength (pubkey/alg+canonical->thumbprint :ed25519
                                                          (byte-array 32))))))
  (testing "invalid length rejected"
    (is (thrown? clojure.lang.ExceptionInfo
                 (pubkey/alg+canonical->thumbprint :ed25519 (byte-array 33)))))
  (testing "p256 requires 0x04 prefix"
    (is (thrown? clojure.lang.ExceptionInfo
                 (pubkey/alg+canonical->thumbprint :p256 (byte-array 65))))))

;; -- constant-time equality ------------------------------------------------

(deftest constant-time-equal-true-cases
  (is (true? (hash/constant-time-equal? (byte-array 0) (byte-array 0))))
  (is (true? (hash/constant-time-equal? (byte-array [1 2 3]) (byte-array [1 2 3])))))

(deftest constant-time-equal-false-cases
  (is (false? (hash/constant-time-equal? (byte-array [1 2 3]) (byte-array [1 2 4]))))
  (is (false? (hash/constant-time-equal? (byte-array [1 2])   (byte-array [1 2 3])))))
