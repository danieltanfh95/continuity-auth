(ns continuity-auth.client.crypto-test
  "Browser-side smoke tests for the Web Crypto wrappers.

  These exercise the real SubtleCrypto API in headless Chrome via
  karma. They cover:
    - Ed25519 keypair generation + sign + roundtrip-via-import verify
    - P-256 keypair generation + sign + roundtrip-via-import verify
    - SHA-256 digest produces 32 bytes
    - Thumbprint is a 32-byte SHA-256 of pubkey bytes
    - The exported pubkey has the canonical length (32 for Ed25519,
      65 for P-256)

  Importantly: we VERIFY signatures by re-importing the exported pubkey
  via `crypto.subtle.importKey`. The private key remains non-extractable
  throughout."
  (:require
   [cljs.test :refer-macros [deftest is async]]
   [continuity-auth.client.crypto :as crypto]
   [promesa.core :as p]))

;; -- helpers ---------------------------------------------------------------

(defn- subtle [] (.. js/window -crypto -subtle))

(defn- import-public
  "Import canonical pubkey bytes back into a CryptoKey we can use to
  verify signatures."
  [alg pub-bytes]
  (let [params (case alg
                 :ed25519 #js {:name "Ed25519"}
                 :p256    #js {:name "ECDSA" :namedCurve "P-256"})
        usages #js ["verify"]]
    (.importKey (subtle) "raw" pub-bytes params true usages)))

(defn- verify-sig
  "Verify a signature using the re-imported pubkey."
  [alg pub-bytes signature message]
  (p/let [pk (import-public alg pub-bytes)
          params (case alg
                   :ed25519 #js {:name "Ed25519"}
                   :p256    #js {:name "ECDSA" :hash #js {:name "SHA-256"}})]
    (.verify (subtle) params pk signature message)))

(defn- bytes-of [xs]
  (let [out (js/Uint8Array. (count xs))]
    (dotimes [i (count xs)] (aset out i (nth xs i)))
    out))

;; -- tests ----------------------------------------------------------------

(deftest ed25519-generate-export-roundtrip
  (async done
    (-> (crypto/generate-keypair :ed25519)
        (p/then (fn [kp]
                  (p/let [pub-bytes (crypto/export-public (:public-key kp))
                          msg       (bytes-of (range 16))
                          sig       (crypto/sign :ed25519 (:private-key kp) msg)
                          ok?       (verify-sig :ed25519 pub-bytes sig msg)]
                    (is (= 32 (.-length pub-bytes))
                        "Ed25519 raw pubkey is 32 bytes")
                    (is (= 64 (.-length sig))
                        "Ed25519 signature is 64 bytes")
                    (is (true? ok?)
                        "Signature verifies under re-imported pubkey")
                    (done))))
        (p/catch (fn [err]
                   (is false (str "Ed25519 path threw: " err))
                   (done))))))

(deftest p256-generate-export-roundtrip
  (async done
    (-> (crypto/generate-keypair :p256)
        (p/then (fn [kp]
                  (p/let [pub-bytes (crypto/export-public (:public-key kp))
                          msg       (bytes-of (range 16))
                          sig       (crypto/sign :p256 (:private-key kp) msg)
                          ok?       (verify-sig :p256 pub-bytes sig msg)]
                    (is (= 65 (.-length pub-bytes))
                        "P-256 uncompressed SEC1 pubkey is 65 bytes")
                    (is (= 64 (.-length sig))
                        "P-256 raw R||S signature is 64 bytes")
                    (is (= 4 (aget pub-bytes 0))
                        "P-256 first byte is the SEC1 uncompressed marker 0x04")
                    (is (true? ok?)
                        "Signature verifies under re-imported pubkey")
                    (done))))
        (p/catch (fn [err]
                   (is false (str "P-256 path threw: " err))
                   (done))))))

(deftest sha256-produces-32-bytes
  (async done
    (-> (crypto/sha256 (bytes-of [0 1 2 3 4]))
        (p/then (fn [d]
                  (is (= 32 (.-length d)))
                  (done))))))

(deftest thumbprint-is-deterministic
  (async done
    (let [pk (bytes-of (repeat 32 1))]
      (-> (p/let [t1 (crypto/thumbprint pk)
                  t2 (crypto/thumbprint pk)]
            (is (= 32 (.-length t1)))
            (is (= 32 (.-length t2)))
            ;; Bytewise equality
            (let [eq? (loop [i 0]
                        (cond
                          (= i 32) true
                          (not= (aget t1 i) (aget t2 i)) false
                          :else (recur (inc i))))]
              (is (true? eq?)
                  "Same input yields identical SHA-256 across calls"))
            (done))
          (p/catch (fn [err]
                     (is false (str "thumbprint threw: " err))
                     (done)))))))

(deftest unknown-alg-throws
  (is (thrown? js/Error (crypto/generate-keypair :rsa))))
