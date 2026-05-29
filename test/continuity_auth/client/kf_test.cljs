(ns continuity-auth.client.kf-test
  "Browser-side tests for the knowledge-factor derivation.

  Exercises the real @noble/@scure stack in headless Chrome via karma:
    - BIP-39 mnemonic encodes/decodes the identity UUID losslessly
    - an invalid mnemonic is rejected
    - derivation is deterministic AND byte-for-byte matches the JVM
      BouncyCastle reference vector (cross-impl recovery guarantee)
    - the derived public key is a valid WebCrypto Ed25519 key and verifies
      a kf-challenge signed by the derived private seed

  Argon2id (64 MiB, t=3) runs in pure JS here, so these tests take a few
  seconds — kept to a single derivation to stay snappy."
  (:require
   [cljs.test :refer-macros [deftest is async]]
   [continuity-auth.client.kf :as kf]
   [continuity-auth.envelope :as envelope]
   [promesa.core :as p]))

(def ^:private ref "11111111-2222-3333-4444-555555555555")
(def ^:private secret "correct horse battery staple")

;; Byte-for-byte vector shared with the JVM reference
;; (continuity-auth.server.crypto.kf-test) and a node cross-check.
(def ^:private expected-pub-hex
  "75be43fd30ed93bbb375628da45c7894a9f978df989ed44558b411c4723f26c7")

(defn- hex [^js b]
  (->> (array-seq b)
       (map (fn [x] (.padStart (.toString (bit-and x 0xff) 16) 2 "0")))
       (apply str)))

(defn- import-ed25519-public [pub-bytes]
  (.importKey (.. js/window -crypto -subtle)
              "raw" pub-bytes #js {:name "Ed25519"} true #js ["verify"]))

;; -- mnemonic ↔ uuid -------------------------------------------------------

(deftest mnemonic-roundtrips-the-identity-uuid
  (let [m (kf/mnemonic-of ref)]
    (is (= 12 (count (.split m " "))) "a 128-bit UUID encodes to 12 words")
    (is (= ref (kf/uuid-of m)) "decode recovers the exact UUID")))

(deftest invalid-mnemonic-is-rejected
  (is (thrown? js/Error (kf/uuid-of "not a valid bip39 phrase at all nope"))))

;; -- derivation: determinism + JVM parity + sign/verify loop --------------

(deftest derivation-matches-reference-and-signs
  (async done
    (-> (p/let [{:keys [priv pub]} (kf/derive-kf-keypair secret ref)]
          (is (= 32 (.-length pub)) "Ed25519 pubkey is 32 bytes")
          (is (= 32 (.-length priv)) "the seed is 32 bytes")
          (is (= expected-pub-hex (hex pub))
              "derived pubkey matches the JVM BouncyCastle reference vector")
          (p/let [;; A plausible reclaim challenge: a new-device thumbprint
                  ;; (32 bytes) + the envelope nonce (16 bytes).
                  new-thumb (let [b (js/Uint8Array. 32)] (dotimes [i 32] (aset b i i)) b)
                  nonce     (let [b (js/Uint8Array. 16)] (dotimes [i 16] (aset b i i)) b)
                  challenge (envelope/kf-challenge-bytes ref new-thumb nonce)
                  sig       (kf/kf-sign priv challenge)
                  pk        (import-ed25519-public pub)
                  ok?       (.verify (.. js/window -crypto -subtle)
                                     #js {:name "Ed25519"} pk sig challenge)]
            (is (= 64 (.-length sig)) "kf signature is 64 bytes")
            (is (true? ok?)
                "the derived pub verifies a challenge signed by the derived seed")
            (done)))
        (p/catch (fn [err]
                   (is false (str "kf derivation path threw: " err))
                   (done))))))

(deftest different-secret-changes-the-key
  (async done
    (-> (p/let [a (kf/derive-kf-keypair secret ref)
                b (kf/derive-kf-keypair "a different secret" ref)]
          (is (not= (hex (:pub a)) (hex (:pub b)))
              "a different secret derives a different KF key")
          (done))
        (p/catch (fn [err]
                   (is false (str "threw: " err))
                   (done))))))
