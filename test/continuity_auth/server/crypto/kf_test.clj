(ns continuity-auth.server.crypto.kf-test
  "Reference implementation + tests for the client-side knowledge-factor
  key derivation. The server never runs this path (it only wraps/unwraps a
  verifier and checks a signature); these tests pin the derivation contract
  the cljs client must match byte-for-byte:

      salt = blake2s(\"cauth-kf-salt-v1\" ‖ uuid-bytes)   ; 32 bytes
      seed = Argon2id(secret-utf8, salt)                  ; 32 bytes
      kf-keypair = Ed25519(priv = seed)

  Properties: determinism for fixed (secret, identity); a different
  identity UUID ⇒ different salt ⇒ different key; the derived public key
  verifies a kf-challenge signed by the derived private key (closing the
  loop the reclaim handler relies on)."
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.pubkey :as pubkey]
   [continuity-auth.server.crypto.verify :as verify])
  (:import
   (java.nio.charset StandardCharsets)
   (org.bouncycastle.crypto.digests Blake2sDigest)
   (org.bouncycastle.crypto.generators Argon2BytesGenerator)
   (org.bouncycastle.crypto.params Argon2Parameters Argon2Parameters$Builder
                                   Ed25519PrivateKeyParameters)
   (org.bouncycastle.crypto.signers Ed25519Signer)))

;; -- reference derivation (mirrors the intended cljs client) --------------

(def ^:private salt-tag "cauth-kf-salt-v1")

(defn- utf8 ^bytes [^String s] (.getBytes s StandardCharsets/UTF_8))

(defn- blake2s-salt
  "salt = blake2s(salt-tag ‖ uuid-bytes), 32-byte output."
  ^bytes [^java.util.UUID uuid]
  (let [tag  (utf8 salt-tag)
        ub   (let [bb (java.nio.ByteBuffer/allocate 16)]
               (.putLong bb (.getMostSignificantBits uuid))
               (.putLong bb (.getLeastSignificantBits uuid))
               (.array bb))
        d    (Blake2sDigest. 256)
        out  (byte-array 32)]
    (.update d tag 0 (alength tag))
    (.update d ub 0 (alength ub))
    (.doFinal d out 0)
    out))

(defn- argon2id-seed
  "Fixed :argon2id-v1 params (the 0.4.0 protocol constant)."
  ^bytes [^String secret ^bytes salt]
  (let [params (.. (Argon2Parameters$Builder. Argon2Parameters/ARGON2_id)
                   (withSalt salt)
                   (withIterations 3)
                   (withMemoryAsKB 65536)
                   (withParallelism 1)
                   (build))
        gen    (Argon2BytesGenerator.)
        out    (byte-array 32)]
    (.init gen params)
    (.generateBytes gen (utf8 secret) out)
    out))

(defn- derive-kf-keypair
  "Returns {:priv ^bytes seed :pub ^bytes ed25519-pubkey} for (secret, uuid)."
  [^String secret ^java.util.UUID uuid]
  (let [seed (argon2id-seed secret (blake2s-salt uuid))
        priv (Ed25519PrivateKeyParameters. seed 0)
        pub  (.getEncoded (.generatePublicKey priv))]
    {:priv seed :pub pub}))

(defn- kf-sign ^bytes [^bytes seed ^bytes msg]
  (let [priv   (Ed25519PrivateKeyParameters. seed 0)
        signer (Ed25519Signer.)]
    (.init signer true priv)
    (.update signer msg 0 (alength msg))
    (.generateSignature signer)))

;; -- tests ----------------------------------------------------------------

(def ^:private secret "correct horse battery staple")

(deftest derivation-is-deterministic-for-fixed-secret-and-identity
  (testing "same (secret, identity UUID) ⇒ identical kf keypair on every run."
    (let [uuid (java.util.UUID/fromString "11111111-2222-3333-4444-555555555555")
          a    (derive-kf-keypair secret uuid)
          b    (derive-kf-keypair secret uuid)]
      (is (java.util.Arrays/equals ^bytes (:pub a) ^bytes (:pub b)))
      (is (java.util.Arrays/equals ^bytes (:priv a) ^bytes (:priv b))))))

(deftest different-identity-uuid-yields-different-key
  (testing "the salt is derived from the identity UUID, so two identities
            with the SAME password get distinct kf keys — no cross-identity
            verifier reuse."
    (let [u1 (java.util.UUID/fromString "11111111-2222-3333-4444-555555555555")
          u2 (java.util.UUID/fromString "99999999-8888-7777-6666-555555555555")
          k1 (derive-kf-keypair secret u1)
          k2 (derive-kf-keypair secret u2)]
      (is (not (java.util.Arrays/equals ^bytes (:pub k1) ^bytes (:pub k2)))))))

(deftest different-secret-yields-different-key
  (testing "different password under the same identity ⇒ different key."
    (let [uuid (java.util.UUID/fromString "11111111-2222-3333-4444-555555555555")
          k1   (derive-kf-keypair secret uuid)
          k2   (derive-kf-keypair "a different secret" uuid)]
      (is (not (java.util.Arrays/equals ^bytes (:pub k1) ^bytes (:pub k2)))))))

(deftest derived-pub-verifies-a-kf-challenge-signed-by-derived-priv
  (testing "the closed loop the reclaim handler depends on: a kf-challenge
            signed by the derived private key verifies under the derived
            public key via the production verify/verify path."
    (let [uuid         (java.util.UUID/fromString "11111111-2222-3333-4444-555555555555")
          identity-ref (str uuid)
          {:keys [priv pub]} (derive-kf-keypair secret uuid)
          ;; A plausible new-device pubkey thumbprint + envelope nonce.
          new-thumb    (pubkey/alg+canonical->thumbprint :ed25519 (byte-array (range 32)))
          nonce        (byte-array (map byte (range 16)))
          challenge    (envelope/kf-challenge-bytes identity-ref new-thumb nonce)
          sig          (kf-sign priv challenge)]
      (is (verify/verify :ed25519 pub challenge sig)))))

(deftest kf-challenge-binds-the-new-pubkey-thumbprint
  (testing "a signature over a challenge bound to one new-key thumbprint
            does NOT verify against a challenge bound to a different one —
            an eavesdropper cannot swap in their own pubkey (swap-resistance)."
    (let [uuid         (java.util.UUID/fromString "11111111-2222-3333-4444-555555555555")
          identity-ref (str uuid)
          {:keys [priv pub]} (derive-kf-keypair secret uuid)
          thumb-a      (pubkey/alg+canonical->thumbprint :ed25519 (byte-array (range 32)))
          thumb-b      (pubkey/alg+canonical->thumbprint :ed25519 (byte-array (map #(byte (+ % 1)) (range 32))))
          nonce        (byte-array (map byte (range 16)))
          sig          (kf-sign priv (envelope/kf-challenge-bytes identity-ref thumb-a nonce))]
      (is (not (verify/verify :ed25519 pub
                              (envelope/kf-challenge-bytes identity-ref thumb-b nonce)
                              sig))))))
