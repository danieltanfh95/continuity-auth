(ns continuity-auth.server.crypto.pubkey
  "Public-key parsing, canonicalization, and thumbprint computation on the JVM.

  Canonical pubkey encodings (matching the Web Crypto `raw` export format):
    :ed25519 — 32 raw bytes (the EdEC point Y-coord with X-sign in high bit
               of byte 31, little-endian Y)
    :p256    — 65 bytes uncompressed SEC1: 0x04 || X[32] || Y[32]

  These canonical forms are what the client transmits in the bootstrap and
  rotate-key envelopes, and what the server thumbprints to compute
  :pubkey/id (= :key-id in the envelope)."
  (:require
   [continuity-auth.crypto :as crypto]
   [continuity-auth.server.crypto.hash :as hash])
  (:import
   (org.bouncycastle.asn1.sec SECNamedCurves)
   (org.bouncycastle.asn1.x9 X9ECParameters)
   (org.bouncycastle.crypto.params ECDomainParameters
                                   ECPublicKeyParameters
                                   Ed25519PublicKeyParameters)
   (org.bouncycastle.math.ec ECPoint)))

;; -- domain parameters (memoized once) -------------------------------------

(def ^:private ^X9ECParameters p256-x9
  (SECNamedCurves/getByName "secp256r1"))

(def ^:private ^ECDomainParameters p256-domain
  (ECDomainParameters. (.getCurve  p256-x9)
                       (.getG      p256-x9)
                       (.getN      p256-x9)
                       (.getH      p256-x9)))

(defn p256-domain-params ^ECDomainParameters [] p256-domain)

;; -- size checks -----------------------------------------------------------

(defn- check-canonical-length!
  [alg ^bytes bs]
  (let [expected (get crypto/pubkey-byte-length alg)
        actual   (alength bs)]
    (when-not (= expected actual)
      (throw (ex-info "canonical pubkey length mismatch"
                      {:alg alg :expected expected :actual actual})))))

(defn- check-p256-prefix!
  [^bytes bs]
  (let [b0 (bit-and 0xff (aget bs 0))]
    (when-not (= b0 crypto/sec1-uncompressed-prefix)
      (throw (ex-info "P-256 pubkey must be SEC1 uncompressed (0x04 prefix)"
                      {:got (format "0x%02x" b0)})))))

;; -- canonical → BouncyCastle params --------------------------------------

(defn ed25519-params-from-canonical
  "Parse 32 canonical bytes into an Ed25519PublicKeyParameters."
  ^Ed25519PublicKeyParameters [^bytes bs]
  (check-canonical-length! :ed25519 bs)
  (Ed25519PublicKeyParameters. bs 0))

(defn p256-params-from-canonical
  "Parse 65 SEC1-uncompressed bytes into an ECPublicKeyParameters for P-256.

  Decodes the curve point; throws if the bytes do not represent a valid
  point on the curve."
  ^ECPublicKeyParameters [^bytes bs]
  (check-canonical-length! :p256 bs)
  (check-p256-prefix! bs)
  (let [^ECPoint q (.decodePoint (.getCurve p256-x9) bs)]
    (ECPublicKeyParameters. q p256-domain)))

(defn parse-canonical
  "Parse canonical pubkey bytes for the given algorithm, returning a
  BouncyCastle key parameters object suitable for the verify path."
  [alg ^bytes bs]
  (case alg
    :ed25519 (ed25519-params-from-canonical bs)
    :p256    (p256-params-from-canonical    bs)
    (throw (ex-info "unknown algorithm" {:alg alg}))))

;; -- thumbprint ------------------------------------------------------------

(defn thumbprint
  "Return the 32-byte SHA-256 thumbprint of the canonical pubkey bytes.
  This is the :pubkey/id used by the database and the :key-id field of
  envelopes."
  ^bytes [^bytes canonical-bs]
  (hash/sha256 canonical-bs))

(defn alg+canonical->thumbprint
  "Convenience: validate length, then return the thumbprint."
  ^bytes [alg ^bytes canonical-bs]
  (check-canonical-length! alg canonical-bs)
  (when (= alg :p256) (check-p256-prefix! canonical-bs))
  (thumbprint canonical-bs))
