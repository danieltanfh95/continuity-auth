(ns continuity-auth.server.crypto.verify
  "Signature verification on the JVM for the algorithms supported by the
  client: Ed25519 and ECDSA-P256-SHA256.

  Wire format for both algorithms is raw R||S (64 bytes), matching what
  Web Crypto's SubtleCrypto.sign produces. We do NOT accept DER-encoded
  ECDSA signatures on the wire — that would be a second representation
  for the same value and a footgun.

  All verify paths are constant-time-friendly: we run the full verify even
  on obviously-invalid signatures and return a uniform boolean. The caller
  is responsible for treating both the false branch and any thrown
  exception as 'invalid'."
  (:require
   [continuity-auth.crypto :as crypto]
   [continuity-auth.server.crypto.pubkey :as pubkey]
   [continuity-auth.server.crypto.hash :as hash])
  (:import
   (java.math BigInteger)
   (org.bouncycastle.crypto.params ECPublicKeyParameters
                                   Ed25519PublicKeyParameters)
   (org.bouncycastle.crypto.signers ECDSASigner
                                    Ed25519Signer)))

(defn- unsigned-big-int
  "Construct a non-negative BigInteger from the bytes of `bs[off..off+len)`."
  ^BigInteger [^bytes bs ^long off ^long len]
  (BigInteger. 1 bs off len))

(defn- split-raw-ecdsa
  "Split a raw R||S signature into (R, S) BigIntegers. Throws if length
  is not exactly 2 * coordinate-bytes."
  [^bytes sig]
  (let [coord crypto/p256-coord-bytes
        n     (alength sig)
        exp   (* 2 coord)]
    (when-not (= n exp)
      (throw (ex-info "ECDSA raw signature has wrong length"
                      {:expected exp :actual n})))
    [(unsigned-big-int sig 0     coord)
     (unsigned-big-int sig coord coord)]))

(defn verify-ed25519
  "Verify an Ed25519 signature.
   `pubkey-bytes` — 32 canonical bytes.
   `message`      — bytes that were signed.
   `signature`    — 64 raw bytes (R || S)."
  [^bytes pubkey-bytes ^bytes message ^bytes signature]
  (when-not (= 64 (alength signature))
    (throw (ex-info "Ed25519 signature must be 64 bytes"
                    {:actual (alength signature)})))
  (let [^Ed25519PublicKeyParameters pk (pubkey/ed25519-params-from-canonical pubkey-bytes)
        signer (Ed25519Signer.)]
    (.init signer false pk)
    (.update signer message 0 (alength message))
    (.verifySignature signer signature)))

(defn verify-p256
  "Verify an ECDSA-P256-SHA256 signature.
   `pubkey-bytes` — 65 SEC1-uncompressed bytes (0x04 || X || Y).
   `message`      — bytes that were signed (pre-hash; we hash here).
   `signature`    — 64 raw bytes (R || S)."
  [^bytes pubkey-bytes ^bytes message ^bytes signature]
  (let [^ECPublicKeyParameters pk (pubkey/p256-params-from-canonical pubkey-bytes)
        [^BigInteger r ^BigInteger s] (split-raw-ecdsa signature)
        digest (hash/sha256 message)
        signer (ECDSASigner.)]
    (.init signer false pk)
    (.verifySignature signer digest r s)))

(defn verify
  "Verify a signature with the given algorithm.

  Returns true iff the signature is valid against the pubkey and message;
  returns false on any validation or verification failure, including
  malformed-input exceptions. This uniform error-discarding behavior is
  intentional — the caller MUST NOT distinguish between 'invalid sig'
  and 'malformed input' in its response to avoid disclosing why a verify
  failed (avoiding the timing/error-differential side channel of §A§10
  in the plan)."
  [alg ^bytes pubkey-bytes ^bytes message ^bytes signature]
  (when-not (crypto/algorithm? alg)
    (throw (ex-info "unknown algorithm" {:alg alg})))
  (try
    (case alg
      :ed25519 (verify-ed25519 pubkey-bytes message signature)
      :p256    (verify-p256    pubkey-bytes message signature))
    (catch Exception _
      false)))
