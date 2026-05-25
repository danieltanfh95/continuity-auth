(ns continuity-auth.crypto
  "Pure cross-platform constants and predicates for cryptographic
  algorithms accepted by continuity-auth.

  Platform-specific operations (sign, verify, digest) live in the
  server.crypto.* (JVM) and client.crypto (cljs) namespaces.")

(def ^:const algorithms
  "Supported signature algorithms. Keyword forms used throughout the system."
  #{:ed25519 :p256})

(defn algorithm?
  "Predicate: is `x` a supported algorithm keyword?"
  [x]
  (contains? algorithms x))

(def ^:const pubkey-byte-length
  "Canonical public-key encoding length, in bytes, per algorithm.

    :ed25519 — 32 bytes raw (the Web Crypto `raw` export format)
    :p256    — 65 bytes uncompressed SEC1 (0x04 || X[32] || Y[32]), which
               is also the Web Crypto `raw` export format for P-256."
  {:ed25519 32
   :p256    65})

(def ^:const signature-byte-length
  "Raw (non-DER) signature byte length per algorithm.

    :ed25519 — 64 bytes (R[32] || S[32])
    :p256    — 64 bytes raw (R[32] || S[32]) as produced by Web Crypto.
               Wire format is raw, never DER. The server converts to DER
               internally if its verifier requires it."
  {:ed25519 64
   :p256    64})

(def ^:const thumbprint-bytes
  "Pubkey thumbprint length: SHA-256 → 32 bytes."
  32)

(def ^:const sec1-uncompressed-prefix
  "First byte of an uncompressed SEC1 EC point encoding."
  0x04)

(def ^:const p256-coord-bytes
  "Each P-256 coordinate (X, Y) is 32 bytes."
  32)
