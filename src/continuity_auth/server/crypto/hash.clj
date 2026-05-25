(ns continuity-auth.server.crypto.hash
  "SHA-256 digest helper. Single-shot synchronous hashing for short inputs
  (envelope bodies, pubkey thumbprints, nonces). Uses the JDK SUN provider."
  (:import
   (java.security MessageDigest)))

(defn sha256
  "Return the SHA-256 digest of `bs` as a byte array."
  ^bytes [^bytes bs]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (.digest md bs)))

(defn sha256-of-utf8
  "Return the SHA-256 digest of the UTF-8 encoding of string `s`."
  ^bytes [^String s]
  (sha256 (.getBytes s "UTF-8")))

(defn constant-time-equal?
  "Constant-time byte-array equality. Compares all bytes regardless of
  early mismatch to avoid leaking length-or-position information via
  wall-clock timing. Returns true iff `a` and `b` are byte arrays of
  equal length with equal contents."
  [^bytes a ^bytes b]
  (MessageDigest/isEqual a b))
