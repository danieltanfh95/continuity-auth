(ns continuity-auth.server.crypto.verifier-box
  "At-rest wrapping for the knowledge-factor verifier (v6).

  The knowledge-factor verifier is an Ed25519 *public* key, derived
  client-side from `Argon2id(secret, salt)`. Stored as a plain public key
  it would let an operator who dumps the Datalevin store mount an offline
  dictionary attack (derive a candidate key from a guessed password, check
  the public key matches). To match the `:tuple/ip-hash` property — \"an
  operator dumping the store sees opaque material without the keyfile\" —
  we encrypt the verifier under a server-side keystore secret with
  AES-256-GCM. A DB-only dump then yields ciphertext with no verifier to
  check guesses against, so the offline attack is blocked; only a leak of
  BOTH the DB and the kf-wrap keyfile re-enables it (then bounded by
  Argon2id's memory hardness).

  Signature-based proof needs the pubkey bytes back at reclaim time, so the
  wrap is reversible encryption (GCM), not an HMAC.

  Keystore handling mirrors `continuity-auth.server.crypto.ip-hmac`
  (precedence: env raw → configured `:key-b64` → keyfile → auto-generate
  0600 file). The key is SEPARATE from the IP-HMAC key (purpose
  separation): a distinct env var and default path. Losing the keyfile
  makes every stored verifier permanently unrecoverable — reclaim breaks,
  but normal device-key auth is unaffected. Back it up alongside the
  Datalevin store and the IP-HMAC key."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [continuity-auth.envelope :as envelope])
  (:import
   (java.nio.file Files)
   (java.nio.file.attribute PosixFilePermissions)
   (java.security SecureRandom)
   (javax.crypto Cipher)
   (javax.crypto.spec GCMParameterSpec SecretKeySpec)))

(def ^:const key-bytes 32)          ; AES-256
(def ^:const iv-bytes  12)          ; GCM standard nonce length
(def ^:const tag-bits  128)         ; GCM auth tag

;; -- keystore (mirrors ip-hmac) -------------------------------------------

(defn- blank? [^String s]
  (or (nil? s) (.isBlank s)))

(defn- env [^String name] (System/getenv name))

(defn- read-keyfile
  ^bytes [^String path]
  (let [{:keys [secret-b64]} (edn/read-string (slurp path))
        bs (envelope/b64url-decode secret-b64)]
    (when-not (= key-bytes (alength bs))
      (throw (ex-info "kf-wrap keyfile: wrong length"
                      {:path path :expected key-bytes :got (alength bs)})))
    bs))

(defn- generate-secret ^bytes []
  (let [bs (byte-array key-bytes)]
    (.nextBytes (SecureRandom.) bs)
    bs))

(defn- restrict-perms! [path]
  (try
    (Files/setPosixFilePermissions
     path (PosixFilePermissions/fromString "rw-------"))
    (catch UnsupportedOperationException _
      (binding [*out* *err*]
        (println (str "WARN: cannot set POSIX perms on " path
                      " — non-POSIX filesystem"))))))

(defn- write-new-keyfile! ^bytes [^String path]
  (let [secret (generate-secret)
        f      (io/file path)]
    (when-let [parent (.getParentFile f)]
      (.mkdirs parent))
    (spit f (pr-str {:secret-b64 (envelope/b64url-encode secret)}))
    (restrict-perms! (.toPath f))
    secret))

(defn resolve-key-path
  "Return the configured/default kf-wrap keyfile path. Env
  `CONTINUITY_AUTH_KF_WRAP_KEY_PATH` overrides the config value."
  ^String [{:keys [key-path]}]
  (let [from-env (env "CONTINUITY_AUTH_KF_WRAP_KEY_PATH")]
    (cond
      (not (blank? from-env)) from-env
      (not (blank? key-path)) key-path
      :else                   "/var/lib/continuity-auth/kf-wrap.key")))

(defn load-or-create-key!
  "Resolve the kf-wrap secret. Returns a 32-byte array.

  `config` is the `:kf-wrap` stanza from config.edn:
    {:key-path <string>  ; default-path fallback
     :key-b64  <string>} ; direct env-supplied secret (takes precedence)"
  ^bytes [{:keys [key-b64] :as config}]
  (let [from-env-key (env "CONTINUITY_AUTH_KF_WRAP_KEY")]
    (cond
      (not (blank? from-env-key))
      (let [bs (envelope/b64url-decode from-env-key)]
        (when-not (= key-bytes (alength bs))
          (throw (ex-info "CONTINUITY_AUTH_KF_WRAP_KEY: wrong length"
                          {:expected key-bytes :got (alength bs)})))
        bs)

      (not (blank? key-b64))
      (let [bs (envelope/b64url-decode key-b64)]
        (when-not (= key-bytes (alength bs))
          (throw (ex-info "kf-wrap :key-b64: wrong length"
                          {:expected key-bytes :got (alength bs)})))
        bs)

      :else
      (let [path (resolve-key-path config)]
        (if (.exists (io/file path))
          (read-keyfile path)
          (write-new-keyfile! path))))))

;; -- wrap / unwrap --------------------------------------------------------

(defn wrap
  "Encrypt `plaintext` (the canonical kf-pubkey bytes) under `secret` with
  AES-256-GCM. Returns `IV(12) ‖ ciphertext+tag`. A fresh random IV is
  generated per call, so wrapping the same pubkey twice yields different
  ciphertext."
  ^bytes [^bytes secret ^bytes plaintext]
  (let [iv     (byte-array iv-bytes)
        _      (.nextBytes (SecureRandom.) iv)
        cipher (doto (Cipher/getInstance "AES/GCM/NoPadding")
                 (.init Cipher/ENCRYPT_MODE
                        (SecretKeySpec. secret "AES")
                        (GCMParameterSpec. tag-bits iv)))
        ct     (.doFinal cipher plaintext)
        out    (byte-array (+ iv-bytes (alength ct)))]
    (System/arraycopy iv 0 out 0 iv-bytes)
    (System/arraycopy ct 0 out iv-bytes (alength ct))
    out))

(defn unwrap
  "Decrypt a `wrap`ped blob (`IV(12) ‖ ciphertext+tag`) under `secret`,
  returning the original plaintext bytes. Throws on a wrong secret or any
  tampering (GCM tag mismatch) — callers MUST treat a throw as an
  unverifiable verifier and fail uniformly (E_UNAUTHORIZED)."
  ^bytes [^bytes secret ^bytes blob]
  (when (<= (alength blob) iv-bytes)
    (throw (ex-info "kf verifier blob too short" {:len (alength blob)})))
  (let [iv     (java.util.Arrays/copyOfRange blob 0 iv-bytes)
        ct     (java.util.Arrays/copyOfRange blob iv-bytes (alength blob))
        cipher (doto (Cipher/getInstance "AES/GCM/NoPadding")
                 (.init Cipher/DECRYPT_MODE
                        (SecretKeySpec. secret "AES")
                        (GCMParameterSpec. tag-bits iv)))]
    (.doFinal cipher ct)))
