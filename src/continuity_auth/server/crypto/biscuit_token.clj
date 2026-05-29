(ns continuity-auth.server.crypto.biscuit-token
  "Biscuit capability-token minting (offline authorisation, v0.5.0).

  A successful caller can obtain a short-lived Biscuit that asserts the
  trust signal continuity-auth uniquely owns — its identity, the tier it
  has earned, the audience (host) it is for, and an expiry. A host then
  verifies the token OFFLINE with the published root public key (any of
  Biscuit's ~10 language libraries) and allows/denies each action without
  re-calling `/v1/verify`.

  We mint with the real Biscuit format via `org.biscuitsec/biscuit`
  (`com.clevercloud.biscuit.*` at 2.3.1). The token carries minimal claims;
  the host writes all action-level authz policy in its own authorizer, so
  continuity-auth never learns the host's action vocabulary.

  The root signing key is a 32-byte Ed25519 seed held in a keystore file.
  Keystore handling mirrors `continuity-auth.server.crypto.verifier-box`
  (precedence: env raw → configured `:key-b64` → keyfile → auto-generate
  0600 file). The key is SEPARATE from the IP-HMAC and kf-wrap keys
  (purpose separation): a distinct env var and default path. The *public*
  half is published (`root-public-key-hex`) for hosts to pin; losing the
  private keyfile invalidates every outstanding token's verifiability under
  the old pubkey — back it up alongside the Datalevin store."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [continuity-auth.envelope :as envelope])
  (:import
   (com.clevercloud.biscuit.crypto KeyPair)
   (com.clevercloud.biscuit.token Biscuit)
   (java.nio.file Files)
   (java.nio.file.attribute PosixFilePermissions)
   (java.security SecureRandom)
   (java.time Instant)
   (java.time.temporal ChronoUnit)))

(def ^:const seed-bytes 32)             ; Ed25519 seed

;; -- keystore (mirrors verifier-box / ip-hmac) ----------------------------

(defn- blank? [^String s]
  (or (nil? s) (.isBlank s)))

(defn- env [^String name] (System/getenv name))

(defn- read-keyfile
  ^bytes [^String path]
  (let [{:keys [secret-b64]} (edn/read-string (slurp path))
        bs (envelope/b64url-decode secret-b64)]
    (when-not (= seed-bytes (alength bs))
      (throw (ex-info "biscuit root keyfile: wrong length"
                      {:path path :expected seed-bytes :got (alength bs)})))
    bs))

(defn- generate-seed ^bytes []
  (let [bs (byte-array seed-bytes)]
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
  (let [seed (generate-seed)
        f    (io/file path)]
    (when-let [parent (.getParentFile f)]
      (.mkdirs parent))
    (spit f (pr-str {:secret-b64 (envelope/b64url-encode seed)}))
    (restrict-perms! (.toPath f))
    seed))

(defn resolve-key-path
  "Return the configured/default biscuit-root keyfile path. Env
  `CONTINUITY_AUTH_BISCUIT_ROOT_KEY_PATH` overrides the config value."
  ^String [{:keys [key-path]}]
  (let [from-env (env "CONTINUITY_AUTH_BISCUIT_ROOT_KEY_PATH")]
    (cond
      (not (blank? from-env)) from-env
      (not (blank? key-path)) key-path
      :else                   "/var/lib/continuity-auth/biscuit-root.key")))

(defn load-or-create-seed!
  "Resolve the 32-byte Ed25519 root seed.

  `config` is the `:biscuit` stanza from config.edn:
    {:key-path <string>  ; default-path fallback
     :key-b64  <string>} ; direct env-supplied seed (takes precedence)"
  ^bytes [{:keys [key-b64] :as config}]
  (let [from-env-key (env "CONTINUITY_AUTH_BISCUIT_ROOT_KEY")]
    (cond
      (not (blank? from-env-key))
      (let [bs (envelope/b64url-decode from-env-key)]
        (when-not (= seed-bytes (alength bs))
          (throw (ex-info "CONTINUITY_AUTH_BISCUIT_ROOT_KEY: wrong length"
                          {:expected seed-bytes :got (alength bs)})))
        bs)

      (not (blank? key-b64))
      (let [bs (envelope/b64url-decode key-b64)]
        (when-not (= seed-bytes (alength bs))
          (throw (ex-info "biscuit :key-b64: wrong length"
                          {:expected seed-bytes :got (alength bs)})))
        bs)

      :else
      (let [path (resolve-key-path config)]
        (if (.exists (io/file path))
          (read-keyfile path)
          (write-new-keyfile! path))))))

;; -- keypair / pubkey -----------------------------------------------------

(defn keypair-from-seed
  "Construct the (immutable, thread-safe) Biscuit root `KeyPair` from a
  32-byte Ed25519 seed."
  ^KeyPair [^bytes seed]
  (KeyPair. seed))

(defn root-public-key-hex
  "Uppercase hex of the root Ed25519 public key — published for hosts to
  pin and verify tokens offline."
  ^String [^KeyPair kp]
  (.toHex (.public_key kp)))

;; -- mint -----------------------------------------------------------------

;; Fact string values are interpolated into Datalog. Our values are a UUID,
;; a tier keyword name, and an audience the handler has already constrained
;; to a safe charset — but guard at the seam regardless: a `"` or newline
;; would break out of the quoted term.
(defn- safe-value? [^String s]
  (and (string? s)
       (not (re-find #"[\"\\\r\n]" s))))

(defn- quoted [^String s]
  (when-not (safe-value? s)
    (throw (ex-info "unsafe biscuit fact value" {:value s})))
  (str \" s \"))

(defn mint
  "Mint a base64url Biscuit asserting the caller's trust state, signed by
  the root `kp`. `claims`:
    {:identity-ref <uuid-string>
     :tier         <keyword | string>   ; e.g. :tracked
     :audience     <string>             ; the host id
     :expires-at   <java.time.Instant>} ; token TTL boundary

  Authority block:
    identity(\"<ref>\"); tier(\"<tier>\"); audience(\"<aud>\");
    check if time($t), $t <= <expires-at RFC3339>;"
  ^String [^KeyPair kp {:keys [identity-ref tier audience expires-at]}]
  (let [tier-str (name tier)
        ;; second-precision RFC3339 keeps the date literal clean
        exp-str  (-> ^Instant expires-at (.truncatedTo ChronoUnit/SECONDS) .toString)]
    (-> (Biscuit/builder kp)
        (.add_authority_fact (str "identity(" (quoted (str identity-ref)) ")"))
        (.add_authority_fact (str "tier(" (quoted tier-str) ")"))
        (.add_authority_fact (str "audience(" (quoted audience) ")"))
        (.add_authority_check (str "check if time($t), $t <= " exp-str))
        (.build)
        (.serialize_b64url))))
