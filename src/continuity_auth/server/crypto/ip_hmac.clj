(ns continuity-auth.server.crypto.ip-hmac
  "HMAC-based pseudonymisation for client IP addresses.

  The server stores `:tuple/ip-hash` (hex of HMAC-SHA256(ip)) rather than
  the raw IP. Equality under a fixed key is preserved — same IP → same
  hash — so cluster grouping is unchanged. The raw IP is exposed only
  within the request middleware chain (for datacenter-CIDR checks);
  it is never persisted, never logged.

  Keystore handling (precedence at startup):

    1. Env `CONTINUITY_AUTH_IP_HMAC_KEY` (base64, 32 bytes): use directly. Never
       written to disk.
    2. Else path from `CONTINUITY_AUTH_IP_HMAC_KEY_PATH` (or the configured
       `:key-path`). Read EDN `{:secret-b64 \"...\"}`.
    3. If neither resolves to an existing file, generate 32
       `SecureRandom` bytes, write the EDN file at the resolved path
       with POSIX `rw-------` (0600), then return the bytes.

  Losing the keyfile fragments the cluster groupings for every existing
  tuple. The runbook records this — the file must be backed up alongside
  the Datalevin store."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [continuity-auth.envelope :as envelope])
  (:import
   (java.nio.file Files Path)
   (java.nio.file.attribute PosixFilePermissions)
   (java.security SecureRandom)
   (javax.crypto Mac)
   (javax.crypto.spec SecretKeySpec)))

(def ^:const key-bytes 32)

(defn- blank? [^String s]
  (or (nil? s) (.isBlank s)))

(defn- env [^String name]
  (System/getenv name))

(defn- read-keyfile
  "Read the keystore file at `path`. Returns the raw 32-byte secret or
  throws if the file is malformed or wrong length."
  ^bytes [^String path]
  (let [{:keys [secret-b64]} (edn/read-string (slurp path))
        bs (envelope/b64url-decode secret-b64)]
    (when-not (= key-bytes (alength bs))
      (throw (ex-info "ip-hmac keyfile: wrong length"
                      {:path path :expected key-bytes :got (alength bs)})))
    bs))

(defn- generate-secret ^bytes []
  (let [bs (byte-array key-bytes)]
    (.nextBytes (SecureRandom.) bs)
    bs))

(defn- restrict-perms!
  "Set POSIX `rw-------` on `path`. No-op (with warning) on non-POSIX
  filesystems."
  [^Path path]
  (try
    (Files/setPosixFilePermissions
     path
     (PosixFilePermissions/fromString "rw-------"))
    (catch UnsupportedOperationException _
      (binding [*out* *err*]
        (println (str "WARN: cannot set POSIX perms on " path
                      " — non-POSIX filesystem"))))))

(defn- write-new-keyfile!
  "Generate a fresh 32-byte secret, write it to `path` (parents
  created), restrict perms to `0600`, and return the secret."
  ^bytes [^String path]
  (let [secret (generate-secret)
        f      (io/file path)]
    (when-let [parent (.getParentFile f)]
      (.mkdirs parent))
    (spit f (pr-str {:secret-b64 (envelope/b64url-encode secret)}))
    (restrict-perms! (.toPath f))
    secret))

(defn resolve-key-path
  "Return the configured/default keyfile path. Env
  `CONTINUITY_AUTH_IP_HMAC_KEY_PATH` overrides the config value."
  ^String [{:keys [key-path]}]
  (let [from-env (env "CONTINUITY_AUTH_IP_HMAC_KEY_PATH")]
    (cond
      (not (blank? from-env))  from-env
      (not (blank? key-path))  key-path
      :else                    "/var/lib/continuity-auth/ip-hmac.key")))

(defn load-or-create-key!
  "Resolve the IP-HMAC secret. Returns a 32-byte array.

  `config` is the `:ip-hmac` stanza from config.edn:
    {:key-path <string>  ; default-path fallback
     :key-b64  <string>} ; direct env-supplied secret (takes precedence)"
  ^bytes [{:keys [key-b64] :as config}]
  (let [from-env-key (env "CONTINUITY_AUTH_IP_HMAC_KEY")]
    (cond
      (not (blank? from-env-key))
      (let [bs (envelope/b64url-decode from-env-key)]
        (when-not (= key-bytes (alength bs))
          (throw (ex-info "CONTINUITY_AUTH_IP_HMAC_KEY: wrong length"
                          {:expected key-bytes :got (alength bs)})))
        bs)

      (not (blank? key-b64))
      (let [bs (envelope/b64url-decode key-b64)]
        (when-not (= key-bytes (alength bs))
          (throw (ex-info "ip-hmac :key-b64: wrong length"
                          {:expected key-bytes :got (alength bs)})))
        bs)

      :else
      (let [path (resolve-key-path config)]
        (if (.exists (io/file path))
          (read-keyfile path)
          (write-new-keyfile! path))))))

(defn hmac-bytes
  "Raw HMAC-SHA256(secret, msg)."
  ^bytes [^bytes secret ^bytes msg]
  (let [mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. secret "HmacSHA256"))
    (.doFinal mac msg)))

(defn- bytes->hex ^String [^bytes bs]
  (let [sb (StringBuilder. (* 2 (alength bs)))]
    (dotimes [i (alength bs)]
      (let [b (bit-and (aget bs i) 0xff)]
        (when (< b 0x10) (.append sb "0"))
        (.append sb (Integer/toHexString b))))
    (.toString sb)))

(defn hmac-ip-hex
  "Return the canonical IP-hash: lowercase hex of HMAC-SHA256(secret,
  utf8(ip)). `ip` is the textual IP address as resolved by the trusted
  proxy header — no canonicalisation is performed beyond what the
  upstream proxy emits."
  ^String [^bytes secret ^String ip]
  (when (or (nil? ip) (str/blank? ip))
    (throw (ex-info "hmac-ip-hex: nil/blank ip" {})))
  (bytes->hex (hmac-bytes secret (.getBytes ip "UTF-8"))))
