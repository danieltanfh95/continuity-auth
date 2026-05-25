(ns continuity-auth.server.admin.hmac
  "HMAC verification for admin endpoints.

  Symmetric-key authentication for ops/admin calls. Distinct from the
  envelope signature path used by user requests: admin endpoints are
  authenticated by HMAC-SHA256 over

      method || \"\\n\" || path || \"\\n\" || body-sha256 || \"\\n\" || ts || \"\\n\" || nonce

  using a per-key shared secret. Keys are loaded at startup from a file
  whose path is set in config (`:hmac/:admin-keys-path`). The keystore
  shape on disk is

      {:keys [{:id          \"ops-01\"
               :secret-b64  \"<base64-encoded 32-byte secret>\"} ...]}

  The same nonce-cache used by signed envelopes guards against replay
  on the admin side; admin requests must include a 16-byte nonce in the
  X-Admin-Nonce header."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [continuity-auth.envelope :as envelope])
  (:import
   (javax.crypto Mac)
   (javax.crypto.spec SecretKeySpec)))

(defn load-keystore
  "Read the admin keystore from `path`. Returns a map of key-id (string)
  to raw secret bytes. Returns nil if `path` is blank/missing."
  [path]
  (when (and path (not (.isBlank ^String path)))
    (let [f (io/file path)]
      (when (.exists f)
        (let [{:keys [keys]} (edn/read-string (slurp f))]
          (into {}
                (map (fn [{:keys [id secret-b64]}]
                       (let [secret (envelope/b64url-decode secret-b64)]
                         [id secret])))
                keys))))))

(defn ^bytes signing-input
  "Build the canonical signing input bytes for an admin request. The
  shape is deterministic and matches the CLI's implementation."
  [{:keys [method path body-sha256 ts nonce]}]
  (let [parts [method "\n" path "\n"
               (envelope/b64url-encode body-sha256) "\n"
               ts "\n"
               (envelope/b64url-encode nonce)]
        joined (str/join parts)]
    (.getBytes ^String joined "UTF-8")))

(defn hmac-sha256
  "Compute HMAC-SHA256(secret, msg)."
  ^bytes [^bytes secret ^bytes msg]
  (let [mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. secret "HmacSHA256"))
    (.doFinal mac msg)))
