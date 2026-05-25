(ns continuity-auth.admin.cli
  "Command-line client for continuity-auth admin endpoints.

  Talks to a running server via HMAC-authenticated POSTs/GETs against
  the `/v1/admin/*` surface. The server's admin keystore must contain
  this CLI's key-id; the secret-file holds the corresponding raw key
  (32 bytes, base64url-encoded).

  Usage:

      cauth-admin --server URL --key-id ID --secret-file PATH SUBCOMMAND [ARGS]

      Subcommands:
        revoke-key <key-id-b64>     Force-revoke a pubkey
        config                      Dump effective server config

  The CLI prints the parsed JSON response to stdout and exits 0 on
  success; on any non-2xx response or auth failure it prints the body
  to stderr and exits 1."
  (:require
   [clojure.string :as str]
   [clojure.tools.cli :as cli]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.admin.hmac :as hmac]
   [jsonista.core :as json])
  (:import
   (java.net URI)
   (java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
                  HttpResponse$BodyHandlers)
   (java.security SecureRandom)))

(def ^:private json-mapper
  (json/object-mapper {:decode-key-fn keyword :encode-key-fn name}))

(defn- random-nonce ^bytes []
  (let [b (byte-array 16)]
    (.nextBytes (SecureRandom.) b)
    b))

(defn- iso8601-now []
  (let [fmt (java.text.SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        _   (.setTimeZone fmt (java.util.TimeZone/getTimeZone "UTC"))]
    (.format fmt (java.util.Date.))))

(defn- load-secret
  "Read the admin secret from `path`. Accepts either raw bytes (32) or
  a base64url-encoded string."
  ^bytes [^String path]
  (let [content (slurp path)
        trimmed (str/trim content)]
    (if (re-matches #"^[A-Za-z0-9_\-=]+$" trimmed)
      (envelope/b64url-decode trimmed)
      (.getBytes trimmed "UTF-8"))))

(defn- sign-request
  "Compute the HMAC signature headers for an outgoing admin request.

  Inputs:
    method  — HTTP method string (\"GET\", \"POST\", ...)
    path    — request path including any query string
    body    — request body as a byte array (use 0-length for GETs)
    key-id  — admin key identifier
    secret  — raw bytes of the HMAC key

  Returns:
    {:headers <map of header-name → string>}
    suitable for setting on the outgoing HttpRequest."
  [{:keys [method path body key-id secret]}]
  (let [ts       (iso8601-now)
        nonce    (random-nonce)
        body-sha (hmac/sha256 (or body (byte-array 0)))
        input    (hmac/signing-input
                  {:method      method
                   :path        path
                   :body-sha256 body-sha
                   :ts          ts
                   :nonce       nonce})
        sig      (hmac/hmac-sha256 secret input)]
    {:headers {"X-Admin-Key-Id" key-id
               "X-Admin-Ts"     ts
               "X-Admin-Nonce"  (envelope/b64url-encode nonce)
               "X-Admin-Sig"    (envelope/b64url-encode sig)}}))

(defn- send-request
  "Issue the HTTP request and return {:status, :body (parsed JSON or string)}."
  [{:keys [server method path body headers]}]
  (let [client (HttpClient/newHttpClient)
        builder (.. (HttpRequest/newBuilder)
                    (uri (URI. (str server path))))
        _      (doseq [[k v] headers]
                 (.header builder k v))
        _      (case method
                 "GET"  (.GET builder)
                 "POST" (do (.header builder "Content-Type" "application/json")
                            (.POST builder
                                   (HttpRequest$BodyPublishers/ofByteArray
                                    (or body (byte-array 0))))))
        req    (.build builder)
        resp   (.send client req (HttpResponse$BodyHandlers/ofString))
        text   (.body resp)]
    {:status (.statusCode resp)
     :body   (try (json/read-value text json-mapper)
                  (catch Exception _ text))}))

;; -- subcommands -----------------------------------------------------------

(defn- do-revoke-key [{:keys [server key-id secret]} key-id-b64]
  (let [path   "/v1/admin/revoke-key"
        body   (.getBytes (json/write-value-as-string {:key_id key-id-b64} json-mapper)
                          "UTF-8")
        signed (sign-request {:method "POST" :path path :body body
                              :key-id key-id :secret secret})]
    (send-request (merge {:server server :method "POST" :path path :body body}
                         signed))))

(defn- do-config [{:keys [server key-id secret]}]
  (let [path   "/v1/admin/config"
        signed (sign-request {:method "GET" :path path :body nil
                              :key-id key-id :secret secret})]
    (send-request (merge {:server server :method "GET" :path path}
                         signed))))

;; -- main ------------------------------------------------------------------

(def ^:private cli-spec
  [["-s" "--server URL" "continuity-auth server base URL"
    :default "http://localhost:8080"]
   ["-k" "--key-id ID" "admin key identifier (matches keystore entry)"]
   ["-f" "--secret-file PATH" "path to file containing the admin secret"]
   ["-h" "--help"]])

(defn- usage [summary]
  (str "cauth-admin — continuity-auth admin CLI\n\n"
       "Options:\n" summary "\n\n"
       "Subcommands:\n"
       "  revoke-key <key-id-b64>     Force-revoke a pubkey\n"
       "  config                       Dump effective server config\n"))

(defn -main [& args]
  (let [{:keys [options arguments errors summary]} (cli/parse-opts args cli-spec)]
    (cond
      errors
      (do (run! println errors) (System/exit 1))

      (or (:help options) (empty? arguments))
      (do (println (usage summary)) (System/exit (if (:help options) 0 1)))

      :else
      (let [{:keys [server key-id secret-file]} options
            _      (when-not (and key-id secret-file)
                     (binding [*out* *err*]
                       (println "--key-id and --secret-file are required"))
                     (System/exit 1))
            secret (load-secret secret-file)
            ctx    {:server server :key-id key-id :secret secret}
            [sub & rest] arguments
            result (case sub
                     "revoke-key" (do-revoke-key ctx (first rest))
                     "config"     (do-config ctx)
                     (do (binding [*out* *err*]
                           (println "unknown subcommand:" sub))
                         (System/exit 1)))]
        (println (json/write-value-as-string (:body result) json-mapper))
        (System/exit (if (= 200 (:status result)) 0 1))))))
