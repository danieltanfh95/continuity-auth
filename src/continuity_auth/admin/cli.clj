(ns continuity-auth.admin.cli
  "Command-line client for continuity-auth admin endpoints.

  Talks to a running server via HMAC-authenticated POSTs/GETs against
  the `/v1/admin/*` surface. The server's admin keystore must contain
  this CLI's key-id; the secret-file holds the corresponding raw key
  (32 bytes, base64url-encoded).

  Usage (via the unified `continuity` binary):

      continuity admin revoke-key <key-id-b64>    Force-revoke a pubkey
      continuity admin config                     Dump effective server config

  Connection details are taken from env vars (or, when invoked via
  `clojure -M:admin`, from --server / --key-id / --secret-file flags):

      CAUTH_ENDPOINT             server base URL (default http://localhost:8080)
      CAUTH_ADMIN_KEY_ID         admin key identifier (matches keystore entry)
      CAUTH_ADMIN_SECRET_FILE    path to file containing the admin secret

  The CLI prints the parsed JSON response to stdout and returns exit 0
  on success; on any non-2xx response or auth failure it prints the
  body to stderr and returns 1."
  (:require
   [clojure.string :as str]
   [clojure.tools.cli :as cli]
   [continuity-auth.client.json :as json]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.admin.hmac :as hmac]
   [continuity-auth.server.crypto.hash :as hash])
  (:import
   (java.net URI)
   (java.net.http HttpClient HttpRequest HttpRequest$Builder
                  HttpRequest$BodyPublishers HttpResponse$BodyHandlers)
   (java.security SecureRandom)))

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
        body-sha (hash/sha256 (or body (byte-array 0)))
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

(defn- apply-headers
  "Apply each {name → value} pair to the HttpRequest builder. Returns
  the builder so it can be threaded."
  ^HttpRequest$Builder [^HttpRequest$Builder builder headers]
  (reduce-kv (fn [^HttpRequest$Builder b k v] (.header b k v))
             builder
             headers))

(defn- apply-method
  "Bind the HTTP method and (for POST) body+content-type onto the
  builder. Returns the builder."
  ^HttpRequest$Builder [^HttpRequest$Builder builder method ^bytes body]
  (case method
    "GET"  (.GET builder)
    "POST" (-> builder
               (.header "Content-Type" "application/json")
               (.POST (HttpRequest$BodyPublishers/ofByteArray
                       (or body (byte-array 0)))))))

(defn- send-request
  "Issue the HTTP request and return {:status, :body (parsed JSON or string)}."
  [{:keys [server method path body headers]}]
  (let [req  (-> (HttpRequest/newBuilder)
                 (.uri (URI. (str server path)))
                 (apply-headers headers)
                 (apply-method method body)
                 (.build))
        resp (.send (HttpClient/newHttpClient)
                    req
                    (HttpResponse$BodyHandlers/ofString))
        text (.body resp)]
    {:status (.statusCode resp)
     :body   (try (json/<-json text)
                  (catch Exception _ text))}))

;; -- subcommands -----------------------------------------------------------

(defn- do-revoke-key [{:keys [server key-id secret]} key-id-b64]
  (let [path   "/v1/admin/revoke-key"
        body   (.getBytes ^String (json/->json {:key_id key-id-b64}) "UTF-8")
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

;; -- context ---------------------------------------------------------------

(defn- env-or [k]
  (let [v (System/getenv k)]
    (when-not (str/blank? v) v)))

(defn- resolve-context
  "Build the connection context. Flags override env vars; env vars
  default to CAUTH_* equivalents. Returns {:server :key-id :secret} or
  {:error \"reason\"}."
  [{:keys [server key-id secret-file]}]
  (let [server      (or server  (env-or "CAUTH_ENDPOINT")  "http://localhost:8080")
        key-id      (or key-id  (env-or "CAUTH_ADMIN_KEY_ID"))
        secret-file (or secret-file (env-or "CAUTH_ADMIN_SECRET_FILE"))]
    (cond
      (not key-id)
      {:error "missing admin key-id (set CAUTH_ADMIN_KEY_ID or pass --key-id)"}

      (not secret-file)
      {:error "missing admin secret file (set CAUTH_ADMIN_SECRET_FILE or pass --secret-file)"}

      :else
      (try
        {:server server
         :key-id key-id
         :secret (load-secret secret-file)}
        (catch Exception e
          {:error (str "could not load secret file " secret-file ": " (.getMessage e))})))))

(defn- dispatch
  "Run the named subcommand under the resolved context. Returns
  {:status :body} from the server, or {:error \"...\"} on usage error."
  [ctx subcommand args]
  (case subcommand
    :revoke-key
    (if-let [k (first args)]
      (do-revoke-key ctx k)
      {:error "usage: revoke-key <key-id-b64>"})

    :config
    (do-config ctx)

    {:error (str "unknown subcommand: " (name subcommand))}))

(defn- print-result [result]
  (cond
    (:error result)
    (do (binding [*out* *err*] (println (:error result))) 1)

    :else
    (do (println (json/->json (:body result)))
        (if (= 200 (:status result)) 0 1))))

;; -- public entry points --------------------------------------------------

(defn run-admin
  "Dispatcher-facing entry. Called by `continuity-auth.client.dispatch`
  when the user invokes `continuity admin …`.

  Argument shape:
    {:subcommand :revoke-key | :config | nil
     :args       [string…]
     :opts       {…}}   ; reserved for future flag-passing

  Returns an integer exit code; does not call System/exit."
  [{:keys [subcommand args]}]
  (cond
    (nil? subcommand)
    (do (binding [*out* *err*]
          (println "usage: continuity admin <subcommand> [ARGS…]")
          (println "subcommands: revoke-key, config"))
        2)

    :else
    (let [ctx (resolve-context {})]
      (if (:error ctx)
        (do (binding [*out* *err*] (println (:error ctx))) 1)
        (print-result (dispatch ctx subcommand args))))))

;; -- main ------------------------------------------------------------------

(def ^:private cli-spec
  [["-s" "--server URL" "continuity-auth server base URL"
    :default-fn (fn [_] (or (env-or "CAUTH_ENDPOINT") "http://localhost:8080"))]
   ["-k" "--key-id ID" "admin key identifier (matches keystore entry)"]
   ["-f" "--secret-file PATH" "path to file containing the admin secret"]
   ["-h" "--help"]])

(defn- usage [summary]
  (str "continuity admin — continuity-auth admin CLI\n\n"
       "Options:\n" summary "\n\n"
       "Subcommands:\n"
       "  revoke-key <key-id-b64>     Force-revoke a pubkey\n"
       "  config                      Dump effective server config\n"))

(defn -main
  "Entry for `clojure -M:admin` style invocation. Returns nothing useful;
  calls System/exit with the proper code. Dispatcher-style callers
  should use `run-admin` instead."
  [& args]
  (let [{:keys [options arguments errors summary]} (cli/parse-opts args cli-spec)]
    (cond
      errors
      (do (run! println errors) (System/exit 1))

      (or (:help options) (empty? arguments))
      (do (println (usage summary)) (System/exit (if (:help options) 0 1)))

      :else
      (let [ctx (resolve-context (select-keys options [:server :key-id :secret-file]))]
        (if (:error ctx)
          (do (binding [*out* *err*] (println (:error ctx))) (System/exit 1))
          (let [[sub & rest] arguments
                code (print-result (dispatch ctx (keyword (str/replace sub "_" "-")) rest))]
            (System/exit code)))))))
