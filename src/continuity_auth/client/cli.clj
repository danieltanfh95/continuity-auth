(ns continuity-auth.client.cli
  "Babashka-compatible client CLI for the `continuity auth …` subcommand
  group. Provides:

      continuity auth init                 ; genkey via openssl + POST /v1/bootstrap
      continuity auth sign METHOD URL [BODY]
      continuity auth curl  ARGS…          ; wraps curl, attaches signed envelope
      continuity auth wget  ARGS…          ; wraps wget, attaches signed envelope
      continuity auth show                 ; print identity_ref + key thumbprint

  State lives under `$CAUTH_HOME` (default `${XDG_CONFIG_HOME:-~/.config}/
  continuity-auth`):

      $CAUTH_HOME/key.pem        ; Ed25519 PEM/PKCS8, openssl-compatible
      $CAUTH_HOME/identity.edn   ; identity_ref + pubkey + key_id + fp digest

  Env vars:
      CAUTH_ENDPOINT  default http://localhost:8080
      CAUTH_HOME      default $XDG_CONFIG_HOME/continuity-auth
      CAUTH_HOST_ID   optional host_user_id field on each envelope

  Shells out to openssl for Ed25519 keygen + sign so the on-disk key file
  is byte-identical to the one the `scripts/cauth-curl-example.sh` shell
  reference produces. Two implementations of the same protocol; both ship."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.pprint :as pprint]
   [clojure.string :as str]
   [continuity-auth.client.json :as json]
   [continuity-auth.envelope :as envelope])
  (:import
   (java.io ByteArrayOutputStream File)
   (java.net URI)
   (java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
                  HttpResponse$BodyHandlers)
   (java.security MessageDigest SecureRandom)
   (java.text SimpleDateFormat)
   (java.util Date TimeZone)))

;; -- env + paths -----------------------------------------------------------

(defn- getenv-or [k default]
  (or (System/getenv k) default))

(defn- xdg-config-dir []
  (or (System/getenv "XDG_CONFIG_HOME")
      (str (System/getProperty "user.home") "/.config")))

(defn- cauth-home []
  (getenv-or "CAUTH_HOME" (str (xdg-config-dir) "/continuity-auth")))

(defn- cauth-endpoint []
  (getenv-or "CAUTH_ENDPOINT" "http://localhost:8080"))

(defn- cauth-host-id []
  (getenv-or "CAUTH_HOST_ID" ""))

(defn- key-path  [] (str (cauth-home) "/key.pem"))
(defn- id-path   [] (str (cauth-home) "/identity.edn"))

(defn- ensure-home! []
  (let [d (File. ^String (cauth-home))]
    (when-not (.exists d) (.mkdirs d))))

;; -- bytes + shell helpers ------------------------------------------------

(defn- sha256 ^bytes [^bytes bs]
  (.digest (MessageDigest/getInstance "SHA-256") bs))

(defn- random-bytes ^bytes [n]
  (let [b (byte-array n)]
    (.nextBytes (SecureRandom.) b)
    b))

(defn- iso8601-now []
  (let [fmt (SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")]
    (.setTimeZone fmt (TimeZone/getTimeZone "UTC"))
    (.format fmt (Date.))))

(defn- read-all-bytes ^bytes [^java.io.InputStream is]
  (let [buf (byte-array 8192)
        out (ByteArrayOutputStream.)]
    (loop []
      (let [n (.read is buf)]
        (when (pos? n)
          (.write out buf 0 n)
          (recur))))
    (.toByteArray out)))

(defn- shell-exec
  "Run argv as an external process. Optional :stdin-bytes are written to
  stdin. Returns {:exit, :out (String), :err (String), :out-bytes}."
  [argv & {:keys [stdin-bytes]}]
  (let [pb   (doto (ProcessBuilder. ^java.util.List (vec argv))
               (.redirectErrorStream false))
        proc (.start pb)]
    (with-open [^java.io.OutputStream stdin (.getOutputStream proc)]
      (when stdin-bytes
        (.write stdin ^bytes stdin-bytes)))
    (let [out-bytes (read-all-bytes (.getInputStream proc))
          err-bytes (read-all-bytes (.getErrorStream proc))
          exit      (.waitFor proc)]
      {:exit      exit
       :out       (String. ^bytes out-bytes "UTF-8")
       :err       (String. ^bytes err-bytes "UTF-8")
       :out-bytes out-bytes})))

(defn- require-zero! [{:keys [exit err]} step]
  (when-not (zero? exit)
    (binding [*out* *err*]
      (println (str step " failed (exit " exit "):"))
      (println err))
    (throw (ex-info step {:exit exit :err err}))))

;; -- openssl wrappers -----------------------------------------------------

(defn- openssl-genpkey-ed25519! [^String pem-path]
  (require-zero!
   (shell-exec ["openssl" "genpkey" "-algorithm" "ed25519" "-out" pem-path])
   "openssl genpkey"))

(defn- openssl-pubkey-raw
  "Extract the raw 32-byte Ed25519 public key from `key.pem` by parsing
  the DER SPKI form: 12-byte prefix `30 2a 30 05 06 03 2b 65 70 03 21 00`,
  then 32 bytes of raw key."
  ^bytes [^String pem-path]
  (let [{:keys [out-bytes] :as r}
        (shell-exec ["openssl" "pkey" "-in" pem-path "-pubout" "-outform" "DER"])]
    (require-zero! r "openssl pkey -pubout")
    (when-not (= 44 (alength ^bytes out-bytes))
      (throw (ex-info "unexpected DER pubkey length" {:len (alength ^bytes out-bytes)})))
    (let [raw (byte-array 32)]
      (System/arraycopy ^bytes out-bytes 12 raw 0 32)
      raw)))

(defn- openssl-sign-ed25519
  "Produce the 64-byte raw Ed25519 signature of `bs` under `pem-path`."
  ^bytes [^String pem-path ^bytes bs]
  (let [tmp-in  (File/createTempFile "cauth-sign-in"  ".bin")
        tmp-out (File/createTempFile "cauth-sign-out" ".bin")]
    (try
      (with-open [os (io/output-stream tmp-in)]
        (.write os bs))
      (let [r (shell-exec ["openssl" "pkeyutl" "-sign"
                           "-inkey" pem-path "-rawin"
                           "-in"  (.getAbsolutePath tmp-in)
                           "-out" (.getAbsolutePath tmp-out)])]
        (require-zero! r "openssl pkeyutl -sign")
        (with-open [is (io/input-stream tmp-out)]
          (read-all-bytes is)))
      (finally
        (.delete tmp-in)
        (.delete tmp-out)))))

;; -- envelope construction ------------------------------------------------

(defn- build-envelope
  "Construct a wire envelope for the given (method, path, body-bytes)
  against the identity record loaded from disk. Signs with the on-disk
  key. Returns the JSON-safe wire map."
  [{:keys [method path body-bytes identity]}]
  (let [{:keys [pubkey-b64u key-id-b64u fp-digest-b64u host-user-id alg]} identity
        env-fields {:method       method
                    :path         path
                    :body-sha256  (sha256 (or body-bytes (byte-array 0)))
                    :ts           (iso8601-now)
                    :nonce        (random-bytes 16)
                    :fp-digest    (envelope/b64url-decode fp-digest-b64u)
                    :host-user-id (or host-user-id "")
                    :key-id       (envelope/b64url-decode key-id-b64u)}
        canon (envelope/canonical-bytes env-fields)
        sig   (openssl-sign-ed25519 (key-path) canon)
        env   (assoc env-fields :alg (keyword alg) :signature sig)]
    {:wire   (envelope/envelope->wire env)
     :pubkey pubkey-b64u}))

;; -- HTTP -----------------------------------------------------------------

(defn- http-post-json
  "POST JSON body to `url`. Returns {:status :body (parsed) :raw-body}."
  [^String url ^String json-body]
  (let [client (HttpClient/newHttpClient)
        req    (-> (HttpRequest/newBuilder (URI. url))
                   (.header "Content-Type" "application/json")
                   (.POST (HttpRequest$BodyPublishers/ofString json-body))
                   (.build))
        resp   (.send client req (HttpResponse$BodyHandlers/ofString))
        text   (.body resp)]
    {:status   (.statusCode resp)
     :raw-body text
     :body     (try (json/<-json text) (catch Exception _ text))}))

;; -- identity store -------------------------------------------------------

(defn- read-identity []
  (let [f (File. ^String (id-path))]
    (when (.exists f)
      (edn/read-string (slurp f)))))

(defn- write-identity! [m]
  (ensure-home!)
  (spit (id-path) (with-out-str (pprint/pprint m))))

(defn- require-identity! []
  (or (read-identity)
      (do (binding [*out* *err*]
            (println "No identity initialised. Run: continuity auth init"))
          (throw (ex-info "no-identity" {})))))

;; -- subcommands ----------------------------------------------------------

(defn- cmd-init [_opts]
  (ensure-home!)
  (let [pem    (key-path)
        id-f   (File. ^String (id-path))
        _      (when (.exists ^File (File. ^String pem))
                 (binding [*out* *err*]
                   (println (str "key already exists at " pem
                                 "; refusing to overwrite. Move it aside if you want a fresh one.")))
                 (throw (ex-info "key-exists" {:path pem})))
        _      (openssl-genpkey-ed25519! pem)
        pkraw  (openssl-pubkey-raw pem)
        key-id (sha256 pkraw)
        fp-d   (random-bytes 32)
        host   (cauth-host-id)
        env-pkg (build-envelope
                 {:method "POST" :path "/v1/bootstrap" :body-bytes nil
                  :identity {:pubkey-b64u    (envelope/b64url-encode pkraw)
                             :key-id-b64u    (envelope/b64url-encode key-id)
                             :fp-digest-b64u (envelope/b64url-encode fp-d)
                             :host-user-id   host
                             :alg            :ed25519}})
        ;; bootstrap-body has the envelope INSIDE so body-sha256 must be
        ;; recomputed once the body is built. Re-sign with the canonical
        ;; bytes that the server will reconstruct from the wire envelope.
        ;; The envelope-check on the server reconstructs from envelope fields,
        ;; NOT from request body bytes, so this is fine: the server reads
        ;; (:envelope body), parses it, recomputes canonical bytes from those
        ;; fields, and verifies. The body-sha256 in the envelope refers to
        ;; the request body the envelope is *signing for*. For bootstrap
        ;; we use empty body — the envelope itself is the credential, not
        ;; the JSON wrapper. (See server.http.envelope-check :: route binding.)
        body-map  {:envelope (:wire env-pkg)
                   :pubkey   (:pubkey env-pkg)
                   :alg      "ed25519"}
        body-json (json/->json body-map)
        resp      (http-post-json (str (cauth-endpoint) "/v1/bootstrap")
                                  body-json)]
    (if (and (#{200 201} (:status resp))
             (:identity_ref (:body resp)))
      (let [id-rec {:identity-ref   (:identity_ref (:body resp))
                    :alg            "ed25519"
                    :endpoint       (cauth-endpoint)
                    :pubkey-b64u    (envelope/b64url-encode pkraw)
                    :key-id-b64u    (envelope/b64url-encode key-id)
                    :fp-digest-b64u (envelope/b64url-encode fp-d)
                    :host-user-id   host
                    :created        (iso8601-now)}]
        (write-identity! id-rec)
        (.setReadable ^File (File. ^String (key-path)) false false)
        (.setReadable ^File (File. ^String (key-path)) true true)
        (println (str "Bootstrapped identity " (:identity-ref id-rec)
                      " at tier " (:tier (:body resp))))
        (println (str "Key:      " pem))
        (println (str "Identity: " (id-path)))
        (println (str "Endpoint: " (cauth-endpoint)))
        0)
      (do (binding [*out* *err*]
            (println (str "Bootstrap failed: HTTP " (:status resp)))
            (println (or (:raw-body resp) "")))
          (when (.exists id-f) (.delete id-f))
          1))))

(defn- cmd-show [_opts]
  (let [id (require-identity!)]
    (println (str "identity_ref:   " (:identity-ref id)))
    (println (str "alg:            " (:alg id)))
    (println (str "endpoint:       " (:endpoint id)))
    (println (str "key-id (b64u):  " (:key-id-b64u id)))
    (println (str "pubkey (b64u):  " (:pubkey-b64u id)))
    (println (str "host-user-id:   " (pr-str (:host-user-id id))))
    (println (str "created:        " (:created id)))
    (println (str "key file:       " (key-path)))
    0))

(defn- cmd-sign
  "Emit a signed wire envelope (JSON) to stdout for (METHOD URL [BODY])."
  [_opts args]
  (let [[method url body-str] args
        _ (when (or (nil? method) (nil? url))
            (binding [*out* *err*]
              (println "usage: continuity auth sign METHOD URL [BODY]"))
            (throw (ex-info "bad-args" {})))
        body-bytes (when body-str (.getBytes ^String body-str "UTF-8"))
        path       (.getRawPath (URI. url))
        env-pkg    (build-envelope
                    {:method     (str/upper-case method)
                     :path       path
                     :body-bytes body-bytes
                     :identity   (require-identity!)})]
    (println (json/->json (:wire env-pkg)))
    0))

(defn- attach-envelope-header
  "Construct the X-Continuity-Envelope header value for the given (method,
  url, body). Returns a string."
  [method url body-bytes]
  (let [path    (.getRawPath (URI. url))
        env-pkg (build-envelope
                 {:method     (str/upper-case method)
                  :path       path
                  :body-bytes body-bytes
                  :identity   (require-identity!)})]
    (json/->json (:wire env-pkg))))

(defn- cmd-curl
  "Wrap curl. Convention: the URL is the LAST positional argument; the
  method defaults to GET unless -X / --request is set. Body bytes are
  taken from the -d / --data flag if present.

  We attach the envelope via `X-Continuity-Envelope: <wire-json>` so the
  host backend can route it to /v1/verify without rewriting the request
  body."
  [_opts args]
  (when (empty? args)
    (binding [*out* *err*]
      (println "usage: continuity auth curl [CURL-ARGS] URL"))
    (throw (ex-info "no-args" {})))
  (let [method (loop [xs args]
                 (cond
                   (empty? xs) "GET"
                   (or (= "-X" (first xs)) (= "--request" (first xs)))
                   (str/upper-case (or (second xs) "GET"))
                   :else (recur (rest xs))))
        body   (loop [xs args]
                 (cond
                   (empty? xs) nil
                   (or (= "-d" (first xs)) (= "--data" (first xs)))
                   (.getBytes ^String (or (second xs) "") "UTF-8")
                   :else (recur (rest xs))))
        url    (last args)
        header (attach-envelope-header method url body)
        argv   (concat ["curl" "-H" (str "X-Continuity-Envelope: " header)]
                       args)
        r      (shell-exec (vec argv))]
    (print (:out r))
    (binding [*out* *err*] (print (:err r)))
    (flush)
    (:exit r)))

(defn- cmd-wget [_opts args]
  (when (empty? args)
    (binding [*out* *err*]
      (println "usage: continuity auth wget [WGET-ARGS] URL"))
    (throw (ex-info "no-args" {})))
  ;; wget doesn't peek the body by default; we conservatively sign as
  ;; GET (no body). For methods other than GET, callers should use
  ;; `continuity auth curl` or pass an explicit body via `--post-data`.
  (let [method (loop [xs args]
                 (cond
                   (empty? xs) "GET"
                   (= "--method" (first xs)) (str/upper-case (or (second xs) "GET"))
                   (str/starts-with? (first xs) "--post-data") "POST"
                   :else (recur (rest xs))))
        body   (loop [xs args]
                 (cond
                   (empty? xs) nil
                   (str/starts-with? (first xs) "--post-data=")
                   (.getBytes ^String (subs (first xs) (count "--post-data=")) "UTF-8")
                   (= "--post-data" (first xs))
                   (.getBytes ^String (or (second xs) "") "UTF-8")
                   :else (recur (rest xs))))
        url    (last args)
        header (attach-envelope-header method url body)
        argv   (concat ["wget" "--header" (str "X-Continuity-Envelope: " header)]
                       args)
        r      (shell-exec (vec argv))]
    (print (:out r))
    (binding [*out* *err*] (print (:err r)))
    (flush)
    (:exit r)))

;; -- entry point ----------------------------------------------------------

(defn run-auth
  "Top-level entry for `continuity auth <subcommand> [args...]`. Returns
  an integer exit code. Print any user-visible output via println; errors
  go to *err*."
  [{:keys [subcommand args opts]}]
  (try
    (case subcommand
      :init  (cmd-init opts)
      :show  (cmd-show opts)
      :sign  (cmd-sign opts args)
      :curl  (cmd-curl opts args)
      :wget  (cmd-wget opts args)
      (do (binding [*out* *err*]
            (println (str "unknown auth subcommand: " (name (or subcommand :nil))))
            (println "subcommands: init, sign, curl, wget, show"))
          2))
    (catch Exception e
      (binding [*out* *err*]
        (when-let [m (.getMessage e)] (println m)))
      1)))
