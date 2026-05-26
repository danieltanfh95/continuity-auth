(ns continuity-auth.server.system-test
  "Boot the integrant system from resources/config.edn and exercise one
  bootstrap+verify against it.

  This is the regression substrate for the `:size` → `:window` config
  rename: until this test existed, the integration suite constructed
  `:windows` directly with `:window` keys, bypassing the config.edn
  wire path. A real deployment with `:size` would have set every
  per-tier limit lookup to nil → 0 → throttle every request."
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.config :as config]
   [continuity-auth.server.system :as system]
   [jsonista.core :as json])
  (:import
   (java.net URI)
   (java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
                  HttpResponse$BodyHandlers)
   (java.nio.file Files)
   (java.nio.file.attribute FileAttribute)
   (java.security MessageDigest SecureRandom)
   (java.util Date)
   (org.bouncycastle.crypto.generators Ed25519KeyPairGenerator)
   (org.bouncycastle.crypto.params Ed25519KeyGenerationParameters
                                   Ed25519PrivateKeyParameters
                                   Ed25519PublicKeyParameters)
   (org.bouncycastle.crypto.signers Ed25519Signer)))

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "cauth-sys-" (into-array FileAttribute [])))

(defn- delete-recursively [^java.nio.file.Path p]
  (let [f (.toFile p)]
    (when (.isDirectory f)
      (doseq [c (.listFiles f)]
        (delete-recursively (.toPath c))))
    (.delete f)))

(defn- gen-ed25519 []
  (let [g  (Ed25519KeyPairGenerator.)
        _  (.init g (Ed25519KeyGenerationParameters. (SecureRandom.)))
        kp (.generateKeyPair g)
        ^Ed25519PrivateKeyParameters sk (.getPrivate kp)
        ^Ed25519PublicKeyParameters  pk (.getPublic  kp)]
    {:sk sk :pk-bytes (.getEncoded pk)}))

(defn- ed25519-sign ^bytes [sk msg]
  (let [s (Ed25519Signer.)]
    (.init s true sk)
    (.update s msg 0 (alength ^bytes msg))
    (.generateSignature s)))

(defn- sha256 ^bytes [^bytes bs]
  (.digest (MessageDigest/getInstance "SHA-256") bs))

(defn- iso8601-now []
  (let [fmt (java.text.SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        _   (.setTimeZone fmt (java.util.TimeZone/getTimeZone "UTC"))]
    (.format fmt (Date.))))

(defn- http-post [port path body-map]
  (let [c (HttpClient/newHttpClient)
        b (json/write-value-as-string body-map)
        r (.. (HttpRequest/newBuilder)
              (uri (URI. (str "http://127.0.0.1:" port path)))
              (header "Content-Type" "application/json")
              (POST (HttpRequest$BodyPublishers/ofString b))
              build)
        resp (.send c r (HttpResponse$BodyHandlers/ofString))]
    {:status (.statusCode resp)
     :body   (try (json/read-value (.body resp)
                                    (json/object-mapper {:decode-key-fn keyword}))
                  (catch Exception _ (.body resp)))}))

(defn- http-get [port path]
  (let [c (HttpClient/newHttpClient)
        r (.. (HttpRequest/newBuilder)
              (uri (URI. (str "http://127.0.0.1:" port path)))
              build)
        resp (.send c r (HttpResponse$BodyHandlers/ofString))]
    {:status (.statusCode resp)
     :body   (try (json/read-value (.body resp)
                                    (json/object-mapper {:decode-key-fn keyword}))
                  (catch Exception _ (.body resp)))}))

(defn- override-config
  "Replace storage URI with a temp dir and server port with 0 so the
  system can run in a test sandbox. `keyfile-path` is a sibling of
  `dir` (NOT inside it — Datalevin refuses to open a directory that
  contains foreign files)."
  [config dir keyfile-path]
  (-> config
      (assoc-in [:datalevin :uri] (.toString dir))
      (assoc-in [:server :port] 0)
      (assoc-in [:server :join?] false)
      (assoc-in [:ip-hmac :key-path] (.toString keyfile-path))
      ;; Don't actually bind a real metrics bearer — the test exercises
      ;; the verify path, not /metrics.
      (assoc-in [:observability :metrics-enabled?] false)))

(defn- server-port [system]
  (-> (get system :cauth/http-server)
      (.getConnectors)
      first
      (.getLocalPort)))

(deftest system-starts-and-bootstrap-verify-flow
  (testing "Boot from resources/config.edn at :dev profile, exercise
            bootstrap → verify; the per-tier limits must allow at least
            one verify (codex C6 regression)."
    (let [dir         (temp-dir)
          keyfile     (java.nio.file.Files/createTempFile
                       "cauth-sys-ip-hmac-" ".key"
                       (into-array FileAttribute []))
          _           (.delete (.toFile keyfile)) ; auto-generate on first use
          cfg         (-> (config/load-config :dev)
                          (override-config dir keyfile))
          system      (system/start cfg)]
      (try
        (let [port (server-port system)]
          ;; /healthz live
          (let [h (http-get port "/healthz")]
            (is (= 200 (:status h))))
          ;; bootstrap
          (let [kp (gen-ed25519)
                fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
                ts (iso8601-now)
                nonce (let [b (byte-array 16)] (.nextBytes (SecureRandom.) b) b)
                env {:method "POST"
                     :path   "/v1/bootstrap"
                     :body-sha256 (sha256 (.getBytes "" "UTF-8"))
                     :ts ts
                     :nonce nonce
                     :fp-digest fp
                     :host-user-id ""
                     :key-id (sha256 (:pk-bytes kp))}
                bs (envelope/canonical-bytes env)
                sig (ed25519-sign (:sk kp) bs)
                wire (-> (envelope/envelope->wire env)
                         (assoc :sig (envelope/b64url-encode sig)
                                :alg "ed25519"))
                bres (http-post port "/v1/bootstrap"
                                {:envelope wire
                                 :pubkey (envelope/b64url-encode (:pk-bytes kp))
                                 :alg "ed25519"})]
            (is (= 201 (:status bres)) (str "bootstrap body: " (:body bres)))
            ;; verify (the regression target — config.edn `:size` would
            ;; have made every limit lookup return 0)
            (let [ts2 (iso8601-now)
                  nonce2 (let [b (byte-array 16)] (.nextBytes (SecureRandom.) b) b)
                  env2 {:method "POST"
                        :path   "/v1/verify"
                        :body-sha256 (sha256 (.getBytes "" "UTF-8"))
                        :ts ts2
                        :nonce nonce2
                        :fp-digest fp
                        :host-user-id ""
                        :key-id (sha256 (:pk-bytes kp))}
                  bs2 (envelope/canonical-bytes env2)
                  sig2 (ed25519-sign (:sk kp) bs2)
                  wire2 (-> (envelope/envelope->wire env2)
                            (assoc :sig (envelope/b64url-encode sig2)
                                   :alg "ed25519"))
                  vres (http-post port "/v1/verify" {:envelope wire2})]
              (is (= 200 (:status vres))
                  (str "verify must allow under default config; got " (:body vres))))))
        (finally
          (system/stop system)
          (delete-recursively dir)
          (.delete (.toFile keyfile)))))))
