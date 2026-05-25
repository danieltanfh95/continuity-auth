(ns continuity-auth.server.http.integration-test
  "End-to-end integration tests for the HTTP layer.

  Spins a real Jetty on a random port and a real (file-backed) Datalevin
  per test. Exercises the full flow: bootstrap → verify (with a known
  Ed25519 keypair from RFC 8032)."
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.http.router :as router]
   [continuity-auth.server.storage.datalevin :as dtlv]
   [continuity-auth.server.storage.protocol :as storage]
   [jsonista.core :as json]
   [ring.adapter.jetty :as jetty])
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

;; -- helpers ---------------------------------------------------------------

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "fpl-int-" (into-array FileAttribute [])))

(defn- delete-recursively [^java.nio.file.Path p]
  (let [f (.toFile p)]
    (when (.isDirectory f)
      (doseq [c (.listFiles f)]
        (delete-recursively (.toPath c))))
    (.delete f)))

(defn- gen-ed25519 []
  (let [g (Ed25519KeyPairGenerator.)
        _ (.init g (Ed25519KeyGenerationParameters. (SecureRandom.)))
        kp (.generateKeyPair g)
        ^Ed25519PrivateKeyParameters sk (.getPrivate kp)
        ^Ed25519PublicKeyParameters  pk (.getPublic  kp)]
    {:sk sk :pk-bytes (.getEncoded pk)}))

(defn- ed25519-sign ^bytes [sk msg]
  (let [signer (Ed25519Signer.)]
    (.init signer true sk)
    (.update signer msg 0 (alength ^bytes msg))
    (.generateSignature signer)))

(defn- sha256 ^bytes [^bytes bs]
  (.digest (MessageDigest/getInstance "SHA-256") bs))

(defn- iso8601-now []
  (let [fmt (java.text.SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        _   (.setTimeZone fmt (java.util.TimeZone/getTimeZone "UTC"))]
    (.format fmt (Date.))))

(defn- build-bootstrap-envelope
  "Build a complete bootstrap envelope (with signature) for the given
  keypair, IP, and fingerprint digest."
  [{:keys [sk pk-bytes ts host-user-id fp-digest]}]
  (let [nonce-bytes (let [b (byte-array 16)]
                      (.nextBytes (SecureRandom.) b) b)
        body-sha    (sha256 (.getBytes "" "UTF-8"))
        key-id      (sha256 pk-bytes)
        env         {:method        "POST"
                     :path          "/v1/bootstrap"
                     :body-sha256   body-sha
                     :ts            ts
                     :nonce         nonce-bytes
                     :fp-digest     fp-digest
                     :host-user-id  host-user-id
                     :key-id        key-id}
        bytes-to-sign (envelope/canonical-bytes env)
        sig         (ed25519-sign sk bytes-to-sign)]
    {:wire (-> (envelope/envelope->wire env)
               (assoc :sig (envelope/b64url-encode sig)
                      :alg "ed25519"))
     :env  (assoc env :signature sig :alg :ed25519)
     :pubkey-b64 (envelope/b64url-encode pk-bytes)}))

(defn- build-verify-envelope
  [{:keys [sk pk-bytes ts host-user-id fp-digest method path]}]
  (let [nonce-bytes (let [b (byte-array 16)] (.nextBytes (SecureRandom.) b) b)
        body-sha    (sha256 (.getBytes "" "UTF-8"))
        key-id      (sha256 pk-bytes)
        env         {:method        method
                     :path          path
                     :body-sha256   body-sha
                     :ts            ts
                     :nonce         nonce-bytes
                     :fp-digest     fp-digest
                     :host-user-id  host-user-id
                     :key-id        key-id}
        bytes-to-sign (envelope/canonical-bytes env)
        sig         (ed25519-sign sk bytes-to-sign)]
    (-> (envelope/envelope->wire env)
        (assoc :sig (envelope/b64url-encode sig)
               :alg "ed25519"))))

;; -- HTTP harness ----------------------------------------------------------

(defn- with-running-system [f]
  (let [dir   (temp-dir)
        store (dtlv/open (.toString dir))
        clock (fn [] (Date.))
        handler (router/make-handler
                 {:store              store
                  :clock              clock
                  :tolerance-seconds  60
                  :nonce-ttl-seconds  120
                  :windows            [{:window :1m :seconds 60}
                                        {:window :5m :seconds 300}
                                        {:window :1d :seconds 86400}]
                  :tier-limits        {:anonymous {:1m 5  :5m 50  :1d 1000}
                                        :tracked   {:1m 30 :5m 120 :1d 5000}
                                        :penalized {:1m 0  :5m 1   :1d 20}
                                        :banned    {:1m 0  :5m 0   :1d 1}}}
                 {:trusted-cidrs []
                  :ip-header     "x-forwarded-for"})
        server (jetty/run-jetty handler {:port 0 :join? false})]
    (try
      (f {:store store
          :port  (-> server (.getConnectors) first (.getLocalPort))})
      (finally
        (.stop server)
        (storage/close store)
        (delete-recursively dir)))))

(defn- http-post [port path body-map]
  (let [client (HttpClient/newHttpClient)
        body   (json/write-value-as-string body-map)
        req    (.. (HttpRequest/newBuilder)
                   (uri (URI. (str "http://127.0.0.1:" port path)))
                   (header "Content-Type" "application/json")
                   (POST (HttpRequest$BodyPublishers/ofString body))
                   build)
        resp   (.send client req (HttpResponse$BodyHandlers/ofString))]
    {:status (.statusCode resp)
     :body   (try (json/read-value (.body resp)
                                    (json/object-mapper {:decode-key-fn keyword}))
                  (catch Exception _ (.body resp)))}))

(defn- http-get [port path]
  (let [client (HttpClient/newHttpClient)
        req    (.. (HttpRequest/newBuilder)
                   (uri (URI. (str "http://127.0.0.1:" port path)))
                   build)
        resp   (.send client req (HttpResponse$BodyHandlers/ofString))]
    {:status (.statusCode resp)
     :body   (try (json/read-value (.body resp)
                                    (json/object-mapper {:decode-key-fn keyword}))
                  (catch Exception _ (.body resp)))}))

;; -- tests ----------------------------------------------------------------

(deftest healthz-returns-ok
  (with-running-system
    (fn [{:keys [port]}]
      (let [r (http-get port "/healthz")]
        (is (= 200 (:status r)))
        (is (= true (-> r :body :ok)))))))

(deftest readyz-returns-ready
  (with-running-system
    (fn [{:keys [port]}]
      (let [r (http-get port "/readyz")]
        (is (= 200 (:status r)))
        (is (true? (-> r :body :ready)))))))

(deftest bootstrap-creates-identity
  (with-running-system
    (fn [{:keys [port]}]
      (let [kp (gen-ed25519)
            fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
            {:keys [wire pubkey-b64]} (build-bootstrap-envelope
                                       {:sk (:sk kp)
                                        :pk-bytes (:pk-bytes kp)
                                        :ts (iso8601-now)
                                        :host-user-id ""
                                        :fp-digest fp})
            r (http-post port "/v1/bootstrap"
                          {:envelope wire :pubkey pubkey-b64 :alg "ed25519"})]
        (is (= 201 (:status r)) (str "body: " (:body r)))
        (is (true?  (-> r :body :ok)))
        (is (string? (-> r :body :identity_ref)))
        (is (= "anonymous" (-> r :body :tier)))))))

(deftest bootstrap-then-verify
  (with-running-system
    (fn [{:keys [port]}]
      (let [kp (gen-ed25519)
            fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
            {:keys [wire pubkey-b64]} (build-bootstrap-envelope
                                       {:sk (:sk kp)
                                        :pk-bytes (:pk-bytes kp)
                                        :ts (iso8601-now)
                                        :host-user-id ""
                                        :fp-digest fp})
            boot (http-post port "/v1/bootstrap"
                             {:envelope wire :pubkey pubkey-b64 :alg "ed25519"})
            _    (is (= 201 (:status boot)) (str "body: " (:body boot)))

            ;; Now /verify with same key, same fp, same IP — exact observation.
            v-env (build-verify-envelope
                    {:sk (:sk kp)
                     :pk-bytes (:pk-bytes kp)
                     :ts (iso8601-now)
                     :host-user-id ""
                     :fp-digest fp
                     :method "POST"
                     :path "/v1/verify"})
            r (http-post port "/v1/verify" {:envelope v-env})]
        (is (= 200 (:status r)) (str "body: " (:body r)))
        (is (true? (-> r :body :ok)))
        (is (-> r :body :identity_ref))))))

(deftest verify-replay-rejected
  (with-running-system
    (fn [{:keys [port]}]
      (let [kp (gen-ed25519)
            fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
            {:keys [wire pubkey-b64]} (build-bootstrap-envelope
                                       {:sk (:sk kp)
                                        :pk-bytes (:pk-bytes kp)
                                        :ts (iso8601-now)
                                        :host-user-id ""
                                        :fp-digest fp})
            _ (http-post port "/v1/bootstrap"
                          {:envelope wire :pubkey pubkey-b64 :alg "ed25519"})
            v (build-verify-envelope
               {:sk (:sk kp) :pk-bytes (:pk-bytes kp) :ts (iso8601-now)
                :host-user-id "" :fp-digest fp
                :method "POST" :path "/v1/verify"})
            r1 (http-post port "/v1/verify" {:envelope v})
            r2 (http-post port "/v1/verify" {:envelope v})]
        (is (= 200 (:status r1)))
        (is (= 409 (:status r2)) "replay must be rejected with 409 E_REPLAY")
        (is (= "E_REPLAY" (-> r2 :body :code)))))))

(deftest verify-unknown-pubkey-rejected
  (with-running-system
    (fn [{:keys [port]}]
      (let [kp (gen-ed25519)
            fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
            v (build-verify-envelope
               {:sk (:sk kp) :pk-bytes (:pk-bytes kp) :ts (iso8601-now)
                :host-user-id "" :fp-digest fp
                :method "POST" :path "/v1/verify"})
            r (http-post port "/v1/verify" {:envelope v})]
        (is (= 401 (:status r)))
        (is (= "E_UNAUTHORIZED" (-> r :body :code)))))))

(deftest verify-malformed-envelope-rejected
  (with-running-system
    (fn [{:keys [port]}]
      (let [r (http-post port "/v1/verify" {:envelope {:bogus true}})]
        (is (= 400 (:status r)))
        (is (= "E_BAD_REQUEST" (-> r :body :code)))))))

(deftest oversize-body-rejected
  ;; Bring up a system with a tiny 128-byte body cap; POST a payload that
  ;; comfortably exceeds it. The middleware must short-circuit with a 413
  ;; E_PAYLOAD_TOO_LARGE before reaching JSON parsing or the handler.
  (let [dir   (temp-dir)
        store (dtlv/open (.toString dir))
        handler (router/make-handler
                 {:store              store
                  :clock              (fn [] (Date.))
                  :tolerance-seconds  60
                  :nonce-ttl-seconds  120
                  :windows            [{:window :1m :seconds 60}]
                  :tier-limits        {:anonymous {:1m 5}}}
                 {:trusted-cidrs  []
                  :ip-header      "x-forwarded-for"
                  :max-body-bytes 128})
        server (jetty/run-jetty handler {:port 0 :join? false})
        port   (-> server (.getConnectors) first (.getLocalPort))]
    (try
      (let [big (apply str (repeat 1024 "x"))
            r   (http-post port "/v1/bootstrap" {:fluff big})]
        (is (= 413 (:status r)) (str "body: " (:body r)))
        (is (= "E_PAYLOAD_TOO_LARGE" (-> r :body :code))))
      (finally
        (.stop server)
        (storage/close store)
        (delete-recursively dir)))))

(deftest bootstrap-tampered-signature-rejected
  (with-running-system
    (fn [{:keys [port]}]
      (let [kp (gen-ed25519)
            fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
            {:keys [wire pubkey-b64]} (build-bootstrap-envelope
                                       {:sk (:sk kp)
                                        :pk-bytes (:pk-bytes kp)
                                        :ts (iso8601-now)
                                        :host-user-id ""
                                        :fp-digest fp})
            tampered-sig "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            r (http-post port "/v1/bootstrap"
                          {:envelope (assoc wire :sig tampered-sig)
                           :pubkey pubkey-b64 :alg "ed25519"})]
        (is (= 401 (:status r)))
        (is (= "E_UNAUTHORIZED" (-> r :body :code)))))))
