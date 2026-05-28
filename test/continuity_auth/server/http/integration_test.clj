(ns continuity-auth.server.http.integration-test
  "End-to-end integration tests for the HTTP layer.

  Spins a real Jetty on a random port and a real (file-backed) Datalevin
  per test. Exercises the full flow: bootstrap → verify (with a known
  Ed25519 keypair from RFC 8032)."
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.admin.hmac :as admin-hmac]
   [continuity-auth.server.http.router :as router]
   [continuity-auth.server.observability.metrics :as metrics]
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
  (Files/createTempDirectory "cauth-int-" (into-array FileAttribute [])))

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

(defn- iso8601 [^Date d]
  (let [fmt (java.text.SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        _   (.setTimeZone fmt (java.util.TimeZone/getTimeZone "UTC"))]
    (.format fmt d)))

(defn- iso8601-now [] (iso8601 (Date.)))

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
  "Builds a wire envelope signed by `sk` and bound to `(method, path)`.

  `:body-sha256` is the intent-binding hash. For /v1/verify and /v1/revoke-key
  it is sha256(\"\") (the default). For /v1/rotate-key the caller must pass
  the rotate-key intent-sha — sha256(b64url(new-pubkey) + \":\" + name(new-alg))
  — which the handler enforces via `enforce-route-binding!`."
  [{:keys [sk pk-bytes ts host-user-id fp-digest method path body-sha256]}]
  (let [nonce-bytes (let [b (byte-array 16)] (.nextBytes (SecureRandom.) b) b)
        body-sha    (or body-sha256 (sha256 (.getBytes "" "UTF-8")))
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

(def ^:private default-tier-limits
  {:anonymous {:1m 5  :5m 50  :1d 1000}
   :tracked   {:1m 30 :5m 120 :1d 5000}
   :penalized {:1m 0  :5m 1   :1d 20}
   :banned    {:1m 0  :5m 0   :1d 1}})

(defn- with-running-system
  ([f] (with-running-system {} f))
  ([{:keys [clock grace-seconds keystore config registry bearer
            tier-limits global-limits priority-weights]
     :or {clock         (fn [] (Date.))
          grace-seconds 86400
          keystore      nil
          config        {}
          tier-limits   default-tier-limits}}
    f]
   (let [dir   (temp-dir)
         store (dtlv/open (.toString dir))
         handler (router/make-handler
                  {:store              store
                   :clock              clock
                   :tolerance-seconds  60
                   :nonce-ttl-seconds  120
                   :grace-seconds      grace-seconds
                   :keystore           keystore
                   :config             config
                   :registry           registry
                   :bearer             bearer
                   :windows            [{:window :1m :seconds 60}
                                         {:window :5m :seconds 300}
                                         {:window :1d :seconds 86400}]
                   :tier-limits        tier-limits
                   :global-limits      global-limits
                   :priority-weights   priority-weights}
                  {:trusted-cidrs []
                   :ip-header     "x-forwarded-for"
                   ;; Fixed test key so the ingress hashing is deterministic
                   ;; but never written to disk. Production loads from
                   ;; the IP-HMAC keystore component.
                   :ip-hmac-key   (byte-array 32 (byte 0x42))
                   ;; Integration tests fire many bootstraps back-to-back from
                   ;; one localhost IP. Disable per-IP exp-backoff (floor=0,
                   ;; cap=0 ⇒ penalty=0) so the middleware is a no-op here;
                   ;; the staircase is unit-tested in middleware_test.clj.
                   :bootstrap-rl  {:floor-ms 0 :cap-ms 0
                                   :doubling-factor 1 :reset-threshold-ms 0}})
         server (jetty/run-jetty handler {:port 0 :join? false})]
     (try
       (f {:store store
           :port  (-> server (.getConnectors) first (.getLocalPort))})
       (finally
         (.stop server)
         (storage/close store)
         (delete-recursively dir))))))

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
        (is (-> r :body :identity_ref))
        (is (number? (-> r :body :priority_weight))
            "verify allow response must include :priority_weight (numeric)")
        ;; The priority_weight must match the default mapping for whatever
        ;; tier the response reports. Under the spaced-continuity model a
        ;; fresh key + one verify lands at the score floor (:anonymous);
        ;; the assertion is tier-driven so it survives score tuning.
        (let [tier-kw (keyword (-> r :body :tier))
              expected (get {:anonymous 1.0 :tracked 30.0
                             :penalized 0.0 :banned 0.0}
                            tier-kw)]
          (is (= expected (-> r :body :priority_weight))
              (str "priority_weight should match default weight for tier "
                   (-> r :body :tier))))))))

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

;; -- v0.3.0: configurable priority weight + class-level back-pressure -----

(defn- boot-and-verify!
  "Bootstrap a fresh keypair and issue one /verify. Returns the verify
  response. Each call is a distinct identity (fresh key + fp)."
  [port]
  (let [kp (gen-ed25519)
        fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
        {:keys [wire pubkey-b64]} (build-bootstrap-envelope
                                   {:sk (:sk kp) :pk-bytes (:pk-bytes kp)
                                    :ts (iso8601-now) :host-user-id "" :fp-digest fp})
        _ (http-post port "/v1/bootstrap"
                     {:envelope wire :pubkey pubkey-b64 :alg "ed25519"})
        v (build-verify-envelope
           {:sk (:sk kp) :pk-bytes (:pk-bytes kp) :ts (iso8601-now)
            :host-user-id "" :fp-digest fp :method "POST" :path "/v1/verify"})]
    (http-post port "/v1/verify" {:envelope v})))

(deftest verify-priority-weight-reflects-config
  (testing "priority_weight in the verify response is sourced from
            :priority-weights config, not the hardcoded defaults"
    (let [weights {:anonymous 2.5 :tracked 7.0 :penalized 0.0 :banned 0.0}]
      (with-running-system
        {:priority-weights weights}
        (fn [{:keys [port]}]
          (let [r        (boot-and-verify! port)
                tier-kw  (keyword (-> r :body :tier))]
            (is (= 200 (:status r)) (str "body: " (:body r)))
            (is (= (get weights tier-kw) (-> r :body :priority_weight))
                (str "priority_weight must match configured weight for tier "
                     (-> r :body :tier)))))))))

(deftest verify-class-cap-throttles-across-identities
  (testing "A class cap denies a second identity's verify once the shared
            tier bucket is drained — each caller is within its own budget,
            but the tier as a whole is capped — with :scope \"class\""
    (with-running-system
      ;; cap 1 req/min on :1m for every tier, so whatever tier the verifies
      ;; land in, the second distinct caller hits the shared class bucket.
      {:global-limits {:anonymous {:1m 1} :tracked {:1m 1}
                       :penalized {:1m 1} :banned {:1m 1}}}
      (fn [{:keys [port]}]
        (let [r1 (boot-and-verify! port)
              r2 (boot-and-verify! port)]
          (is (= 200 (:status r1)) (str "first caller allowed: " (:body r1)))
          (is (= 429 (:status r2)) (str "second caller class-throttled: " (:body r2)))
          (is (= "E_RATE" (-> r2 :body :code)))
          (is (= "class"  (-> r2 :body :scope))
              "a class-cap denial must be tagged scope=class")
          (is (number? (-> r2 :body :priority_weight))))))))

(deftest verify-no-class-cap-by-default
  (testing "With no :global-limits, distinct identities are not throttled
            against each other — the class path stays inert (v0.2 behavior)"
    (with-running-system
      (fn [{:keys [port]}]
        (let [r1 (boot-and-verify! port)
              r2 (boot-and-verify! port)]
          (is (= 200 (:status r1)))
          (is (= 200 (:status r2))
              "no class cap configured ⇒ second caller is not class-throttled"))))))

(deftest verification-flow-bootstrap-verify-rotate-revoke
  ;; Plan §Verification line: "full bootstrap + verify + rotate + revoke
  ;; flow via integration script works end-to-end".
  ;;
  ;; Drives the flow with an injected clock so we can advance past the
  ;; rotation grace window and assert the old key gets rejected.
  (let [now-ms (atom (System/currentTimeMillis))
        clock  (fn [] (Date. @now-ms))
        grace  120  ; short grace so we can step past it in one nudge
        advance! (fn [secs] (swap! now-ms + (* 1000 secs)))]
    (with-running-system
      {:clock clock :grace-seconds grace}
      (fn [{:keys [port]}]
        (let [ts  (fn [] (iso8601 (clock)))   ; envelope timestamps follow the injected clock
              kp1 (gen-ed25519)
              fp  (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
              ;; 1) bootstrap
              {b-wire :wire b-pub :pubkey-b64}
              (build-bootstrap-envelope
               {:sk (:sk kp1) :pk-bytes (:pk-bytes kp1)
                :ts (ts) :host-user-id "" :fp-digest fp})
              boot (http-post port "/v1/bootstrap"
                              {:envelope b-wire :pubkey b-pub :alg "ed25519"})
              _ (is (= 201 (:status boot)) (str "bootstrap: " (:body boot)))

              ;; 2) verify with the original key
              v1 (build-verify-envelope
                  {:sk (:sk kp1) :pk-bytes (:pk-bytes kp1)
                   :ts (ts) :host-user-id ""
                   :fp-digest fp :method "POST" :path "/v1/verify"})
              r1 (http-post port "/v1/verify" {:envelope v1})
              _ (is (= 200 (:status r1)) (str "verify-old: " (:body r1)))

              ;; 3) rotate: sign with old key, deliver new key
              kp2 (gen-ed25519)
              new-pub-b64 (envelope/b64url-encode (:pk-bytes kp2))
              rot-env (build-verify-envelope
                       {:sk (:sk kp1) :pk-bytes (:pk-bytes kp1)
                        :ts (ts) :host-user-id ""
                        :fp-digest fp :method "POST" :path "/v1/rotate-key"
                        :body-sha256 (sha256
                                       (envelope/rotate-key-intent-utf8
                                         (:pk-bytes kp2) :ed25519))})
              rot (http-post port "/v1/rotate-key"
                             {:envelope   rot-env
                              :new-pubkey new-pub-b64
                              :new-alg    "ed25519"})
              _ (is (= 200 (:status rot)) (str "rotate: " (:body rot)))
              _ (is (true? (-> rot :body :ok)))
              _ (is (string? (-> rot :body :new_key_id)))

              ;; 4) within grace: BOTH keys verify
              v-old-in-grace (build-verify-envelope
                              {:sk (:sk kp1) :pk-bytes (:pk-bytes kp1)
                               :ts (ts) :host-user-id ""
                               :fp-digest fp :method "POST" :path "/v1/verify"})
              r-old-grace (http-post port "/v1/verify" {:envelope v-old-in-grace})
              _ (is (= 200 (:status r-old-grace))
                    (str "old key in-grace must still verify: " (:body r-old-grace)))

              v-new (build-verify-envelope
                     {:sk (:sk kp2) :pk-bytes (:pk-bytes kp2)
                      :ts (ts) :host-user-id ""
                      :fp-digest fp :method "POST" :path "/v1/verify"})
              r-new (http-post port "/v1/verify" {:envelope v-new})
              _ (is (= 200 (:status r-new))
                    (str "new key must verify: " (:body r-new)))

              ;; 5) advance past grace; old key now rejected (E_FORBIDDEN)
              _ (advance! (inc grace))
              v-old-post (build-verify-envelope
                          {:sk (:sk kp1) :pk-bytes (:pk-bytes kp1)
                           :ts (ts) :host-user-id ""
                           :fp-digest fp :method "POST" :path "/v1/verify"})
              r-old-post (http-post port "/v1/verify" {:envelope v-old-post})
              _ (is (= 403 (:status r-old-post))
                    (str "old key post-grace must be rejected: " (:body r-old-post)))
              _ (is (= "E_FORBIDDEN" (-> r-old-post :body :code)))

              ;; 6) new key still works after grace
              v-new2 (build-verify-envelope
                      {:sk (:sk kp2) :pk-bytes (:pk-bytes kp2)
                       :ts (ts) :host-user-id ""
                       :fp-digest fp :method "POST" :path "/v1/verify"})
              r-new2 (http-post port "/v1/verify" {:envelope v-new2})
              _ (is (= 200 (:status r-new2))
                    (str "new key post-grace must verify: " (:body r-new2)))

              ;; 7) revoke the new key explicitly
              rev-env (build-verify-envelope
                       {:sk (:sk kp2) :pk-bytes (:pk-bytes kp2)
                        :ts (ts) :host-user-id ""
                        :fp-digest fp :method "POST" :path "/v1/revoke-key"})
              rev (http-post port "/v1/revoke-key" {:envelope rev-env})
              _ (is (= 200 (:status rev)) (str "revoke: " (:body rev)))
              _ (is (true? (-> rev :body :ok)))
              _ (is (string? (-> rev :body :revoked_at)))

              ;; 8) subsequent verify with the revoked key is rejected
              ;; (advance 1s so /verify sees the revoke as in-the-past,
              ;; not exactly-now — the comparison is `now >= revoked-at`)
              _ (advance! 1)
              v-after (build-verify-envelope
                       {:sk (:sk kp2) :pk-bytes (:pk-bytes kp2)
                        :ts (ts) :host-user-id ""
                        :fp-digest fp :method "POST" :path "/v1/verify"})
              r-after (http-post port "/v1/verify" {:envelope v-after})]
          (is (= 403 (:status r-after))
              (str "revoked key must be rejected: " (:body r-after)))
          (is (= "E_FORBIDDEN" (-> r-after :body :code))))))))

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
                  :ip-hmac-key    (byte-array 32 (byte 0x42))
                  :max-body-bytes 128
                  :bootstrap-rl   {:floor-ms 0 :cap-ms 0
                                   :doubling-factor 1 :reset-threshold-ms 0}})
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

;; -- admin endpoints --------------------------------------------------------

(defn- admin-sign-headers
  "Build the X-Admin-* headers for an outgoing admin request (test
  mirror of `continuity-auth.admin.cli/sign-request`)."
  [{:keys [method path body key-id secret]}]
  (let [ts       (iso8601-now)
        nonce    (let [b (byte-array 16)] (.nextBytes (SecureRandom.) b) b)
        body-sha (.digest (java.security.MessageDigest/getInstance "SHA-256")
                          (or body (byte-array 0)))
        input    (admin-hmac/signing-input
                  {:method method :path path :body-sha256 body-sha
                   :ts ts :nonce nonce})
        sig      (admin-hmac/hmac-sha256 secret input)]
    {"X-Admin-Key-Id" key-id
     "X-Admin-Ts"     ts
     "X-Admin-Nonce"  (envelope/b64url-encode nonce)
     "X-Admin-Sig"    (envelope/b64url-encode sig)}))

(defn- admin-http
  "POST or GET an admin endpoint with the right HMAC headers."
  [port method path body-map opts]
  (let [client (HttpClient/newHttpClient)
        body   (when body-map (.getBytes ^String (json/write-value-as-string body-map) "UTF-8"))
        hdrs   (admin-sign-headers (merge opts {:method method :path path :body body}))
        builder (.. (HttpRequest/newBuilder)
                    (uri (URI. (str "http://127.0.0.1:" port path))))
        _ (doseq [[k v] hdrs] (.header builder k v))
        _ (case method
            "POST" (do (.header builder "Content-Type" "application/json")
                       (.POST builder
                              (HttpRequest$BodyPublishers/ofByteArray
                               (or body (byte-array 0)))))
            "GET"  (.GET builder))
        req  (.build builder)
        resp (.send client req (HttpResponse$BodyHandlers/ofString))]
    {:status (.statusCode resp)
     :body   (try (json/read-value (.body resp)
                                    (json/object-mapper {:decode-key-fn keyword}))
                  (catch Exception _ (.body resp)))}))

(deftest admin-revoke-key-via-hmac
  ;; Bootstrap a key as a regular user, then admin-revoke it, then assert
  ;; that subsequent verify with that key is rejected with E_FORBIDDEN.
  (let [secret (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
        ks     {"ops-test" secret}]
    (with-running-system
      {:keystore ks}
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
              key-id-b64 (envelope/b64url-encode
                          (.digest (java.security.MessageDigest/getInstance "SHA-256")
                                   (:pk-bytes kp)))
              rev (admin-http port "POST" "/v1/admin/revoke-key"
                              {:key_id key-id-b64}
                              {:key-id "ops-test" :secret secret})]
          (is (= 200 (:status rev)) (str "admin-revoke: " (:body rev)))
          (is (true? (-> rev :body :ok)))
          (let [v (build-verify-envelope
                   {:sk (:sk kp) :pk-bytes (:pk-bytes kp)
                    :ts (iso8601-now) :host-user-id ""
                    :fp-digest fp :method "POST" :path "/v1/verify"})
                r (http-post port "/v1/verify" {:envelope v})]
            (is (= 403 (:status r)))
            (is (= "E_FORBIDDEN" (-> r :body :code)))))))))

(deftest admin-rejects-unsigned-call
  (let [secret (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
        ks     {"ops-test" secret}]
    (with-running-system
      {:keystore ks}
      (fn [{:keys [port]}]
        (let [r (http-post port "/v1/admin/revoke-key" {:key_id "deadbeef"})]
          (is (= 401 (:status r)))
          (is (= "E_UNAUTHORIZED" (-> r :body :code))))))))

(deftest admin-rejects-wrong-key
  (let [secret (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
        ks     {"ops-test" secret}
        wrong  (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)]
    (with-running-system
      {:keystore ks}
      (fn [{:keys [port]}]
        (let [r (admin-http port "POST" "/v1/admin/revoke-key"
                            {:key_id "deadbeef"}
                            {:key-id "ops-test" :secret wrong})]
          (is (= 401 (:status r)))
          (is (= "E_UNAUTHORIZED" (-> r :body :code))))))))

(deftest admin-disabled-without-keystore
  (with-running-system
    (fn [{:keys [port]}]
      (let [r (admin-http port "POST" "/v1/admin/revoke-key"
                          {:key_id "deadbeef"}
                          {:key-id "ops-test"
                           :secret (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)})]
        (is (= 403 (:status r)))
        (is (= "E_FORBIDDEN" (-> r :body :code)))))))

(deftest admin-config-dumps-effective-with-redaction
  (let [secret (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
        ks     {"ops-test" secret}
        cfg    {:server {:port 18080}
                :hmac   {:admin-keys-path "/etc/cauth/admin.edn"}
                :observability {:prometheus-bearer "topsecret"}}]
    (with-running-system
      {:keystore ks :config cfg}
      (fn [{:keys [port]}]
        (let [r (admin-http port "GET" "/v1/admin/config" nil
                            {:key-id "ops-test" :secret secret})]
          (is (= 200 (:status r)) (str "config: " (:body r)))
          (is (= 18080 (-> r :body :server :port)))
          (is (= "<redacted>" (-> r :body :hmac :admin-keys-path)))
          (is (= "<redacted>" (-> r :body :observability :prometheus-bearer))))))))

(deftest admin-config-strips-uri-userinfo
  ;; Codex M4: a Datalevin URI like `dtlv://user:pw@host/db` must NOT leak
  ;; the user:pw portion in the config dump. Both pathways:
  ;;   - the `:uri` key is in `sensitive-config-keys` → wholesale redacted
  ;;   - any string value matching `scheme://user:pw@host` gets its userinfo
  ;;     stripped via the postwalk in `redact`
  (let [secret (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
        ks     {"ops-test" secret}
        cfg    {:datalevin {:uri "dtlv://admin:hunter2@db.internal:8891/cauth"}
                ;; Stash the same string under an innocuous key — the
                ;; URI-userinfo postwalk must catch it too.
                :misc {:notes "see dtlv://ops:s3cret@db.internal/cauth for details"}}]
    (with-running-system
      {:keystore ks :config cfg}
      (fn [{:keys [port]}]
        (let [r (admin-http port "GET" "/v1/admin/config" nil
                            {:key-id "ops-test" :secret secret})
              body (:body r)]
          (is (= 200 (:status r)))
          ;; :datalevin/:uri is in sensitive-config-keys → fully redacted.
          (is (= "<redacted>" (-> body :datalevin :uri)))
          (let [notes (-> body :misc :notes)]
            (is (string? notes))
            (is (not (str/includes? notes "ops:s3cret"))
                (str "userinfo must be stripped, got: " notes))
            (is (str/includes? notes "<redacted>"))))))))

;; -- /metrics auth ---------------------------------------------------------

(deftest metrics-rejects-without-bearer
  ;; Codex M1: a non-blank bearer is required. With a registry but blank
  ;; bearer, every /metrics request returns 401.
  (with-running-system
    {:registry (metrics/make-registry)
     :bearer   ""}
    (fn [{:keys [port]}]
      (let [r (http-get port "/metrics")]
        (is (= 401 (:status r)))))))

(deftest metrics-allows-with-bearer
  (with-running-system
    {:registry (metrics/make-registry)
     :bearer   "scrape-token"}
    (fn [{:keys [port]}]
      (let [client (HttpClient/newHttpClient)
            r (.. (HttpRequest/newBuilder)
                  (uri (URI. (str "http://127.0.0.1:" port "/metrics")))
                  (header "Authorization" "Bearer scrape-token")
                  build)
            resp (.send client r (HttpResponse$BodyHandlers/ofString))]
        (is (= 200 (.statusCode resp)))))))

(deftest verify-records-into-metrics-registry
  ;; Regression for the wiring claim in the security review: running a
  ;; bootstrap+verify must produce a non-zero `cauth_verify_total`. Before
  ;; wiring this counter, /metrics shipped flat zeros and T14 ("ops would
  ;; catch via metrics") was aspirational.
  (let [registry (metrics/make-registry)]
    (with-running-system
      {:registry registry :bearer "tok"}
      (fn [{:keys [port]}]
        (let [kp (gen-ed25519)
              fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
              {:keys [wire pubkey-b64]} (build-bootstrap-envelope
                                          {:sk (:sk kp)
                                           :pk-bytes (:pk-bytes kp)
                                           :ts (iso8601-now)
                                           :host-user-id ""
                                           :fp-digest fp})
              _    (http-post port "/v1/bootstrap"
                              {:envelope wire :pubkey pubkey-b64 :alg "ed25519"})
              v    (build-verify-envelope
                    {:sk (:sk kp) :pk-bytes (:pk-bytes kp)
                     :ts (iso8601-now) :host-user-id ""
                     :fp-digest fp :method "POST" :path "/v1/verify"})
              vres (http-post port "/v1/verify" {:envelope v})
              _    (is (= 200 (:status vres)))
              ;; Scrape /metrics and look for cauth_verify_total > 0.
              client (HttpClient/newHttpClient)
              mr (.. (HttpRequest/newBuilder)
                     (uri (URI. (str "http://127.0.0.1:" port "/metrics")))
                     (header "Authorization" "Bearer tok")
                     build)
              mresp (.send client mr (HttpResponse$BodyHandlers/ofString))
              text  (.body mresp)]
          (is (= 200 (.statusCode mresp)))
          (is (str/includes? text "cauth_verify_total")
              "registry should expose cauth_verify_total")
          (is (re-find #"cauth_verify_total\{[^}]*outcome=\"ok\"[^}]*\}\s+1\.0" text)
              (str "expected cauth_verify_total{outcome=ok,...} = 1.0; got:\n" text)))))))

;; -- Adversarial: route-binding (codex C1/C2/C3) --------------------------

(deftest rotate-key-rejects-wrong-route-binding
  ;; A captured envelope intended for /v1/verify (or any other path)
  ;; must NOT be replayable as /v1/rotate-key. Likewise, an envelope with
  ;; a body-sha that doesn't match sha256(intent-string) must be rejected
  ;; even if the method/path are correct — preventing the "install a
  ;; different new pubkey than the user signed for" attack.
  (with-running-system
    (fn [{:keys [port]}]
      (let [kp1 (gen-ed25519)
            fp  (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
            {:keys [wire pubkey-b64]} (build-bootstrap-envelope
                                        {:sk (:sk kp1) :pk-bytes (:pk-bytes kp1)
                                         :ts (iso8601-now) :host-user-id ""
                                         :fp-digest fp})
            _ (http-post port "/v1/bootstrap"
                          {:envelope wire :pubkey pubkey-b64 :alg "ed25519"})
            kp2 (gen-ed25519)
            new-pub-b64 (envelope/b64url-encode (:pk-bytes kp2))]
        (testing "envelope signed for /v1/verify cannot rotate"
          (let [env (build-verify-envelope
                     {:sk (:sk kp1) :pk-bytes (:pk-bytes kp1)
                      :ts (iso8601-now) :host-user-id ""
                      :fp-digest fp :method "POST" :path "/v1/verify"})
                r (http-post port "/v1/rotate-key"
                              {:envelope env :new-pubkey new-pub-b64
                               :new-alg "ed25519"})]
            (is (= 401 (:status r))
                (str "rotate-key must reject /v1/verify-bound envelope: " (:body r)))
            (is (= "E_UNAUTHORIZED" (-> r :body :code)))))
        (testing "envelope signed for rotate-key but with wrong body-sha (mismatched intent) is rejected"
          (let [;; Wrong body-sha: sha256("") instead of sha256(intent)
                env (build-verify-envelope
                     {:sk (:sk kp1) :pk-bytes (:pk-bytes kp1)
                      :ts (iso8601-now) :host-user-id ""
                      :fp-digest fp :method "POST" :path "/v1/rotate-key"})
                r (http-post port "/v1/rotate-key"
                              {:envelope env :new-pubkey new-pub-b64
                               :new-alg "ed25519"})]
            (is (= 401 (:status r))
                (str "rotate-key must reject mismatched intent body-sha: " (:body r)))))
        (testing "envelope signed for rotate-key with body-sha = intent(OTHER pubkey) is rejected"
          ;; The attacker signed for intent(victim's chosen new key), but
          ;; tries to replay with `:new-pubkey` of a DIFFERENT key. The
          ;; server's intent body-sha is derived from the request body's
          ;; new-pubkey, so the captured envelope's body-sha won't match.
          (let [other (gen-ed25519)
                attacker-intent-sha
                (sha256 (envelope/rotate-key-intent-utf8
                          (:pk-bytes other) :ed25519))
                env (build-verify-envelope
                     {:sk (:sk kp1) :pk-bytes (:pk-bytes kp1)
                      :ts (iso8601-now) :host-user-id ""
                      :fp-digest fp :method "POST" :path "/v1/rotate-key"
                      :body-sha256 attacker-intent-sha})
                r (http-post port "/v1/rotate-key"
                              {:envelope env :new-pubkey new-pub-b64
                               :new-alg "ed25519"})]
            (is (= 401 (:status r))
                (str "rotate-key must reject intent-replay against different new pubkey: "
                     (:body r)))))))))

(deftest revoke-key-rejects-wrong-route-binding
  ;; A captured envelope intended for /v1/verify cannot be replayed
  ;; against /v1/revoke-key (codex C2 — DoS against any active user).
  (with-running-system
    (fn [{:keys [port]}]
      (let [kp (gen-ed25519)
            fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
            {:keys [wire pubkey-b64]} (build-bootstrap-envelope
                                        {:sk (:sk kp) :pk-bytes (:pk-bytes kp)
                                         :ts (iso8601-now) :host-user-id ""
                                         :fp-digest fp})
            _ (http-post port "/v1/bootstrap"
                          {:envelope wire :pubkey pubkey-b64 :alg "ed25519"})
            ;; Envelope signed for /v1/verify
            env (build-verify-envelope
                  {:sk (:sk kp) :pk-bytes (:pk-bytes kp)
                   :ts (iso8601-now) :host-user-id ""
                   :fp-digest fp :method "POST" :path "/v1/verify"})
            r (http-post port "/v1/revoke-key" {:envelope env})]
        (is (= 401 (:status r))
            (str "revoke-key must reject /v1/verify-bound envelope: " (:body r)))
        (is (= "E_UNAUTHORIZED" (-> r :body :code)))))))

(deftest bootstrap-rejects-wrong-route-binding
  ;; An envelope intended for /v1/verify cannot install a fresh identity
  ;; via /v1/bootstrap (codex C3 corollary).
  (with-running-system
    (fn [{:keys [port]}]
      (let [kp (gen-ed25519)
            fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
            nonce (let [b (byte-array 16)] (.nextBytes (SecureRandom.) b) b)
            env {:method "POST"
                 :path   "/v1/verify"           ; WRONG: not /v1/bootstrap
                 :body-sha256 (sha256 (.getBytes "" "UTF-8"))
                 :ts (iso8601-now)
                 :nonce nonce
                 :fp-digest fp
                 :host-user-id ""
                 :key-id (sha256 (:pk-bytes kp))}
            sig (ed25519-sign (:sk kp) (envelope/canonical-bytes env))
            wire (-> (envelope/envelope->wire env)
                     (assoc :sig (envelope/b64url-encode sig) :alg "ed25519"))
            r (http-post port "/v1/bootstrap"
                         {:envelope wire
                          :pubkey   (envelope/b64url-encode (:pk-bytes kp))
                          :alg      "ed25519"})]
        (is (= 401 (:status r)))
        (is (= "E_UNAUTHORIZED" (-> r :body :code)))))))

(deftest re-bootstrap-of-existing-pubkey-rejected
  ;; Codex C4: a second bootstrap with the same pubkey must NOT upsert
  ;; on :pubkey/id and rebind the existing pubkey to a fresh neutral
  ;; identity (which would reset score/tier/buckets). The handler now
  ;; explicitly rejects with E_CONFLICT before the unique-identity
  ;; transact runs.
  (with-running-system
    (fn [{:keys [port]}]
      (let [kp (gen-ed25519)
            fp (let [b (byte-array 32)] (.nextBytes (SecureRandom.) b) b)
            mk (fn []
                 (build-bootstrap-envelope
                   {:sk (:sk kp) :pk-bytes (:pk-bytes kp)
                    :ts (iso8601-now) :host-user-id ""
                    :fp-digest fp}))
            first  (http-post port "/v1/bootstrap"
                              (let [{:keys [wire pubkey-b64]} (mk)]
                                {:envelope wire :pubkey pubkey-b64 :alg "ed25519"}))
            _      (is (= 201 (:status first)))
            second (http-post port "/v1/bootstrap"
                              (let [{:keys [wire pubkey-b64]} (mk)]
                                {:envelope wire :pubkey pubkey-b64 :alg "ed25519"}))]
        (is (= 409 (:status second))
            (str "second bootstrap must be E_CONFLICT: " (:body second)))
        (is (= "E_CONFLICT" (-> second :body :code)))))))
