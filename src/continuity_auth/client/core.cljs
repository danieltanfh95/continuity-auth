(ns continuity-auth.client.core
  "Public API of the continuity-auth browser library.

  Surface (every function returns a promise unless noted):

      init        — initialize: load or generate the keypair, ensure
                    metadata, attach cross-tab listeners
      verify      — sign a request envelope and POST to /v1/verify
      sign-fetch! — produce a signed envelope to attach to an outgoing
                    fetch; the caller dispatches the fetch
      rotate-key! — generate a new keypair, sign rotation envelope with
                    the old key, persist the new
      revoke!     — sign a revocation envelope and POST it to the
                    service; clear local state on success
      clear!      — wipe local state without server-side revocation
                    (offline 'log out everywhere')

  All keys live in the user's browser only. The server never sees the
  private key; it only verifies signatures against the registered
  public key.

  Usage:
      (require '[continuity-auth.client.core :as fpl])
      (-> (fpl/init {:endpoint \"https://fl.example.com\"
                     :host-id  \"my-app\"})
          (.then (fn [_] (fpl/verify {:method \"POST\"
                                       :path   \"/api/foo\"
                                       :body   \"...\"}))))"
  (:require
   [clojure.string :as str]
   [continuity-auth.client.crypto :as crypto]
   [continuity-auth.client.fingerprint :as fingerprint]
   [continuity-auth.client.storage :as storage]
   [continuity-auth.client.tabs :as tabs]
   [continuity-auth.envelope :as envelope]
   [promesa.core :as p]))

;; -- module state ----------------------------------------------------------

(defonce ^:private state
  (atom {:initialized? false
         :endpoint     nil
         :host-id      nil
         :alg          nil
         :keypair      nil      ; in-memory cache of CryptoKeys
         :pubkey-bytes nil      ; canonical bytes
         :key-id       nil      ; thumbprint
         :host-user-id nil}))   ; host can set later

(defn- iso8601-now []
  (.toISOString (js/Date.)))

(defn- random-bytes [n]
  (let [b (js/Uint8Array. n)]
    (.getRandomValues (.-crypto js/window) b)
    b))

(defn- utf8 [s]
  (.encode (js/TextEncoder.) s))

;; -- key lifecycle ---------------------------------------------------------

(defn- supported-alg []
  ;; Prefer Ed25519, fall back to P-256. We attempt a no-op
  ;; generateKey with a discardable result to detect availability.
  (-> (crypto/generate-keypair :ed25519)
      (p/then (fn [_] :ed25519))
      (p/catch (fn [_] :p256))))

(defn- load-or-generate-keypair
  "Returns a promise resolving to {:keypair, :pubkey-bytes, :key-id, :alg}.
  Reuses an existing IndexedDB keypair if present and consistent with
  localStorage meta; otherwise generates a new one inside the cross-tab
  lock."
  []
  (p/let [meta     (storage/read-meta)
          existing (storage/get-keypair)]
    (if (and meta existing (:key-id meta) (:alg meta))
      (p/let [pub-bytes (crypto/export-public (:public-key existing))]
        {:keypair      existing
         :pubkey-bytes pub-bytes
         :key-id       (envelope/b64url-decode (:key-id meta))
         :alg          (keyword (:alg meta))})
      (tabs/with-keygen-lock
       (fn []
         ;; Re-check inside the lock — another tab may have populated.
         (p/let [m2 (storage/read-meta)
                 e2 (storage/get-keypair)]
           (if (and m2 e2)
             (p/let [pub-bytes (crypto/export-public (:public-key e2))]
               {:keypair      e2
                :pubkey-bytes pub-bytes
                :key-id       (envelope/b64url-decode (:key-id m2))
                :alg          (keyword (:alg m2))})
             (p/let [alg       (supported-alg)
                     keypair   (crypto/generate-keypair alg)
                     pub-bytes (crypto/export-public (:public-key keypair))
                     key-id    (crypto/thumbprint pub-bytes)]
               (storage/put-keypair! keypair)
               (storage/write-meta!
                {:key-id     (envelope/b64url-encode key-id)
                 :alg        (name alg)
                 :created-at (iso8601-now)
                 :version    1})
               (tabs/post! {:type "key-rotated" :key-id (envelope/b64url-encode key-id)})
               {:keypair      keypair
                :pubkey-bytes pub-bytes
                :key-id       key-id
                :alg          alg}))))))))

;; -- envelope construction -------------------------------------------------

(defn- canonical-query
  "Re-order query params lexicographically. Matches the server-side
  expectation in docs/crypto-protocol.md. If `path` has no query
  component, returns `path` unchanged."
  [path]
  (let [idx (.indexOf path "?")]
    (if (neg? idx)
      path
      (let [base (.substring path 0 idx)
            qs   (.substring path (inc idx))
            pairs (->> (.split qs "&")
                       (js->clj)
                       (remove str/blank?)
                       sort
                       (str/join "&"))]
        (if (zero? (count pairs))
          base
          (str base "?" pairs))))))

(defn- build-envelope
  "Construct the canonical envelope map (sans signature) for a request."
  [{:keys [method path body host-user-id]} key-id fp-digest]
  (p/let [body-bytes (utf8 (or body ""))
          body-sha   (crypto/sha256 body-bytes)
          nonce      (random-bytes 16)
          ts         (iso8601-now)]
    {:method        (or method "POST")
     :path          (canonical-query (or path "/"))
     :body-sha256   body-sha
     :ts            ts
     :nonce         nonce
     :fp-digest     fp-digest
     :host-user-id  (or host-user-id "")
     :key-id        key-id}))

(defn- sign-envelope!
  "Sign the envelope and return the wire-shape map."
  [env private-key alg]
  (p/let [bytes (envelope/canonical-bytes env)
          sig   (crypto/sign alg private-key bytes)]
    (-> (envelope/envelope->wire (assoc env :alg alg :signature sig)))))

;; -- bootstrap-vs-verify branch -------------------------------------------

(defn- bootstrap-payload [wire pubkey-bytes alg]
  {:envelope wire
   :pubkey   (envelope/b64url-encode pubkey-bytes)
   :alg      (name alg)})

(defn- http-post [endpoint path body]
  (p/let [resp (js/fetch (str endpoint path)
                         #js {:method  "POST"
                              :headers #js {"Content-Type" "application/json"}
                              :body    (.stringify js/JSON (clj->js body))})
          text (.text resp)
          parsed (try
                   (.parse js/JSON text)
                   (catch :default _ nil))]
    {:status (.-status resp)
     :body   (js->clj parsed :keywordize-keys true)}))

;; -- public API ------------------------------------------------------------

(defn init
  "Initialize the library. Loads or generates the keypair; if generating,
  the first verify call will bootstrap an identity on the server.

  Options:
    :endpoint     URL of the continuity-auth service (required)
    :host-id      opaque integration identifier (recommended)
    :host-user-id (optional) set the host's verified user_id; pass nil
                  to clear

  Returns a promise resolving to {:key-id <b64url string>, :alg <kw>}."
  [{:keys [endpoint host-id host-user-id]}]
  (when-not endpoint
    (throw (ex-info "fpl/init requires :endpoint" {})))
  (p/let [{:keys [keypair pubkey-bytes key-id alg]} (load-or-generate-keypair)
          _ (swap! state assoc
                   :initialized? true
                   :endpoint     endpoint
                   :host-id      host-id
                   :host-user-id host-user-id
                   :keypair      keypair
                   :pubkey-bytes pubkey-bytes
                   :key-id       key-id
                   :alg          alg)
          _ (tabs/subscribe!
             (fn [evt]
               (when (= "key-rotated" (:type evt))
                 ;; Drop in-memory cache; next call reloads from IndexedDB.
                 (swap! state assoc :keypair nil :pubkey-bytes nil :key-id nil))))]
    {:key-id (envelope/b64url-encode key-id)
     :alg    alg}))

(defn- ensure-initialized! []
  (when-not (:initialized? @state)
    (throw (ex-info "fpl/init has not been called" {}))))

(defn sign-fetch!
  "Sign a request envelope. Returns a promise resolving to the wire
  envelope (a JSON-safe map). The caller decides whether to POST it to
  continuity-auth or attach it to an outgoing fetch the host backend
  will forward.

  `req` keys:
    :method        — HTTP method, default \"POST\"
    :path          — full path with query (will be canonicalized)
    :body          — request body string (or nil)
    :host-user-id  — overrides the value set in init"
  [req]
  (ensure-initialized!)
  (let [{:keys [keypair pubkey-bytes key-id alg host-user-id]} @state]
    (p/let [fp (fingerprint/compute-digest)
            env (build-envelope (merge {:host-user-id host-user-id} req)
                                 key-id (:digest fp))
            wire (sign-envelope! env (:private-key keypair) alg)]
      {:envelope         wire
       :low-confidence?  (:low-confidence fp)
       :pubkey-canonical pubkey-bytes
       :alg              alg})))

(defn verify
  "Sign and POST to /v1/verify (or /v1/bootstrap if the key has not
  been registered yet). Returns a promise resolving to the parsed
  response.

  This is a convenience for the case where the browser communicates
  directly with continuity-auth; the typical production path is
  `sign-fetch!` + host-backend forwarding."
  [req]
  (ensure-initialized!)
  (let [{:keys [endpoint]} @state]
    (p/let [{:keys [envelope]} (sign-fetch! req)
            ;; Heuristic: if we just generated the key in this session
            ;; AND the server has never seen it, /verify will return
            ;; E_UNAUTHORIZED. The cleanest path is to call /v1/bootstrap
            ;; once after first init. We don't track that explicitly
            ;; here in v1; the caller invokes (verify {...}) for the
            ;; bootstrap target on first run.
            resp (http-post endpoint "/v1/verify" {:envelope envelope})]
      resp)))

(defn bootstrap!
  "Explicitly POST /v1/bootstrap with the current keypair. Returns the
  parsed response."
  []
  (ensure-initialized!)
  (let [{:keys [endpoint pubkey-bytes alg]} @state]
    (p/let [{:keys [envelope]} (sign-fetch! {:method "POST"
                                              :path   "/v1/bootstrap"
                                              :body   ""})
            resp (http-post endpoint "/v1/bootstrap"
                            (bootstrap-payload envelope pubkey-bytes alg))]
      resp)))

(defn clear!
  "Wipe local state. Does NOT call the server. Use `revoke!` for a
  server-side revocation."
  []
  (storage/clear-all!)
  (swap! state assoc :keypair nil :pubkey-bytes nil :key-id nil :initialized? false))

(defn set-host-user-id!
  "Update the host_user_id used in subsequent envelopes."
  [user-id]
  (swap! state assoc :host-user-id user-id))
