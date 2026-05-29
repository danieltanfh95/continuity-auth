(ns continuity-auth.client.core
  "Public API of the continuity-auth browser library.

  Surface (every function returns a promise unless noted):

      init        — initialize: load or generate the keypair, ensure
                    metadata, attach cross-tab listeners
      verify      — sign a request envelope and POST to /v1/verify
      sign-fetch — produce a signed envelope to attach to an outgoing
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
      (require '[continuity-auth.client.core :as cauth])
      (-> (cauth/init {:endpoint \"https://fl.example.com\"
                     :host-id  \"my-app\"})
          (.then (fn [_] (cauth/verify {:method \"POST\"
                                       :path   \"/api/foo\"
                                       :body   \"...\"}))))"
  (:require
   [clojure.string :as str]
   [continuity-auth.client.crypto :as crypto]
   [continuity-auth.client.fingerprint :as fingerprint]
   [continuity-auth.client.kf :as kf]
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
         :identity-ref nil      ; server-assigned identity UUID (from verify/bootstrap)
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

(defn- capture-identity-ref!
  "Record the server-assigned identity_ref from a verify/bootstrap response
  so KF set-verifier can derive the recovery salt later. Returns `resp`."
  [resp]
  (when-let [ref (-> resp :body :identity_ref)]
    (swap! state assoc :identity-ref ref))
  resp)

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
    (throw (ex-info "cauth/init requires :endpoint" {})))
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
    (throw (ex-info "cauth/init has not been called" {}))))

(defn sign-fetch
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
  `sign-fetch` + host-backend forwarding."
  [req]
  (ensure-initialized!)
  (let [{:keys [endpoint]} @state]
    (p/let [{:keys [envelope]} (sign-fetch req)
            ;; Heuristic: if we just generated the key in this session
            ;; AND the server has never seen it, /verify will return
            ;; E_UNAUTHORIZED. The cleanest path is to call /v1/bootstrap
            ;; once after first init. We don't track that explicitly
            ;; here in v1; the caller invokes (verify {...}) for the
            ;; bootstrap target on first run.
            resp (http-post endpoint "/v1/verify" {:envelope envelope})]
      (capture-identity-ref! resp))))

(defn bootstrap!
  "Explicitly POST /v1/bootstrap with the current keypair. Returns the
  parsed response."
  []
  (ensure-initialized!)
  (let [{:keys [endpoint pubkey-bytes alg]} @state]
    (p/let [{:keys [envelope]} (sign-fetch {:method "POST"
                                              :path   "/v1/bootstrap"
                                              :body   ""})
            resp (http-post endpoint "/v1/bootstrap"
                            (bootstrap-payload envelope pubkey-bytes alg))]
      (capture-identity-ref! resp))))

;; -- rotate-key / revoke --------------------------------------------------
;;
;; Control endpoints share a structural contract with the server's
;; `enforce-route-binding!` check:
;;   - envelope.method = "POST"
;;   - envelope.path   = the endpoint's canonical route
;;   - envelope.body-sha256 = sha256(intent-bytes)
;;     * for /v1/revoke-key: intent-bytes = empty byte-array
;;     * for /v1/rotate-key: intent-bytes = utf8(b64url(new-pub) ":" name(new-alg))
;; The intent-bound body-sha prevents a captured envelope from being
;; replayed to install a DIFFERENT new pubkey (codex C1).

(defn- sign-control-envelope!
  "Build, sign, and return the wire envelope for a control endpoint.
  `intent-bytes` is the body the envelope's body-sha256 will bind to —
  empty for revoke, the rotate-key-intent UTF-8 for rotate."
  [{:keys [path]} intent-bytes]
  (ensure-initialized!)
  (let [{:keys [keypair pubkey-bytes key-id alg host-user-id]} @state]
    (p/let [fp (fingerprint/compute-digest)
            body-sha (crypto/sha256 intent-bytes)
            nonce    (random-bytes 16)
            ts       (iso8601-now)
            env  {:method        "POST"
                  :path          path
                  :body-sha256   body-sha
                  :ts            ts
                  :nonce         nonce
                  :fp-digest     (:digest fp)
                  :host-user-id  (or host-user-id "")
                  :key-id        key-id}
            wire (sign-envelope! env (:private-key keypair) alg)]
      {:envelope         wire
       :pubkey-canonical pubkey-bytes
       :alg              alg})))

(defn rotate-key!
  "Generate a new keypair, sign a rotation envelope with the OLD key,
  POST it to /v1/rotate-key. On success, persist the new keypair and
  notify other tabs.

  The signed envelope's body-sha256 binds to the intent string
  `b64url(new-pub) + \":\" + name(new-alg)` — so a captured rotate-key
  envelope cannot be replayed to install a different new pubkey.

  Returns a promise resolving to the parsed server response."
  []
  (ensure-initialized!)
  (let [{:keys [endpoint]} @state]
    (tabs/with-keygen-lock
      (fn []
        (p/let [old-alg     (:alg @state)
                new-keypair (crypto/generate-keypair old-alg)
                new-pub     (crypto/export-public (:public-key new-keypair))
                intent      (envelope/rotate-key-intent-utf8 new-pub old-alg)
                {:keys [envelope]} (sign-control-envelope!
                                    {:path "/v1/rotate-key"}
                                    intent)
                resp (http-post endpoint "/v1/rotate-key"
                                {:envelope   envelope
                                 :new-pubkey (envelope/b64url-encode new-pub)
                                 :new-alg    (name old-alg)})]
          (when (and (>= (:status resp) 200) (< (:status resp) 300))
            (let [new-key-id (crypto/thumbprint new-pub)]
              (storage/put-keypair! new-keypair)
              (storage/write-meta!
                {:key-id     (envelope/b64url-encode new-key-id)
                 :alg        (name old-alg)
                 :created-at (iso8601-now)
                 :version    1})
              (tabs/post! {:type "key-rotated"
                           :key-id (envelope/b64url-encode new-key-id)})
              (swap! state assoc
                     :keypair new-keypair
                     :pubkey-bytes new-pub
                     :key-id new-key-id)))
          resp)))))

(defn revoke!
  "Sign a /v1/revoke-key envelope with the current keypair and POST it.
  On success, clear local state (the keypair the server just revoked
  is no longer usable).

  Returns a promise resolving to the parsed server response."
  []
  (ensure-initialized!)
  (let [{:keys [endpoint]} @state]
    (p/let [{:keys [envelope]} (sign-control-envelope!
                                {:path "/v1/revoke-key"}
                                (js/Uint8Array. 0))
            resp (http-post endpoint "/v1/revoke-key" {:envelope envelope})]
      (when (and (>= (:status resp) 200) (< (:status resp) 300))
        (storage/clear-all!)
        (swap! state assoc :keypair nil :pubkey-bytes nil :key-id nil
                            :initialized? false))
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

;; -- knowledge-factor: set-verifier / recover -----------------------------
;;
;; A knowledge factor (a secret only the user knows) lets the SAME identity
;; be reclaimed from a new device after the device key is lost. The server
;; stores only an encrypted verifier; the secret never leaves the browser.
;; Both calls are COLD paths — they pull in Argon2id + Ed25519 + BIP-39
;; (see `client.kf`), never touched by the hot verify path.

(defn set-verifier!
  "Bind a knowledge factor to the current identity so it can be reclaimed
  from a new device. Device-authenticated: derives the KF Ed25519 keypair
  from `secret` + this identity's UUID, then signs a /v1/set-verifier
  envelope with the current DEVICE key, intent-bound to the KF public key.

  Requires a known identity_ref — call `verify` (or `bootstrap`) first; its
  response establishes it. The KF private key is derived, used to compute
  the public verifier, and discarded — it is never sent or stored.

  Returns a promise resolving to {:status, :body, :mnemonic}. `:mnemonic`
  is the 12-word BIP-39 recovery phrase the user MUST write down; recovery
  needs both the phrase and the secret."
  [{:keys [secret]}]
  (ensure-initialized!)
  (let [{:keys [endpoint identity-ref]} @state]
    (when-not identity-ref
      (throw (ex-info "set-verifier! requires a known identity_ref; call verify or bootstrap first" {})))
    (p/let [{:keys [pub]} (kf/derive-kf-keypair secret identity-ref)
            intent (envelope/set-verifier-intent-utf8 pub :ed25519)
            {:keys [envelope]} (sign-control-envelope! {:path "/v1/set-verifier"} intent)
            resp (http-post endpoint "/v1/set-verifier"
                            {:envelope  envelope
                             :kf-pubkey (envelope/b64url-encode pub)
                             :kf-alg    "ed25519"})]
      (assoc resp :mnemonic (kf/mnemonic-of identity-ref)))))

(defn recover!
  "Reclaim an existing identity onto THIS (freshly initialized) device using
  the recovery phrase + the knowledge-factor secret. Decodes the mnemonic to
  the identity UUID, re-derives the KF keypair, signs the kf-challenge with
  it, and signs a /v1/recover-identity envelope with this device's key. The
  new-key envelope and the kf-challenge share one nonce so the proof is both
  route-bound and single-use.

  On success the current device key is attached to the recovered identity
  (inheriting its earned tier — reclaim grants no uplift) and identity_ref is
  recorded. Returns a promise resolving to the parsed server response. All
  proof failures collapse to E_UNAUTHORIZED (the server never reveals which
  check failed, nor whether the identity exists)."
  [{:keys [secret mnemonic]}]
  (ensure-initialized!)
  (let [{:keys [endpoint keypair pubkey-bytes key-id alg host-user-id]} @state
        identity-ref (kf/uuid-of mnemonic)]
    (p/let [{:keys [priv]} (kf/derive-kf-keypair secret identity-ref)
            fp        (fingerprint/compute-digest)
            nonce     (random-bytes 16)
            challenge (envelope/kf-challenge-bytes identity-ref key-id nonce)
            kf-sig    (kf/kf-sign priv challenge)
            intent    (envelope/recover-intent-utf8 identity-ref pubkey-bytes kf-sig)
            body-sha  (crypto/sha256 intent)
            env       {:method       "POST"
                       :path         "/v1/recover-identity"
                       :body-sha256  body-sha
                       :ts           (iso8601-now)
                       :nonce        nonce
                       :fp-digest    (:digest fp)
                       :host-user-id (or host-user-id "")
                       :key-id       key-id}
            wire (sign-envelope! env (:private-key keypair) alg)
            resp (http-post endpoint "/v1/recover-identity"
                            {:identity-ref identity-ref
                             :new-pubkey   (envelope/b64url-encode pubkey-bytes)
                             :new-alg      (name alg)
                             :kf-alg       "ed25519"
                             :kf-sig       (envelope/b64url-encode kf-sig)
                             :envelope     wire})]
      (when (and (>= (:status resp) 200) (< (:status resp) 300))
        (swap! state assoc :identity-ref identity-ref))
      resp)))
