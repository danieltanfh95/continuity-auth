(ns continuity-auth.server.http.handlers.admin
  "Admin endpoints — HMAC-authenticated, intended for ops use.

  Surface:
    POST /v1/admin/revoke-key — force-revoke a pubkey by its thumbprint
    GET  /v1/admin/config     — dump the effective resolved config (with
                                sensitive fields redacted)

  Authentication: every admin request must carry the headers
    X-Admin-Key-Id  — the id of the HMAC key
    X-Admin-Ts      — ISO-8601, must be within ±60s of server now
    X-Admin-Nonce   — base64url 16 raw bytes, replay-cached
    X-Admin-Sig     — base64url HMAC-SHA256 over
                      method || \"\\n\" || path || \"\\n\"
                      || sha256(body) || \"\\n\" || ts || \"\\n\" || nonce

  Auth failure returns E_UNAUTHORIZED. Replay returns E_REPLAY.

  The admin keystore is loaded once at startup and supplied to the
  handler factory via deps; it is a `{key-id-string -> ^bytes secret}`
  map. Empty/missing keystore disables the admin endpoints entirely
  (returning E_FORBIDDEN) so the server cannot accidentally be left
  open to anonymous admin calls."
  (:require
   [clojure.string :as str]
   [clojure.walk :as walk]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.admin.hmac :as hmac]
   [continuity-auth.server.crypto.hash :as hash]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.http.util :as util]
   [continuity-auth.server.replay.nonce :as nonce]
   [continuity-auth.server.storage.protocol :as storage]))

(def ^:private sensitive-config-keys
  "Keys whose values must never appear in a config dump."
  #{:prometheus-bearer :host-keys-path :admin-keys-path})

(defn- read-headers [request]
  (let [h (:headers request)]
    {:key-id (get h "x-admin-key-id")
     :ts     (get h "x-admin-ts")
     :nonce  (get h "x-admin-nonce")
     :sig    (get h "x-admin-sig")}))

(defn- body-bytes-of
  "Return the original raw request body bytes, stashed by the
  wrap-body-size-limit middleware at `:cauth/raw-body`. Returns nil if
  the request had no body."
  ^bytes [request]
  (:cauth/raw-body request))

(defn- verify-admin!
  "Validate the admin-auth headers + signature against the request body.
  Returns the resolved key-id on success; throws an errors/fail! exception
  on failure."
  [{:keys [keystore tolerance-seconds nonce-ttl-seconds store ^java.util.Date now]} request]
  (when (empty? keystore)
    (errors/fail! :E_FORBIDDEN "admin endpoints disabled (no admin keystore loaded)"))
  (let [{:keys [key-id ts nonce sig]} (read-headers request)]
    (when-not (and key-id ts nonce sig)
      (errors/fail! :E_UNAUTHORIZED "missing admin auth headers"))
    (let [secret (get keystore key-id)]
      (when-not secret
        (errors/fail! :E_UNAUTHORIZED "unknown admin key-id"))
      ;; Timestamp window
      (let [^java.util.Date parsed (try (java.util.Date/from (java.time.Instant/parse ts))
                                        (catch Exception _ nil))]
        (when-not parsed
          (errors/fail! :E_UNAUTHORIZED "invalid admin ts"))
        (when (> (Math/abs (- (.getTime now) (.getTime parsed)))
                 (* 1000 (long tolerance-seconds)))
          (errors/fail! :E_UNAUTHORIZED "admin ts outside clock-skew window")))
      ;; Signature
      (let [nonce-bytes (envelope/b64url-decode nonce)
            sig-bytes   (envelope/b64url-decode sig)
            body        (or (body-bytes-of request) (byte-array 0))
            body-sha    (hash/sha256 body)
            input       (hmac/signing-input
                         {:method      (-> request :request-method name str/upper-case)
                          :path        (or (:uri request) "")
                          :body-sha256 body-sha
                          :ts          ts
                          :nonce       nonce-bytes})
            expected    (hmac/hmac-sha256 secret input)]
        (when-not (hash/constant-time-equal? expected sig-bytes)
          (errors/fail! :E_UNAUTHORIZED "admin signature mismatch"))
        ;; Replay defense — only AFTER signature verifies, so attackers
        ;; can't pollute the nonce cache.
        (let [result (nonce/check-and-record! store nonce-bytes nonce-ttl-seconds now)]
          (when (= :replay result)
            (errors/fail! :E_REPLAY "admin nonce replay")))
        key-id))))

;; -- handlers --------------------------------------------------------------

(defn make-revoke-key-handler
  "POST /v1/admin/revoke-key. Body: {\"key_id\": <b64url thumbprint>}.

  Force-revokes the pubkey at `now`. Does NOT require an LS-signed
  envelope from the user — this is the ops escape hatch for compromised
  keys where the user can no longer (or won't) sign a revoke envelope."
  [{:keys [store clock keystore tolerance-seconds nonce-ttl-seconds]}]
  (fn [request]
    (let [now (clock)
          admin-id (verify-admin!
                    {:keystore          keystore
                     :tolerance-seconds tolerance-seconds
                     :nonce-ttl-seconds nonce-ttl-seconds
                     :store             store
                     :now               now}
                    request)
          {:keys [key_id]} (:body-params request)
          _ (when-not (string? key_id)
              (errors/fail! :E_BAD_REQUEST "missing key_id"))
          thumb (try (envelope/b64url-decode key_id)
                     (catch Exception _
                       (errors/fail! :E_BAD_REQUEST "malformed key_id")))
          snap (storage/snapshot store)
          rec  (storage/find-pubkey-by-thumbprint store snap thumb)
          _    (when-not rec
                 (errors/fail! :E_NOT_FOUND "unknown key-id"))
          identity-eid (util/identity-eid-of rec)
          tx (util/revoke-tx {:pubkey-eid   (:db/id rec)
                              :identity-eid identity-eid
                              :revoked-at   now
                              :reason       :admin-revoke})]
      (storage/transact! store tx)
      {:status  200
       :headers {"Content-Type" "application/json; charset=utf-8"
                 "X-Admin-Authenticated-As" admin-id}
       :body    {:ok         true
                 :revoked_at (util/iso8601 now)}})))

(defn- redact
  "Walk `m`, replacing the value of every entry whose key is in
  `sensitive-config-keys` with the string `\"<redacted>\"`. Handles
  arbitrary nesting (maps inside vectors inside maps, etc.) via postwalk
  — each map node is rewritten as its children are visited."
  [m]
  (walk/postwalk
   (fn [node]
     (if (map? node)
       (reduce-kv (fn [acc k v]
                    (assoc acc k (if (sensitive-config-keys k) "<redacted>" v)))
                  {}
                  node)
       node))
   m))

(defn make-config-handler
  "GET /v1/admin/config. Returns the effective resolved config (after
  aero + env vars), with sensitive fields redacted."
  [{:keys [store clock keystore tolerance-seconds nonce-ttl-seconds config]}]
  (fn [request]
    (let [now (clock)
          admin-id (verify-admin!
                    {:keystore          keystore
                     :tolerance-seconds tolerance-seconds
                     :nonce-ttl-seconds nonce-ttl-seconds
                     :store             store
                     :now               now}
                    request)]
      {:status  200
       :headers {"Content-Type" "application/json; charset=utf-8"
                 "X-Admin-Authenticated-As" admin-id}
       :body    (redact config)})))
