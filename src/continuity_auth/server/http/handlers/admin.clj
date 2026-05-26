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
  #{:prometheus-bearer :host-keys-path :admin-keys-path
    :uri :password :secret :token :dburl})

(def ^:private userinfo-uri-pattern
  "Match the userinfo portion of a URI: `<scheme>://<userinfo>@<rest>`.
  Used by `strip-uri-userinfo` to redact credentials inline in any
  string value of the dumped config (e.g. `dtlv://user:pw@host/db`)."
  #"([A-Za-z][A-Za-z0-9+.\-]*://)[^@/\s]*@")

(defn- strip-uri-userinfo
  "Return `s` with any `scheme://user:pw@` prefix rewritten to
  `scheme://<redacted>@`. Strings that contain no userinfo are returned
  unchanged. Non-string values pass through."
  [v]
  (if (string? v)
    (str/replace v userinfo-uri-pattern "$1<redacted>@")
    v))

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

(def ^:private dummy-admin-secret
  "Deterministic fallback secret used when the supplied key-id is
  unknown. HMAC-SHA256 over any 32-byte key takes the same wall-clock
  time, so computing against this dummy makes the unknown-key code path
  indistinguishable from a valid-key-bad-sig path — closing the
  admin-key-id timing oracle."
  (byte-array 32))

(defn- safe-b64url-decode
  "b64url-decode that returns a fixed-size zero byte-array on failure
  instead of throwing. We use this only for inputs that feed into the
  uniform-timing HMAC compare — the resulting `auth-failed?` flag is
  what surfaces a bad input to the caller. We refuse to short-circuit
  on a decode exception, because that would leak whether `nonce` or
  `sig` was malformed via wall-clock."
  ^bytes [s fallback-len]
  (try (envelope/b64url-decode s)
       (catch Exception _ (byte-array (long fallback-len)))))

(defn- verify-admin!
  "Validate the admin-auth headers + signature against the request body.
  Returns the resolved key-id on success; throws via `errors/fail!` on
  failure.

  All public failure paths return E_UNAUTHORIZED. Wall-clock timing is
  uniform across:
    - unknown key-id  → HMAC computed against a deterministic dummy
    - bad timestamp   → HMAC still computed; bad-ts? folded into the
                        final auth-failed? AND
    - bad signature   → HMAC computed; constant-time-compare fails

  The unknown-key timing oracle — measure latency for `valid-key,
  bad-sig` vs `unknown-key, anything` — is closed."
  [{:keys [keystore tolerance-seconds nonce-ttl-seconds store ^java.util.Date now]} request]
  (when (empty? keystore)
    (errors/fail! :E_FORBIDDEN "admin endpoints disabled (no admin keystore loaded)"))
  (let [{:keys [key-id ts nonce sig]} (read-headers request)]
    (when-not (and key-id ts nonce sig)
      (errors/fail! :E_UNAUTHORIZED "missing admin auth headers"))
    (let [real-secret    (get keystore key-id)
          secret         (or real-secret dummy-admin-secret)
          unknown-key?   (nil? real-secret)
          ^java.util.Date parsed
                         (try (java.util.Date/from (java.time.Instant/parse ts))
                              (catch Exception _ nil))
          bad-ts?        (or (nil? parsed)
                             (> (Math/abs (- (.getTime now) (.getTime ^java.util.Date parsed)))
                                (* 1000 (long tolerance-seconds))))
          nonce-bytes    (safe-b64url-decode nonce 16)
          sig-bytes      (safe-b64url-decode sig 32)
          body           (or (body-bytes-of request) (byte-array 0))
          body-sha       (hash/sha256 body)
          input          (hmac/signing-input
                          {:method      (-> request :request-method name str/upper-case)
                           :path        (or (:uri request) "")
                           :body-sha256 body-sha
                           :ts          ts
                           :nonce       nonce-bytes})
          expected       (hmac/hmac-sha256 secret input)
          sig-ok?        (hash/constant-time-equal? expected sig-bytes)
          auth-failed?   (or unknown-key? bad-ts? (not sig-ok?))]
      (when auth-failed?
        (errors/fail! :E_UNAUTHORIZED "admin auth failed"))
      ;; Replay defense — only AFTER auth verifies, so attackers can't
      ;; pollute the nonce cache with arbitrary values.
      (let [result (nonce/check-and-record! store nonce-bytes nonce-ttl-seconds now)]
        (when (= :replay result)
          (errors/fail! :E_REPLAY "admin nonce replay")))
      key-id)))

;; -- handlers --------------------------------------------------------------

(defn make-revoke-key-handler
  "POST /v1/admin/revoke-key. Body: {\"key_id\": <b64url thumbprint>}.

  Force-revokes the pubkey at `now`. Does NOT require a user-signed
  envelope — this is the ops escape hatch for compromised keys where
  the user can no longer (or won't) sign a revoke envelope."
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
  "Walk `m`, applying two layers of redaction:

    1. Any entry whose key is in `sensitive-config-keys` has its value
       replaced with `\"<redacted>\"`.
    2. Any string value (in any position) that looks like a URI with
       userinfo (`scheme://user:pw@host`) has its userinfo stripped
       via `strip-uri-userinfo`.

  The two-pass walk is necessary because a credential can leak either
  via the key name (`:prometheus-bearer`) or inline in the value of a
  more innocuous key (e.g. a Datalevin URI placed under `:uri` —
  already in sensitive-keys, but defense-in-depth in case a future
  config knob places it elsewhere)."
  [m]
  (walk/postwalk
   (fn [node]
     (cond
       (map? node)
       (reduce-kv (fn [acc k v]
                    (assoc acc k (if (sensitive-config-keys k)
                                   "<redacted>"
                                   (strip-uri-userinfo v))))
                  {}
                  node)

       (string? node)
       (strip-uri-userinfo node)

       :else node))
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
