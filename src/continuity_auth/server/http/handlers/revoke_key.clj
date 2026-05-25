(ns continuity-auth.server.http.handlers.revoke-key
  "POST /v1/revoke-key — user-initiated revocation.

  Per ontology §4 explicit revocation sets `:pubkey/revoked-at = now`,
  which takes effect immediately for all subsequent verify calls. There
  is no grace window for explicit revocation (unlike rotation).

  Request body:
    {\"envelope\": <wire-envelope signed by the key to revoke;
                   envelope.key-id == thumbprint of that key>}

  Response (200):
    {\"ok\":         true,
     \"revoked_at\": <ISO-8601 timestamp>}

  Errors:
    E_BAD_REQUEST  — missing / malformed envelope
    E_UNAUTHORIZED — signature fails to verify
    E_FORBIDDEN    — pubkey is already revoked
    E_REPLAY       — envelope nonce already used"
  (:require
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.http.envelope-check :as ec]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.storage.protocol :as storage]))

(defn- iso8601
  ^String [^java.util.Date d]
  (let [fmt (java.text.SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")]
    (.setTimeZone fmt (java.util.TimeZone/getTimeZone "UTC"))
    (.format fmt d)))

(defn- read-payload
  [body-params]
  (let [{:keys [envelope]} body-params]
    (when-not envelope
      (errors/fail! :E_BAD_REQUEST "missing envelope"))
    (try (envelope/wire->envelope envelope)
         (catch Exception _
           (errors/fail! :E_BAD_REQUEST "malformed envelope")))))

(defn make-handler
  "Build the revoke-key handler.

  deps: {:store              Storage
         :clock              (fn [] java.util.Date)
         :tolerance-seconds  long
         :nonce-ttl-seconds  long}"
  [{:keys [store clock tolerance-seconds nonce-ttl-seconds]}]
  (fn [request]
    (let [env  (read-payload (:body-params request))
          now  (clock)
          snap (storage/snapshot store)
          rec  (ec/verify-existing-envelope!
                {:store              store
                 :snap               snap
                 :envelope           env
                 :tolerance-seconds  tolerance-seconds
                 :nonce-ttl-seconds  nonce-ttl-seconds
                 :now                now})
          identity-eid (or (:db/id (:pubkey/identity rec))
                           (:pubkey/identity rec))
          tx [{:db/id             (:db/id rec)
               :pubkey/revoked-at now}
              {:trust-event/identity identity-eid
               :trust-event/ts       now
               :trust-event/delta    0.0
               :trust-event/reason   :revoke-key}]]
      (storage/transact! store tx)
      {:status  200
       :headers {"Content-Type" "application/json; charset=utf-8"}
       :body    {:ok         true
                 :revoked_at (iso8601 now)}})))
