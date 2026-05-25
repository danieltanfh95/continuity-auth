(ns continuity-auth.server.http.handlers.revoke-key
  "POST /v1/revoke-key — user-initiated revocation.

  Per ontology §4 explicit revocation sets `:pubkey/revoked-at = now`,
  which takes effect immediately for all subsequent verify calls. There
  is no grace window for explicit revocation (unlike rotation).

  Request body:
    {\"envelope\": <wire-envelope, signed for POST /v1/revoke-key,
                    with body-sha256 = sha256(\"\");
                    envelope.key-id == thumbprint of the key to revoke>}

  The envelope MUST be route-bound to this endpoint. A signing oracle
  on any other path (e.g. an XSS that triggers `sign-fetch` against
  `/api/anything`) cannot drive revocation against the user's key.

  Response (200):
    {\"ok\":         true,
     \"revoked_at\": <ISO-8601 timestamp>}

  Errors:
    E_BAD_REQUEST  — missing / malformed envelope
    E_UNAUTHORIZED — signature fails OR envelope not bound to this route
    E_FORBIDDEN    — pubkey is already revoked
    E_REPLAY       — envelope nonce already used"
  (:require
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.hash :as hash]
   [continuity-auth.server.http.envelope-check :as ec]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.http.util :as util]
   [continuity-auth.server.storage.protocol :as storage]))

(def ^:private route-path "/v1/revoke-key")

(def ^:private empty-body-sha256
  "sha256(``) — the binding body-sha256 for revoke-key envelopes."
  (hash/sha256 (byte-array 0)))

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
                 :now                now
                 :expect             {:method      "POST"
                                      :path        route-path
                                      :body-sha256 empty-body-sha256}})
          identity-eid (util/identity-eid-of rec)
          tx (util/revoke-tx {:pubkey-eid   (:db/id rec)
                              :identity-eid identity-eid
                              :revoked-at   now
                              :reason       :revoke-key})]
      (storage/transact! store tx)
      {:status  200
       :headers {"Content-Type" "application/json; charset=utf-8"}
       :body    {:ok         true
                 :revoked_at (util/iso8601 now)}})))
