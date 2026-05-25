(ns continuity-auth.server.http.handlers.rotate-key
  "POST /v1/rotate-key — register a successor pubkey, signed by the old.

  Per ontology §4 the rotation produces a successor `Pubkey` bound to
  the same `Identity`. The predecessor is *future-dated revoked* at
  `now + grace_seconds`; until then both keys verify, and the client
  can finish in-flight requests with the old key before switching over.
  After the grace window passes, the old key is treated as revoked.

  Request body:
    {\"envelope\":   <wire-envelope, signed for POST /v1/rotate-key,
                      body-sha256 = sha256(rotate-key-intent(new-pubkey,new-alg));
                      envelope.key-id == thumbprint of the OLD key>,
     \"new-pubkey\": <base64url canonical bytes of the NEW pubkey>,
     \"new-alg\":    \"ed25519\" | \"p256\"}

  The intent-bound body-sha256 prevents a captured envelope from being
  replayed to install a DIFFERENT new pubkey: the user's signed bytes
  cover the exact (new-pubkey, new-alg) the server is about to commit.

  Response (200):
    {\"ok\":               true,
     \"new_key_id\":       <b64url thumbprint of the new pubkey>,
     \"grace_expires_at\": <ISO-8601 timestamp; old key valid until this>}

  Errors:
    E_BAD_REQUEST     — missing / wrong-length fields, malformed payload
    E_UNAUTHORIZED    — old-key signature fails OR envelope not bound to
                        this route+intent
    E_FORBIDDEN       — old key is already revoked
    E_REPLAY          — envelope nonce already used
    E_CONFLICT        — new pubkey is already registered to some identity"
  (:require
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.hash :as hash]
   [continuity-auth.server.crypto.pubkey :as pubkey]
   [continuity-auth.server.http.envelope-check :as ec]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.http.util :as util]
   [continuity-auth.server.storage.protocol :as storage]))

(def ^:private route-path "/v1/rotate-key")

(defn make-handler
  "Build the rotate-key handler.

  deps: {:store               Storage
         :clock               (fn [] java.util.Date)
         :tolerance-seconds   long
         :nonce-ttl-seconds   long
         :grace-seconds       long  ; rotation overlap window, default 86400}"
  [{:keys [store clock tolerance-seconds nonce-ttl-seconds grace-seconds]
    :or   {grace-seconds 86400}}]
  (fn [request]
    (let [{:keys [envelope pubkey-bytes alg]}
          (util/parse-pubkey-payload (:body-params request)
                                     {:pubkey-key :new-pubkey
                                      :alg-key    :new-alg})
          now           (clock)
          snap          (storage/snapshot store)
          ;; Reject if the new pubkey is already registered BEFORE the
          ;; signature check — saves the work and gives a deterministic
          ;; error early.
          new-thumb     (pubkey/alg+canonical->thumbprint alg pubkey-bytes)
          _             (when (storage/find-pubkey-by-thumbprint store snap new-thumb)
                          (errors/fail! :E_CONFLICT "new pubkey already registered"))
          intent-bytes  (envelope/rotate-key-intent-utf8 pubkey-bytes alg)
          intent-sha    (hash/sha256 intent-bytes)
          old-rec       (ec/verify-existing-envelope!
                         {:store              store
                          :snap               snap
                          :envelope           envelope
                          :tolerance-seconds  tolerance-seconds
                          :nonce-ttl-seconds  nonce-ttl-seconds
                          :now                now
                          :expect             {:method      "POST"
                                               :path        route-path
                                               :body-sha256 intent-sha}})
          identity-eid  (util/identity-eid-of old-rec)
          grace-expires (java.util.Date.
                          (+ (.getTime ^java.util.Date now)
                             (* 1000 (long grace-seconds))))
          ;; Future-dated revocation on the old key is honored by
          ;; envelope-check + merge/classify, which compare `now` to
          ;; `:pubkey/revoked-at` rather than treating any non-nil
          ;; value as revoked.
          tx (into [{:db/id              -1
                     :pubkey/id          new-thumb
                     :pubkey/identity    identity-eid
                     :pubkey/bytes       pubkey-bytes
                     :pubkey/alg         alg
                     :pubkey/created-at  now
                     :pubkey/rotation-of (:db/id old-rec)}]
                   (util/revoke-tx {:pubkey-eid   (:db/id old-rec)
                                    :identity-eid identity-eid
                                    :revoked-at   grace-expires
                                    :event-ts     now
                                    :reason       :rotate-key}))]
      (storage/transact! store tx)
      {:status  200
       :headers {"Content-Type" "application/json; charset=utf-8"}
       :body    {:ok               true
                 :new_key_id       (envelope/b64url-encode new-thumb)
                 :grace_expires_at (util/iso8601 grace-expires)}})))
