(ns continuity-auth.server.http.handlers.rotate-key
  "POST /v1/rotate-key — register a successor pubkey, signed by the old.

  Per ontology §4 the rotation produces a successor `Pubkey` bound to
  the same `Identity`. The predecessor is *future-dated revoked* at
  `now + grace_seconds`; until then both keys verify, and the client
  can finish in-flight requests with the old key before switching over.
  After the grace window passes, the old key is treated as revoked.

  Request body:
    {\"envelope\":   <wire-envelope signed by the OLD key,
                     key-id == old-key thumbprint>,
     \"new-pubkey\": <base64url canonical bytes of the NEW pubkey>,
     \"new-alg\":    \"ed25519\" | \"p256\"}

  Response (200):
    {\"ok\":               true,
     \"new_key_id\":       <b64url thumbprint of the new pubkey>,
     \"grace_expires_at\": <ISO-8601 timestamp; old key valid until this>}

  Errors:
    E_BAD_REQUEST     — missing / wrong-length fields, malformed payload
    E_UNAUTHORIZED    — old-key signature fails to verify
    E_FORBIDDEN       — old key is already revoked
    E_REPLAY          — envelope nonce already used
    E_CONFLICT        — new pubkey is already registered to some identity"
  (:require
   [continuity-auth.crypto :as crypto]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.pubkey :as pubkey]
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
  (let [{:keys [envelope new-pubkey new-alg]} body-params]
    (when-not (and envelope new-pubkey new-alg)
      (errors/fail! :E_BAD_REQUEST "missing envelope / new-pubkey / new-alg"))
    (let [alg-kw (keyword new-alg)]
      (when-not (crypto/algorithm? alg-kw)
        (errors/fail! :E_BAD_REQUEST "unknown new-alg"))
      (let [env (try (envelope/wire->envelope envelope)
                     (catch Exception _
                       (errors/fail! :E_BAD_REQUEST "malformed envelope")))
            pkb (try (envelope/b64url-decode new-pubkey)
                     (catch Exception _
                       (errors/fail! :E_BAD_REQUEST "malformed new-pubkey")))]
        (when-not (= (count pkb) (get crypto/pubkey-byte-length alg-kw))
          (errors/fail! :E_BAD_REQUEST "new-pubkey wrong length for new-alg"))
        {:envelope env :new-pubkey-bytes pkb :new-alg alg-kw}))))

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
    (let [{:keys [envelope new-pubkey-bytes new-alg]} (read-payload (:body-params request))
          now      (clock)
          snap     (storage/snapshot store)
          old-rec  (ec/verify-existing-envelope!
                    {:store              store
                     :snap               snap
                     :envelope           envelope
                     :tolerance-seconds  tolerance-seconds
                     :nonce-ttl-seconds  nonce-ttl-seconds
                     :now                now})
          new-thumb (pubkey/alg+canonical->thumbprint new-alg new-pubkey-bytes)]
      (when (storage/find-pubkey-by-thumbprint store snap new-thumb)
        (errors/fail! :E_CONFLICT "new pubkey already registered"))
      (let [identity-eid  (or (:db/id (:pubkey/identity old-rec))
                              (:pubkey/identity old-rec))
            grace-expires (java.util.Date.
                            (+ (.getTime ^java.util.Date now)
                               (* 1000 (long grace-seconds))))
            tx [{:db/id              -1
                 :pubkey/id          new-thumb
                 :pubkey/identity    identity-eid
                 :pubkey/bytes       new-pubkey-bytes
                 :pubkey/alg         new-alg
                 :pubkey/created-at  now
                 :pubkey/rotation-of (:db/id old-rec)}
                ;; Future-dated revocation on the old key (honored by
                ;; envelope-check + merge/classify, which compare now to
                ;; revoked-at rather than treating any non-nil value as
                ;; revoked — see §28 fix in this codebase).
                {:db/id             (:db/id old-rec)
                 :pubkey/revoked-at grace-expires}
                {:trust-event/identity identity-eid
                 :trust-event/ts       now
                 :trust-event/delta    0.0
                 :trust-event/reason   :rotate-key}]]
        (storage/transact! store tx)
        {:status  200
         :headers {"Content-Type" "application/json; charset=utf-8"}
         :body    {:ok               true
                   :new_key_id       (envelope/b64url-encode new-thumb)
                   :grace_expires_at (iso8601 grace-expires)}}))))
