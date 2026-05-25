(ns continuity-auth.server.http.handlers.bootstrap
  "POST /v1/bootstrap — first signed request from a fresh LS keypair.

  Request body shape:
    {\"envelope\":  <wire-envelope>,
     \"pubkey\":    <base64url-encoded canonical pubkey bytes>,
     \"alg\":       \"ed25519\" | \"p256\"}

  Response:
    {\"ok\":           true,
     \"identity_ref\": <uuid string>,
     \"tier\":         \"anonymous\"}

  Behavior:
    - Validate inputs and envelope structure.
    - Compute the pubkey thumbprint and confirm it matches envelope.key-id.
    - Verify the signature against the supplied pubkey.
    - Atomically record the nonce (replay defense).
    - Create identity + pubkey + first tuple (one transaction)."
  (:require
   [continuity-auth.crypto :as crypto]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.http.envelope-check :as ec]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.identity.merge :as merge]
   [continuity-auth.server.storage.protocol :as storage]))

(defn- read-bootstrap-payload
  "Parse the request body into structured form. Throws E_BAD_REQUEST on
  malformed input."
  [body-params]
  (let [{:keys [envelope pubkey alg]} body-params]
    (when-not (and envelope pubkey alg)
      (errors/fail! :E_BAD_REQUEST "missing envelope / pubkey / alg"))
    (let [alg-kw (keyword alg)]
      (when-not (crypto/algorithm? alg-kw)
        (errors/fail! :E_BAD_REQUEST "unknown alg"))
      (let [env (try (envelope/wire->envelope envelope)
                     (catch Exception _
                       (errors/fail! :E_BAD_REQUEST "malformed envelope")))
            pkb (try (envelope/b64url-decode pubkey)
                     (catch Exception _
                       (errors/fail! :E_BAD_REQUEST "malformed pubkey")))]
        (when-not (= (count pkb) (get crypto/pubkey-byte-length alg-kw))
          (errors/fail! :E_BAD_REQUEST "pubkey wrong length for alg"))
        {:envelope env :pubkey-bytes pkb :alg alg-kw}))))

(defn make-handler
  "Build the bootstrap handler with injected deps.

  deps: {:store        Storage
         :clock        (fn [] java.util.Date)
         :tolerance-seconds long
         :nonce-ttl-seconds long}"
  [{:keys [store clock tolerance-seconds nonce-ttl-seconds]}]
  (fn [request]
    (let [{:keys [envelope pubkey-bytes alg]}
          (read-bootstrap-payload (:body-params request))
          now (clock)
          ;; Verify cryptography + record nonce.
          pubkey (ec/verify-bootstrap-envelope!
                  {:store              store
                   :envelope           envelope
                   :pubkey-bytes       pubkey-bytes
                   :alg                alg
                   :tolerance-seconds  tolerance-seconds
                   :nonce-ttl-seconds  nonce-ttl-seconds
                   :now                now})
          ;; Build the identity + pubkey + tuple tx.
          ip  (:cauth/client-ip request)
          fp  (:fp-digest envelope)
          tx  (merge/bootstrap-tx
               {:ip ip :fp-digest fp} pubkey now)
          _   (storage/transact! store tx)
          ;; Lookup the new identity to return its UUID.
          snap (storage/snapshot store)
          identity (storage/pull
                    store snap
                    [:pubkey/id (:id pubkey)]
                    [:pubkey/identity])
          identity-eid (:db/id (:pubkey/identity identity))
          identity-rec (storage/pull store snap identity-eid
                                      [:identity/id])]
      {:status  201
       :headers {"Content-Type" "application/json; charset=utf-8"}
       :body    {:ok            true
                 :identity_ref  (str (:identity/id identity-rec))
                 :tier          "anonymous"}})))
