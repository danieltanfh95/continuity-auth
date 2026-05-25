(ns continuity-auth.server.http.handlers.bootstrap
  "POST /v1/bootstrap — first signed request from a fresh LS keypair.

  Request body shape:
    {\"envelope\":  <wire-envelope, route-bound to POST /v1/bootstrap>,
     \"pubkey\":    <base64url-encoded canonical pubkey bytes>,
     \"alg\":       \"ed25519\" | \"p256\"}

  Response:
    {\"ok\":           true,
     \"identity_ref\": <uuid string>,
     \"tier\":         \"anonymous\"}

  Behavior:
    - Validate inputs and envelope structure.
    - Enforce route binding: envelope must be signed for `POST /v1/bootstrap`.
    - Compute the pubkey thumbprint and confirm it matches envelope.key-id.
    - Reject duplicate-pubkey bootstrap — otherwise the unique-identity
      upsert on `:pubkey/id` would rebind the existing pubkey to a fresh
      neutral identity, defeating score/tier/rate-limit continuity.
    - Verify the signature against the supplied pubkey.
    - Atomically record the nonce (replay defense).
    - Create identity + pubkey + first tuple (one transaction)."
  (:require
   [continuity-auth.server.http.envelope-check :as ec]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.http.util :as util]
   [continuity-auth.server.identity.merge :as merge]
   [continuity-auth.server.storage.protocol :as storage]))

(def ^:private route-path "/v1/bootstrap")

(defn make-handler
  "Build the bootstrap handler with injected deps.

  deps: {:store        Storage
         :clock        (fn [] java.util.Date)
         :tolerance-seconds long
         :nonce-ttl-seconds long}"
  [{:keys [store clock tolerance-seconds nonce-ttl-seconds]}]
  (fn [request]
    (let [{:keys [envelope pubkey-bytes alg]}
          (util/parse-pubkey-payload (:body-params request) {})
          now  (clock)
          ;; Pre-snapshot: reject if this pubkey already exists. Done
          ;; BEFORE the crypto verify so that an attacker with a valid
          ;; envelope cannot cheaply force the unique-identity upsert
          ;; to rebind an existing pubkey.
          snap (storage/snapshot store)
          _    (when (storage/find-pubkey-by-thumbprint
                      store snap (:key-id envelope))
                 (errors/fail! :E_CONFLICT "pubkey already registered"))
          ;; Verify cryptography + route binding + record nonce.
          pubkey (ec/verify-bootstrap-envelope!
                  {:store              store
                   :envelope           envelope
                   :pubkey-bytes       pubkey-bytes
                   :alg                alg
                   :tolerance-seconds  tolerance-seconds
                   :nonce-ttl-seconds  nonce-ttl-seconds
                   :now                now
                   :expect             {:method "POST" :path route-path}})
          ;; Build the identity + pubkey + tuple tx.
          ip  (:cauth/client-ip request)
          fp  (:fp-digest envelope)
          tx  (merge/bootstrap-tx
               {:ip ip :fp-digest fp} pubkey now)
          _   (storage/transact! store tx)
          ;; Lookup the new identity to return its UUID.
          snap2 (storage/snapshot store)
          identity (storage/pull
                    store snap2
                    [:pubkey/id (:id pubkey)]
                    [:pubkey/identity])
          identity-eid (:db/id (:pubkey/identity identity))
          identity-rec (storage/pull store snap2 identity-eid
                                      [:identity/id])]
      {:status  201
       :headers {"Content-Type" "application/json; charset=utf-8"}
       :body    {:ok            true
                 :identity_ref  (str (:identity/id identity-rec))
                 :tier          "anonymous"}})))
