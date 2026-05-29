(ns continuity-auth.server.http.handlers.set-verifier
  "POST /v1/set-verifier — bind a knowledge factor to the current identity.

  Authenticated by the EXISTING device key. The client derives an Ed25519
  keypair from a secret only it knows (`Argon2id(secret, salt)`), and sends
  the PUBLIC key; the server wraps it under the kf-wrap keystore secret and
  stores it on the identity. The secret and the KF private key never leave
  the client.

  Request body:
    {\"envelope\":  <wire-envelope, signed by the DEVICE key, route-bound to
                     POST /v1/set-verifier, body-sha256 =
                     sha256(set-verifier-intent(kf-pubkey, kf-alg))>,
     \"kf-pubkey\": <base64url canonical Ed25519 pubkey bytes>,
     \"kf-alg\":    \"ed25519\"}

  The intent-bound body-sha256 stops a captured envelope from installing a
  DIFFERENT verifier. Setting a verifier when one already exists overwrites
  it (re-bind), gated by the device key. A verifier grants no tier change.

  Response (200): {\"ok\": true, \"kf_set_at\": <ISO-8601>}

  Errors:
    E_BAD_REQUEST  — missing/malformed fields, kf-alg not ed25519
    E_UNAUTHORIZED — device-key signature / route binding failed
    E_REPLAY       — envelope nonce already used"
  (:require
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.hash :as hash]
   [continuity-auth.server.crypto.verifier-box :as vbox]
   [continuity-auth.server.http.envelope-check :as ec]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.http.util :as util]
   [continuity-auth.server.storage.protocol :as storage]))

(def ^:private route-path "/v1/set-verifier")

(defn make-handler
  "Build the set-verifier handler.

  deps: {:store             Storage
         :clock             (fn [] java.util.Date)
         :tolerance-seconds long
         :nonce-ttl-seconds long
         :kf-wrap-secret    ^bytes 32-byte AES key}"
  [{:keys [store clock tolerance-seconds nonce-ttl-seconds kf-wrap-secret]}]
  (when-not kf-wrap-secret
    (throw (ex-info "set-verifier/make-handler: missing :kf-wrap-secret" {})))
  (fn [request]
    (let [{:keys [envelope pubkey-bytes alg]}
          (util/parse-pubkey-payload (:body-params request)
                                     {:pubkey-key :kf-pubkey :alg-key :kf-alg})
          _    (when-not (= :ed25519 alg)
                 (errors/fail! :E_BAD_REQUEST "kf-alg must be ed25519"))
          now  (clock)
          snap (storage/snapshot store)
          intent-sha (hash/sha256
                      (envelope/set-verifier-intent-utf8 pubkey-bytes alg))
          record (ec/verify-existing-envelope!
                  {:store             store
                   :snap              snap
                   :envelope          envelope
                   :tolerance-seconds tolerance-seconds
                   :nonce-ttl-seconds nonce-ttl-seconds
                   :now               now
                   :expect            {:method      "POST"
                                       :path        route-path
                                       :body-sha256 intent-sha}})
          identity-eid (util/identity-eid-of record)
          wrapped      (vbox/wrap kf-wrap-secret pubkey-bytes)
          tx [{:db/id                identity-eid
               :identity/kf-verifier wrapped
               :identity/kf-alg      alg
               :identity/kf-kdf      :argon2id-v1
               :identity/kf-set-at   now}
              {:trust-event/identity identity-eid
               :trust-event/ts       now
               :trust-event/delta    0.0
               :trust-event/reason   :set-verifier}]]
      (storage/transact! store tx)
      {:status  200
       :headers {"Content-Type" "application/json; charset=utf-8"}
       :body    {:ok        true
                 :kf_set_at (util/iso8601 now)}})))
