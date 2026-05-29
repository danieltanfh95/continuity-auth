(ns continuity-auth.server.http.handlers.recover-identity
  "POST /v1/recover-identity — reclaim an existing identity from a new device.

  The new device proves the knowledge factor (a secret only the user knows)
  and attaches a fresh device key to the existing identity. The identity's
  accumulated spaced-continuity sketch is left untouched, so the reclaimed
  key inherits the EARNED tier — reclaim grants no uplift, only continuity.

  Two signatures, two roles:
    - the NEW-key envelope proves possession of the new private key and
      supplies route/nonce/timestamp binding (single-use via the nonce
      cache), exactly like /bootstrap;
    - the kf-sig proves the knowledge factor: it is an Ed25519 signature,
      by the secret-derived key, over `kf-challenge(identity-ref,
      new-pubkey-thumbprint, envelope-nonce)`. Binding to the new key's
      thumbprint stops an eavesdropper from swapping in their own pubkey.

  Request body:
    {\"identity-ref\": <UUID string; decoded client-side from the mnemonic>,
     \"new-pubkey\":   <base64url canonical bytes of the NEW device pubkey>,
     \"new-alg\":      \"ed25519\" | \"p256\",
     \"kf-alg\":       \"ed25519\",
     \"kf-sig\":       <base64url Ed25519 signature over the kf-challenge>,
     \"envelope\":     <wire-envelope signed by the NEW key, route-bound to
                        POST /v1/recover-identity, body-sha256 =
                        sha256(recover-intent(identity-ref, new-pubkey,
                                              kf-sig))>}

  Response (200): {\"ok\": true, \"identity_ref\": <same>,
                   \"tier\": <reclaimed tier>, \"new_key_id\": <b64url thumb>}

  Errors (all proof failures collapse to E_UNAUTHORIZED — see threat-model
  T10; an attacker must not learn which check failed, nor whether the
  identity exists or has a verifier):
    E_BAD_REQUEST  — missing/malformed fields, kf-alg not ed25519,
                     malformed identity-ref
    E_UNAUTHORIZED — new-key sig / route binding failed, identity unknown,
                     no verifier set, kf-sig invalid, verifier unwrap failed
    E_REPLAY       — envelope nonce already used
    E_CONFLICT     — the new pubkey is already registered"
  (:require
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.hash :as hash]
   [continuity-auth.server.crypto.pubkey :as pubkey]
   [continuity-auth.server.crypto.verifier-box :as vbox]
   [continuity-auth.server.crypto.verify :as verify]
   [continuity-auth.server.http.envelope-check :as ec]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.http.util :as util]
   [continuity-auth.server.identity.merge :as merge]
   [continuity-auth.server.identity.score :as score]
   [continuity-auth.server.ratelimit.tier :as tier]
   [continuity-auth.server.storage.protocol :as storage]))

(def ^:private route-path "/v1/recover-identity")

(defn- host-linked?
  [store snap identity-eid]
  (->> (storage/q store snap
                  '[:find [?e ...]
                    :in $ ?i ?st
                    :where
                    [?e :host-link/identity ?i]
                    [?e :host-link/state ?st]]
                  [identity-eid :committed])
       seq boolean))

(defn- parse-uuid-ref
  [^String s]
  (try
    (java.util.UUID/fromString s)
    (catch Exception _
      (errors/fail! :E_BAD_REQUEST "malformed identity-ref"))))

(defn make-handler
  "Build the recover-identity handler.

  deps: {:store             Storage
         :clock             (fn [] java.util.Date)
         :tolerance-seconds long
         :nonce-ttl-seconds long
         :kf-wrap-secret    ^bytes 32-byte AES key
         :scoring           spaced-continuity weight constants (or nil)
         :tier-thresholds   tier projection thresholds (or nil)}"
  [{:keys [store clock tolerance-seconds nonce-ttl-seconds kf-wrap-secret
            scoring tier-thresholds]
    :or   {scoring         score/default-scoring
           tier-thresholds tier/default-thresholds}}]
  (when-not kf-wrap-secret
    (throw (ex-info "recover-identity/make-handler: missing :kf-wrap-secret" {})))
  (fn [request]
    (let [body (:body-params request)
          {:keys [envelope pubkey-bytes alg]}
          (util/parse-pubkey-payload body {:pubkey-key :new-pubkey
                                           :alg-key    :new-alg})
          identity-ref (:identity-ref body)
          kf-alg-raw   (:kf-alg body)
          kf-sig-raw   (:kf-sig body)
          _ (when-not (and (string? identity-ref) kf-sig-raw)
              (errors/fail! :E_BAD_REQUEST "missing identity-ref / kf-sig"))
          _ (when-not (= "ed25519" kf-alg-raw)
              (errors/fail! :E_BAD_REQUEST "kf-alg must be ed25519"))
          kf-sig (try (envelope/b64url-decode kf-sig-raw)
                      (catch Exception _
                        (errors/fail! :E_BAD_REQUEST "malformed kf-sig")))
          now       (clock)
          new-thumb (pubkey/alg+canonical->thumbprint alg pubkey-bytes)
          snap      (storage/snapshot store)
          ;; Reject duplicate new pubkey before crypto, like /bootstrap and
          ;; /rotate-key, so a valid envelope can't force a unique upsert.
          _ (when (storage/find-pubkey-by-thumbprint store snap new-thumb)
              (errors/fail! :E_CONFLICT "new pubkey already registered"))
          ;; The new-key envelope proves possession of the new private key,
          ;; binds the route, and records the nonce. Its body-sha256 covers
          ;; the whole reclaim request (identity, new key, kf-sig).
          intent-sha (hash/sha256
                      (envelope/recover-intent-utf8 identity-ref pubkey-bytes kf-sig))
          _ (ec/verify-bootstrap-envelope!
             {:store             store
              :envelope          envelope
              :pubkey-bytes      pubkey-bytes
              :alg               alg
              :tolerance-seconds tolerance-seconds
              :nonce-ttl-seconds nonce-ttl-seconds
              :now               now
              :expect            {:method      "POST"
                                  :path        route-path
                                  :body-sha256 intent-sha}})
          ident-uuid (parse-uuid-ref identity-ref)
          identity   (storage/pull store snap [:identity/id ident-uuid]
                                   [:db/id
                                    :identity/kf-verifier
                                    :identity/kf-alg
                                    :identity/ever-tracked?
                                    :identity/created-at
                                    :identity/last-clean-at
                                    :identity/clean-count
                                    :identity/spacing
                                    :identity/violation-count])
          verifier  (:identity/kf-verifier identity)
          ;; Unknown identity OR no knowledge factor set are indistinguishable
          ;; on the wire — both fail uniformly (T10), never leaking existence.
          _ (when-not verifier
              (errors/fail! :E_UNAUTHORIZED "recovery unavailable"))
          kf-pub (try (vbox/unwrap kf-wrap-secret verifier)
                      (catch Exception _
                        (errors/fail! :E_UNAUTHORIZED "recovery unavailable")))
          challenge (envelope/kf-challenge-bytes identity-ref new-thumb (:nonce envelope))
          ok? (verify/verify (or (:identity/kf-alg identity) :ed25519)
                             kf-pub challenge kf-sig)
          _ (when-not ok?
              (errors/fail! :E_UNAUTHORIZED "recovery unavailable"))
          identity-eid (:db/id identity)
          tx [{:db/id             -1
               :pubkey/id         new-thumb
               :pubkey/identity   identity-eid
               :pubkey/bytes      pubkey-bytes
               :pubkey/alg        alg
               :pubkey/created-at now}
              {:trust-event/identity identity-eid
               :trust-event/ts       now
               :trust-event/delta    0.0
               :trust-event/reason   :recover-identity}]
          _ (storage/transact! store tx)
          ;; Reclaim grants no uplift: project the EXISTING sketch's tier
          ;; for the informational response.
          now-ms    (.getTime ^java.util.Date now)
          sketch    (merge/identity->sketch identity now-ms)
          score-now (score/score-of sketch now-ms scoring)
          tier-now  (tier/project
                     {:score         score-now
                      :host-linked?  (host-linked? store snap identity-eid)
                      :ever-tracked? (boolean (:identity/ever-tracked? identity))}
                     tier-thresholds)]
      {:status  200
       :headers {"Content-Type" "application/json; charset=utf-8"}
       :body    {:ok           true
                 :identity_ref identity-ref
                 :tier         (name tier-now)
                 :new_key_id   (envelope/b64url-encode new-thumb)}})))
