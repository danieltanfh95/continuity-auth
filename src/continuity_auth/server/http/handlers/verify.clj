(ns continuity-auth.server.http.handlers.verify
  "POST /v1/verify — the main rate-limit decision path.

  Request body: {\"envelope\": <wire-envelope>}
  Response (allow): {\"ok\": true, \"identity_ref\": <uuid>,
                     \"tier\": <string>, \"retry_after_ms\": 0}
  Response (deny):  {\"ok\": false, \"retry_after_ms\": <ms>,
                     \"code\": \"E_RATE\" | \"E_FORBIDDEN\"}"
  (:require
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.http.envelope-check :as ec]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.identity.merge :as merge]
   [continuity-auth.server.identity.score :as score]
   [continuity-auth.server.observability.metrics :as metrics]
   [continuity-auth.server.ratelimit.tier :as tier]
   [continuity-auth.server.ratelimit.window :as window]
   [continuity-auth.server.storage.protocol :as storage]))

(defn- parse-envelope [body-params]
  (let [{:keys [envelope]} body-params]
    (when-not envelope
      (errors/fail! :E_BAD_REQUEST "missing envelope"))
    (try
      (envelope/wire->envelope envelope)
      (catch Exception _
        (errors/fail! :E_BAD_REQUEST "malformed envelope")))))

(defn- host-linked?
  "Does this identity have a committed host-link?"
  [store snap identity-eid]
  (->> (storage/q store snap
                  '[:find [?e ...]
                    :in $ ?i ?st
                    :where
                    [?e :host-link/identity ?i]
                    [?e :host-link/state ?st]]
                  [identity-eid :committed])
       seq
       boolean))

(defn make-handler
  "Build the /verify handler.

  deps: {:store, :clock, :tolerance-seconds, :nonce-ttl-seconds,
         :registry — Prometheus registry (or nil if metrics disabled),
         :windows  — a coll of {:window kw :seconds long}
         :scoring  — score deltas map
         :tier-thresholds — tier projection thresholds (or nil for default)
         :tier-limits     — per-tier limits map (or nil for default)}"
  [{:keys [store clock tolerance-seconds nonce-ttl-seconds registry
            windows scoring tier-thresholds tier-limits]
    :or {scoring         score/default-deltas
         tier-thresholds tier/default-thresholds
         tier-limits     tier/default-limits}}]
  (fn [request]
    (let [start-ms (System/currentTimeMillis)
          env (parse-envelope (:body-params request))
          now (clock)
          ;; Single read snapshot for the decision.
          snap (storage/snapshot store)
          pubkey (ec/verify-existing-envelope!
                  {:store             store
                   :snap              snap
                   :envelope          env
                   :tolerance-seconds tolerance-seconds
                   :nonce-ttl-seconds nonce-ttl-seconds
                   :now               now})
          ip       (:cauth/client-ip request)
          ;; If the client's verified IP from the network is missing,
          ;; reject — IP is an axis we depend on.
          _        (when-not ip
                     (errors/fail! :E_BAD_REQUEST "client ip not available"))
          incoming {:ip ip :fp-digest (:fp-digest env)}
          classification (merge/classify store snap incoming pubkey now)
          identity-eid   (:identity-eid classification)]
      (case (:kind classification)
        :revoked-pubkey
        (errors/fail! :E_FORBIDDEN "pubkey revoked")

        :orphan-pubkey
        (errors/fail! :E_CONFLICT "pubkey integrity error")

        (let [identity (storage/pull store snap identity-eid
                                      [:identity/score
                                       :identity/ever-tracked?])
              score-before (or (:identity/score identity) score/score-neutral)
              hl?          (host-linked? store snap identity-eid)
              tier-now     (tier/project
                            {:score         score-before
                             :host-linked?  hl?
                             :ever-tracked? (boolean (:identity/ever-tracked? identity))}
                            tier-thresholds)
              limits       (tier/limits-for tier-now tier-limits)
              window-decs  (window/check-many store identity-eid windows limits now)]
          (if (:allowed? window-decs)
            (let [tx (merge/classification-tx
                      classification incoming score-before scoring now)]
              ;; SYNC transact for score + request event. Async would let
              ;; two concurrent verifies for the same identity each read
              ;; the same `score-before` and write the same `score-after`,
              ;; flattening penalties to one-per-burst. Latency cost is
              ;; <1 ms in practice; correctness wins.
              (storage/transact! store tx)
              (metrics/record-verify! registry :ok tier-now
                                       (- (System/currentTimeMillis) start-ms))
              {:status  200
               :headers {"Content-Type" "application/json; charset=utf-8"}
               :body    {:ok             true
                         :identity_ref   (-> (storage/pull store snap
                                                            identity-eid
                                                            [:identity/id])
                                              :identity/id str)
                         :tier           (name tier-now)
                         :retry_after_ms 0}})
            (do
              ;; Throttle event log doesn't update score, so async is fine
              ;; here — no read-modify-write race to lose.
              (storage/transact-async!
               store
               [{:request/identity identity-eid
                 :request/ts       now
                 :request/outcome  :throttled}])
              (metrics/record-verify! registry :throttled tier-now
                                       (- (System/currentTimeMillis) start-ms))
              (errors/error-response :E_RATE (:retry-after-ms window-decs)))))))))
