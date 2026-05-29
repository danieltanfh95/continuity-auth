(ns continuity-auth.server.http.handlers.issue-token
  "POST /v1/issue-token — mint a short-lived Biscuit capability token.

  Authenticated by the device key (same envelope scheme as /v1/verify),
  this control-plane endpoint hands the CALLER an offline-verifiable token
  asserting the trust signal it has earned: identity, tier, audience, and
  an expiry. The caller then presents the opaque token to a host backend,
  which verifies it OFFLINE with the published root public key (see
  `GET /v1/token-pubkey`) and allows/denies each action without re-calling
  `/v1/verify`. The rate-limit hot path is untouched — this is additive.

  Request body:
    {\"envelope\": <wire-envelope, signed by the DEVICE key, route-bound to
                    POST /v1/issue-token, body-sha256 =
                    sha256(issue-token-intent(audience, ttl_ms))>,
     \"audience\": <host id; [A-Za-z0-9._:-], <=128 chars>,
     \"ttl_ms\":   <optional positive int; clamped to the tier cap>}

  The intent-bound body-sha256 stops a captured envelope from minting a
  token for a DIFFERENT audience. The token carries the caller's CURRENT
  tier (recomputed at read time, like /verify) — no DB write, no schema.

  TTL is purely data-driven: effective = min(requested-or-tier-cap,
  tier-cap, max-ttl-ms). A tier whose cap is 0 (e.g. :banned in the default
  config) yields effective 0 → E_FORBIDDEN, rather than a dead token.

  Response (200):
    {\"ok\": true, \"token\": <base64url Biscuit>, \"tier\": <string>,
     \"audience\": <string>, \"expires_at\": <ISO-8601>,
     \"identity_ref\": <uuid>}

  Errors:
    E_BAD_REQUEST  — missing/malformed envelope, audience, or ttl_ms
    E_UNAUTHORIZED — device-key signature / route binding / nonce failed
    E_FORBIDDEN    — revoked pubkey, or the tier cap is 0
    E_REPLAY       — envelope nonce already used"
  (:require
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.biscuit-token :as bt]
   [continuity-auth.server.crypto.hash :as hash]
   [continuity-auth.server.http.envelope-check :as ec]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.http.util :as util]
   [continuity-auth.server.identity.merge :as merge]
   [continuity-auth.server.identity.score :as score]
   [continuity-auth.server.observability.metrics :as metrics]
   [continuity-auth.server.ratelimit.tier :as tier]
   [continuity-auth.server.storage.protocol :as storage])
  (:import
   (java.time Instant)
   (java.util Date)))

(def ^:private route-path "/v1/issue-token")
(def ^:private audience-re #"^[A-Za-z0-9._:-]{1,128}$")

(defn- host-linked?
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

(defn- parse-request
  "Pull `{:envelope :audience :ttl-ms}` out of the JSON body, validating
  shape. `ttl-ms` is nil when absent (meaning 'use the tier cap')."
  [body-params]
  (let [{:keys [envelope audience ttl_ms]} body-params]
    (when-not envelope
      (errors/fail! :E_BAD_REQUEST "missing envelope"))
    (when-not (and (string? audience) (re-matches audience-re audience))
      (errors/fail! :E_BAD_REQUEST "missing or invalid audience"))
    (when (and (some? ttl_ms)
               (not (and (integer? ttl_ms) (pos? ttl_ms))))
      (errors/fail! :E_BAD_REQUEST "ttl_ms must be a positive integer"))
    (let [env (try (envelope/wire->envelope envelope)
                   (catch Exception _
                     (errors/fail! :E_BAD_REQUEST "malformed envelope")))]
      {:envelope    env
       :audience    audience
       :req-ttl-ms  (when (some? ttl_ms) (long ttl_ms))})))

(defn make-handler
  "Build the issue-token handler.

  deps: {:store, :clock, :tolerance-seconds, :nonce-ttl-seconds,
         :registry — Prometheus registry (or nil),
         :scoring  — spaced-continuity weight constants (or nil for default),
         :tier-thresholds — tier projection thresholds (or nil for default),
         :biscuit-token   — {:keypair <KeyPair>
                             :ttl-ms  {tier -> cap-ms}
                             :max-ttl-ms <long>}}"
  [{:keys [store clock tolerance-seconds nonce-ttl-seconds registry
            scoring tier-thresholds biscuit-token]
    :or {scoring         score/default-scoring
         tier-thresholds tier/default-thresholds}}]
  (when-not biscuit-token
    (throw (ex-info "issue-token/make-handler: missing :biscuit-token" {})))
  (let [{:keys [keypair ttl-ms max-ttl-ms]} biscuit-token
        max-ttl (long (or max-ttl-ms 900000))]
    (fn [request]
      (let [{:keys [envelope audience req-ttl-ms]}
            (parse-request (:body-params request))
            now        (clock)
            snap       (storage/snapshot store)
            intent-sha (hash/sha256
                        (envelope/issue-token-intent-utf8 audience req-ttl-ms))
            record     (ec/verify-existing-envelope!
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
            identity (storage/pull store snap identity-eid
                                   [:identity/id
                                    :identity/score
                                    :identity/ever-tracked?
                                    :identity/created-at
                                    :identity/last-clean-at
                                    :identity/clean-count
                                    :identity/spacing
                                    :identity/violation-count])
            now-ms    (.getTime ^Date now)
            sketch    (merge/identity->sketch identity now-ms)
            score-now (score/score-of sketch now-ms scoring)
            hl?       (host-linked? store snap identity-eid)
            tier-now  (tier/project
                       {:score         score-now
                        :host-linked?  hl?
                        :ever-tracked? (boolean (:identity/ever-tracked? identity))}
                       tier-thresholds)
            tier-cap  (long (get ttl-ms tier-now 0))
            requested (if (some? req-ttl-ms) (long req-ttl-ms) tier-cap)
            effective (max 0 (min requested tier-cap max-ttl))]
        (when (<= effective 0)
          (errors/fail! :E_FORBIDDEN "tier not permitted to mint tokens"))
        (let [id-str  (-> identity :identity/id str)
              expires (.plusMillis ^Instant (.toInstant ^Date now) effective)
              token   (bt/mint keypair {:identity-ref id-str
                                        :tier         tier-now
                                        :audience     audience
                                        :expires-at   expires})]
          (metrics/record-issue-token! registry tier-now)
          {:status  200
           :headers {"Content-Type" "application/json; charset=utf-8"
                     "Cache-Control" "no-store"}
           :body    {:ok           true
                     :token        token
                     :tier         (name tier-now)
                     :audience     audience
                     :expires_at   (util/iso8601 (Date/from expires))
                     :identity_ref id-str}})))))
