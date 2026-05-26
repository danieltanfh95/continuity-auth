(ns continuity-auth.server.http.router
  "Top-level Reitit router. Mounts all v1 endpoints under /v1 and the
  ops endpoints (/healthz, /readyz, /metrics) at the root."
  (:require
   [continuity-auth.server.http.handlers.admin :as admin]
   [continuity-auth.server.http.handlers.bootstrap :as bootstrap]
   [continuity-auth.server.http.handlers.health :as health]
   [continuity-auth.server.http.handlers.revoke-key :as revoke-key]
   [continuity-auth.server.http.handlers.rotate-key :as rotate-key]
   [continuity-auth.server.http.handlers.verify :as verify]
   [continuity-auth.server.http.middleware :as mw]
   [continuity-auth.server.observability.metrics :as metrics]
   [reitit.ring :as ring]))

(defn make-routes
  "Build the route table given handler-deps. Handlers are constructed
  here so that each receives the appropriate slice of deps."
  [deps]
  [["/healthz"           {:get  {:handler (health/make-healthz deps)}}]
   ["/readyz"            {:get  {:handler (health/make-readyz   deps)}}]
   ["/metrics"           {:get  {:handler (metrics/make-handler
                                            (select-keys deps [:registry :bearer]))}}]

   ["/v1"
    ["/bootstrap"        {:post {:handler (bootstrap/make-handler deps)}}]
    ["/verify"           {:post {:handler (verify/make-handler    deps)}}]
    ["/rotate-key"       {:post {:handler (rotate-key/make-handler deps)}}]
    ["/revoke-key"       {:post {:handler (revoke-key/make-handler deps)}}]
    ["/admin"
     ["/revoke-key"      {:post {:handler (admin/make-revoke-key-handler deps)}}]
     ["/config"          {:get  {:handler (admin/make-config-handler deps)}}]]]])

(defn make-handler
  "Construct the full Ring handler stack:
       request-id
         → error
           → body-size-limit
             → JSON in/out
               → trusted-proxy IP
                 → bootstrap per-IP rate limit
                   → router

  `deps` is the merged map of system dependencies. `proxy-cfg` controls
  the trusted-proxy IP extraction (parsed via mw/parse-trusted-cidrs).
  `:max-body-bytes` is the hard upper bound on a request body in bytes
  (default 65 536, matching `config.edn :limits/:max-body-bytes`).

  The bootstrap rate-limit middleware sits INSIDE wrap-trusted-proxy-ip
  so it can read `:cauth/client-ip`. Tier 2 IP-anchored signals + Tier 3
  datacenter-CIDR multiplier are composed here from the merged config —
  see `mw/make-suspicion-fn`."
  [deps {:keys [trusted-cidrs ip-header max-body-bytes bootstrap-rl ip-hmac-key]
         :or {trusted-cidrs   []
              ip-header       "x-forwarded-for"
              max-body-bytes  65536
              bootstrap-rl    {}}}]
  (when-not ip-hmac-key
    (throw (ex-info "router/make-handler: missing :ip-hmac-key" {})))
  (let [{:keys [signals-enabled? signal-read-timeout-ms signal-cache-ttl-ms
                datacenter-cidrs]} bootstrap-rl
        dc-ranges    (mw/parse-trusted-cidrs (or datacenter-cidrs ""))
        suspicion-fn (mw/make-suspicion-fn
                      {:storage          (:store deps)
                       :signals-enabled? (if (some? signals-enabled?)
                                           signals-enabled?
                                           (some? (:store deps)))
                       :cache-ttl-ms     (or signal-cache-ttl-ms 300000)
                       :read-timeout-ms  (or signal-read-timeout-ms 50)
                       :datacenter-cidrs dc-ranges
                       :on-fallback      (fn [_kind _ex] nil)})
        staircase-opts (-> bootstrap-rl
                           (dissoc :signals-enabled?
                                   :signal-read-timeout-ms
                                   :signal-cache-ttl-ms
                                   :datacenter-cidrs)
                           (assoc :suspicion-fn suspicion-fn))]
    (-> (ring/ring-handler
         (ring/router (make-routes deps))
         (ring/create-default-handler
          {:not-found
           (fn [_] {:status 404
                    :headers {"Content-Type" "application/json; charset=utf-8"}
                    :body "{\"ok\":false,\"code\":\"E_NOT_FOUND\",\"retry_after_ms\":0}"})}))
        (mw/wrap-bootstrap-rate-limit staircase-opts)
        (mw/wrap-trusted-proxy-ip {:trusted-cidrs trusted-cidrs
                                    :ip-header     ip-header
                                    :ip-hmac-key   ip-hmac-key})
        mw/wrap-json-response
        mw/wrap-json-body
        (mw/wrap-body-size-limit max-body-bytes)
        mw/wrap-error
        mw/wrap-request-id)))
