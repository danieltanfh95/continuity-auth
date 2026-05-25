(ns continuity-auth.server.observability.metrics
  "Prometheus metrics registry and exposition.

  Single registry per system. Counters, gauges, and histograms covering
  the surfaces called out in the plan §J:
    - verify outcomes by tier
    - verify latency histogram
    - signature verify failures
    - nonce replay attempts
    - identity counts by tier (gauge)
    - cluster merge outcomes
    - datalevin write latency"
  (:require
   [iapetos.core :as prom]
   [iapetos.export :as export]))

(defn make-registry
  "Build a fresh Prometheus registry with all continuity-auth metrics
  pre-registered. Returns the registry."
  []
  (-> (prom/collector-registry)
      (prom/register
       (prom/counter   :cauth/verify-total
                       {:description "Total verify requests by outcome and tier"
                        :labels      [:outcome :tier]})
       (prom/counter   :cauth/bootstrap-total
                       {:description "Total bootstrap requests by outcome"
                        :labels      [:outcome]})
       (prom/counter   :cauth/signature-verify-failures-total
                       {:description "Signature verification failures by alg"
                        :labels      [:alg]})
       (prom/counter   :cauth/nonce-replay-attempts-total
                       {:description "Nonce replay attempts detected"})
       (prom/counter   :cauth/cluster-merge-total
                       {:description "Cluster classification outcomes"
                        :labels      [:kind]})
       (prom/gauge     :cauth/identity-total
                       {:description "Current identity count by tier"
                        :labels      [:tier]})
       (prom/histogram :cauth/verify-latency-seconds
                       {:description "End-to-end /verify latency, seconds"
                        :buckets     [0.001 0.005 0.01 0.025 0.05 0.1 0.25 0.5 1.0 5.0]})
       (prom/histogram :cauth/datalevin-write-latency-seconds
                       {:description "Datalevin synchronous transact latency, seconds"
                        :buckets     [0.0005 0.001 0.005 0.01 0.05 0.1 0.5 1.0]}))))

(defn record-verify!
  "Record a /verify outcome to metrics. `outcome` ∈ #{:ok :throttled
  :forbidden :unauthorized :rate-limited :replay :bad-request :internal}."
  [registry outcome tier latency-ms]
  (when registry
    (prom/inc  registry :cauth/verify-total {:outcome (name outcome)
                                            :tier    (name (or tier :anonymous))})
    (prom/observe registry :cauth/verify-latency-seconds
                  (/ (double latency-ms) 1000.0))))

(defn record-bootstrap!
  [registry outcome]
  (when registry
    (prom/inc registry :cauth/bootstrap-total {:outcome (name outcome)})))

(defn record-signature-failure!
  [registry alg]
  (when registry
    (prom/inc registry :cauth/signature-verify-failures-total
              {:alg (name (or alg :unknown))})))

(defn record-replay!
  [registry]
  (when registry
    (prom/inc registry :cauth/nonce-replay-attempts-total)))

(defn record-cluster-merge!
  [registry kind]
  (when registry
    (prom/inc registry :cauth/cluster-merge-total {:kind (name kind)})))

(defn set-identity-total!
  [registry tier n]
  (when registry
    (prom/set registry :cauth/identity-total {:tier (name tier)} n)))

;; -- /metrics handler ------------------------------------------------------

(defn make-handler
  "Return a Ring handler that exposes the registry in Prometheus text
  format. If `:bearer` is provided in deps, requests must carry the
  matching `Authorization: Bearer <token>` header (intentionally cheap;
  /metrics scraper provides the token)."
  [{:keys [registry bearer]}]
  (fn [request]
    (cond
      (nil? registry)
      {:status 503 :body "metrics not initialized"}

      (and (not (or (nil? bearer) (= "" bearer)))
           (not= (str "Bearer " bearer)
                 (get-in request [:headers "authorization"])))
      {:status 401 :body "unauthorized"}

      :else
      {:status 200
       :headers {"Content-Type" "text/plain; version=0.0.4"}
       :body    (export/text-format registry)})))
