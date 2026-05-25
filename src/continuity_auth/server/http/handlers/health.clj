(ns continuity-auth.server.http.handlers.health
  "Liveness and readiness endpoints.

  /healthz — liveness: process is up. Always 200 once Jetty is accepting.
  /readyz  — readiness: DB reachable. 200 when storage snapshot works,
             503 if storage is unreachable.
  /metrics — Prometheus text exposition (wired by observability layer)."
  (:require
   [continuity-auth.server.storage.protocol :as storage]))

(defn make-healthz [_deps]
  (fn [_request]
    {:status 200
     :headers {"Content-Type" "application/json; charset=utf-8"
               "Cache-Control" "no-store"}
     :body {:ok true}}))

(defn make-readyz [{:keys [store]}]
  (fn [_request]
    (try
      (storage/snapshot store)
      {:status 200
       :headers {"Content-Type" "application/json; charset=utf-8"
                 "Cache-Control" "no-store"}
       :body {:ready true :db_status "ok"}}
      (catch Throwable _
        {:status 503
         :headers {"Content-Type" "application/json; charset=utf-8"
                   "Cache-Control" "no-store"}
         :body {:ready false :db_status "unreachable"}}))))
