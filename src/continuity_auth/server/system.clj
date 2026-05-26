(ns continuity-auth.server.system
  "Integrant system map for continuity-auth.

  Components (init order):
    :cauth/storage           — Datalevin connection, schema-version-checked
    :cauth/nonce-sweeper     — background daemon thread reclaiming expired nonces
    :cauth/clock             — injected clock function (Date now)
    :cauth/admin-keystore    — loaded admin HMAC keystore (or nil)
    :cauth/http-handler      — Ring handler with full middleware stack
    :cauth/http-server       — Jetty server listening on configured port

  Halt is reverse-order: server → handler → sweeper → storage."
  (:require
   [continuity-auth.server.admin.hmac :as admin-hmac]
   [continuity-auth.server.http.middleware :as mw]
   [continuity-auth.server.http.router :as router]
   [continuity-auth.server.observability.logging :as logging]
   [continuity-auth.server.observability.metrics :as metrics]
   [continuity-auth.server.replay.nonce :as nonce]
   [continuity-auth.server.storage.datalevin :as dtlv]
   [continuity-auth.server.storage.migrations.runner :as migrations]
   [continuity-auth.server.storage.protocol :as storage]
   [integrant.core :as ig]
   [ring.adapter.jetty :as jetty]))

(defn system-map
  "Build the integrant system map from `config`. Config keys are pulled
  from `:server`, `:datalevin`, `:replay`, etc. of the aero-loaded
  config.edn."
  [{:keys [server datalevin replay ratelimit scoring trusted-proxies
            limits observability grace hmac]
    :as config}]
  {:cauth/storage
   {:uri (:uri datalevin)}

   :cauth/migrate
   {:storage (ig/ref :cauth/storage)}

   :cauth/clock
   {}

   :cauth/metrics
   {:enabled?        (boolean (:metrics-enabled? observability))
    :bearer          (:prometheus-bearer observability)}

   :cauth/logging
   {}

   :cauth/nonce-sweeper
   {:storage  (ig/ref :cauth/storage)
    :interval (:sweeper-interval-seconds replay)}

   :cauth/admin-keystore
   {:path (:admin-keys-path hmac)}

   :cauth/http-handler
   {:storage         (ig/ref :cauth/storage)
    :migrate         (ig/ref :cauth/migrate)
    :clock           (ig/ref :cauth/clock)
    :metrics         (ig/ref :cauth/metrics)
    :admin-keystore  (ig/ref :cauth/admin-keystore)
    :config          config
    :replay          replay
    :rate-windows    (:windows ratelimit)
    :tier-limits     (:tiers ratelimit)
    :scoring         scoring
    :proxy           trusted-proxies
    :limits          limits
    :grace           grace}

   :cauth/http-server
   {:handler  (ig/ref :cauth/http-handler)
    :host     (:host server)
    :port     (:port server)
    :join?    (:join? server)
    :max-threads (:max-threads server)}})

;; -- init methods ---------------------------------------------------------

(defmethod ig/init-key :cauth/storage [_ {:keys [uri]}]
  (dtlv/open uri))

(defmethod ig/halt-key! :cauth/storage [_ store]
  (storage/close store))

(defmethod ig/init-key :cauth/migrate [_ {:keys [storage]}]
  (let [outcome (migrations/migrate! storage)]
    {:outcome outcome}))

(defmethod ig/init-key :cauth/clock [_ _]
  ;; Wrap so tests can swap by passing an alternate fn-of-no-args.
  (fn clock-now [] (java.util.Date.)))

(defmethod ig/init-key :cauth/metrics [_ {:keys [enabled? bearer]}]
  (when enabled?
    (when (or (nil? bearer) (= "" bearer))
      ;; Codex M1: /metrics defaults to 401 when bearer is blank. We
      ;; refuse to ship an open metrics endpoint silently — operators
      ;; either set CAUTH_PROM_BEARER or accept that /metrics is closed.
      (binding [*out* *err*]
        (println "WARN [:cauth/metrics] metrics enabled but CAUTH_PROM_BEARER is blank;")
        (println "     /metrics will return 401 to every request until a bearer is set.")))
    {:registry (metrics/make-registry)
     :bearer   bearer}))

(defmethod ig/init-key :cauth/logging [_ cfg]
  (logging/start-publishers! cfg))

(defmethod ig/halt-key! :cauth/logging [_ stop-fn]
  (when stop-fn (stop-fn)))

(defmethod ig/init-key :cauth/nonce-sweeper [_ {:keys [storage interval]}]
  (nonce/start-sweeper! storage interval))

(defmethod ig/halt-key! :cauth/nonce-sweeper [_ stop-fn]
  (when stop-fn (stop-fn)))

(defmethod ig/init-key :cauth/admin-keystore [_ {:keys [path]}]
  ;; Returns the loaded keystore map (key-id -> ^bytes secret) or nil
  ;; if no path is configured. The handlers refuse all admin calls when
  ;; the keystore is nil/empty, so leaving this unset is the "admin
  ;; disabled" deployment.
  (admin-hmac/load-keystore path))

(defn- normalize-rate-windows
  "Validate the configured rate-limit windows.

  Each window must have BOTH a `:window` keyword (used as the lookup key
  in the per-tier limits map) and a `:seconds` long (the bucket size).
  Throws ex-info with `:cauth/error :config/invalid` if any are missing —
  fail-fast at startup, since the verify path would otherwise default
  every limit to 0 and throttle every request."
  [rate-windows]
  (doseq [w rate-windows]
    (when-not (keyword? (:window w))
      (throw (ex-info "rate-limit window missing :window keyword"
                      {:cauth/error :config/invalid :window w})))
    (when-not (pos-int? (:seconds w))
      (throw (ex-info "rate-limit window missing :seconds (positive int)"
                      {:cauth/error :config/invalid :window w}))))
  (mapv #(select-keys % [:window :seconds]) rate-windows))

(defmethod ig/init-key :cauth/http-handler
  [_ {:keys [storage clock metrics replay rate-windows tier-limits
              scoring proxy limits grace admin-keystore config]}]
  (router/make-handler
   {:store               storage
    :clock               clock
    :tolerance-seconds   (:timestamp-tolerance-seconds replay)
    :nonce-ttl-seconds   (:nonce-ttl-seconds replay)
    :grace-seconds       (:key-rotation-overlap-seconds grace)
    :windows             (normalize-rate-windows rate-windows)
    :scoring             scoring
    :tier-limits         tier-limits
    :registry            (:registry metrics)
    :bearer              (:bearer metrics)
    :keystore            admin-keystore
    :config              config}
   {:trusted-cidrs  (mw/parse-trusted-cidrs (:cidrs proxy))
    :ip-header      (:ip-header proxy)
    :max-body-bytes (:max-body-bytes limits)}))

(defmethod ig/init-key :cauth/http-server
  [_ {:keys [handler host port join? max-threads]}]
  (jetty/run-jetty handler
                   {:host        host
                    :port        port
                    :join?       (boolean join?)
                    :max-threads (or max-threads 64)}))

(defmethod ig/halt-key! :cauth/http-server [_ server]
  (when server (.stop server)))

;; -- start / stop --------------------------------------------------------

(defn start
  "Build the system map from `config` and initialize it."
  [config]
  (ig/init (system-map config)))

(defn stop
  "Halt the system in reverse-init order."
  [system]
  (when system (ig/halt! system)))
