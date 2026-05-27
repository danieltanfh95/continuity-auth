(ns continuity-auth.server.main
  "continuity-auth service entrypoint.

  Boots the integrant system from config.edn at the :prod profile (or
  whichever profile is set via CONTINUITY_AUTH_PROFILE). Registers a JVM shutdown
  hook for graceful stop on SIGTERM.

  CLI flags:
    --selftest    — initialize the system, immediately halt, exit 0.
                    Used by the Docker build to produce an AppCDS
                    archive deterministically."
  (:require
   [clojure.tools.cli :as cli]
   [continuity-auth.server.config :as config]
   [continuity-auth.server.system :as system])
  (:gen-class))

(def ^:private cli-spec
  [["-p" "--profile PROFILE" "aero profile (dev/test/prod)"
    :default :prod :parse-fn keyword]
   ["-s" "--selftest" "init and halt for AppCDS warming"]
   ["-h" "--help"]])

(defn -main [& args]
  (let [{:keys [options summary errors]} (cli/parse-opts args cli-spec)]
    (cond
      errors
      (do (run! println errors) (System/exit 1))

      (:help options)
      (do (println summary) (System/exit 0))

      :else
      (let [profile (or (some-> (System/getenv "CONTINUITY_AUTH_PROFILE") keyword)
                        (:profile options))
            config  (config/load-config profile)
            system  (atom nil)
            stop!   (fn []
                      (when-let [s @system]
                        (system/stop s)
                        (reset! system nil)))]
        (.addShutdownHook (Runtime/getRuntime)
                          (Thread. ^Runnable stop!))
        (try
          (reset! system (system/start config))
          (println "continuity-auth started (profile=" profile ")")
          (if (:selftest options)
            (do (stop!) (System/exit 0))
            (.join (Thread/currentThread)))
          (catch Throwable t
            (println "fatal:" (ex-message t))
            (stop!)
            (System/exit 2)))))))
