(ns continuity-auth.server.config
  "Aero-driven runtime configuration loader."
  (:require
   [aero.core :as aero]
   [clojure.java.io :as io]))

(defn load-config
  "Load the resource config.edn (or an alternate path) with the given
  profile. Default profile is :prod; the test/dev paths pass :test/:dev."
  ([] (load-config :prod))
  ([profile]
   (load-config "config.edn" profile))
  ([resource-path profile]
   (aero/read-config (or (io/resource resource-path)
                         (io/file resource-path))
                     {:profile profile})))
