(ns build
  "tools.build entry points for continuity-auth.

  Targets:
    clojure -T:build uber       — build deployable uberjar
    clojure -T:build clean      — wipe target/
    clojure -T:build version    — print version"
  (:require
   [clojure.tools.build.api :as b]))

(def lib    'org.continuity-auth/server)
(def version (or (System/getenv "CAUTH_VERSION") "0.1.0"))
(def class-dir "target/classes")
(def jar-file  "target/continuity-auth.jar")
(def basis     (delay (b/create-basis {:project "deps.edn"})))

(defn clean [_]
  (b/delete {:path "target"}))

(defn version [_]
  (println version))

(defn uber [_]
  (clean nil)
  (b/copy-dir {:src-dirs   ["src" "resources"]
               :target-dir class-dir})
  (b/compile-clj {:basis        @basis
                  :src-dirs     ["src"]
                  :class-dir    class-dir
                  :ns-compile   '[continuity-auth.server.main]})
  (b/uber {:class-dir class-dir
           :uber-file jar-file
           :basis     @basis
           :main      'continuity-auth.server.main
           :exclude   ["META-INF/.*\\.SF"
                       "META-INF/.*\\.DSA"
                       "META-INF/.*\\.RSA"]})
  (println "built" jar-file))
