(ns continuity-auth.client.dispatch
  "Top-level CLI dispatcher for the `continuity` binary. Routes one of:

      continuity auth  SUBCOMMAND [ARGS…]   → continuity-auth.client.cli
      continuity admin SUBCOMMAND [ARGS…]   → continuity-auth.admin.cli
      continuity --version | --help

  Designed to load under both babashka (the install-ergonomic surface,
  via `bin/continuity`) and the JVM (via `clojure -M:continuity ...` for
  development). Avoid any JVM-only require here."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [continuity-auth.client.cli :as client-cli]))

(defn- read-config-version []
  (try
    (let [r (io/resource "config.edn")]
      (when r
        (-> r slurp edn/read-string :continuity-auth/version)))
    (catch Exception _ nil)))

(def ^:private fallback-version "0.1.0")

(defn- version-string []
  (or (read-config-version) fallback-version))

(def ^:private help-text
  (str
   "continuity — cryptographic device-continuity client for continuity-auth\n"
   "\n"
   "Usage:\n"
   "  continuity auth  <subcommand> [ARGS…]   client-side identity + signing\n"
   "  continuity admin <subcommand> [ARGS…]   operator surface (HMAC-authed)\n"
   "  continuity --version                    print version\n"
   "  continuity --help                       this help\n"
   "\n"
   "auth subcommands:\n"
   "  init                                   generate key + bootstrap identity\n"
   "  sign METHOD URL [BODY]                 emit signed envelope to stdout\n"
   "  curl ARGS… URL                         wrap curl, attach envelope header\n"
   "  wget ARGS… URL                         wrap wget, attach envelope header\n"
   "  show                                   print stored identity_ref + key info\n"
   "\n"
   "admin subcommands:\n"
   "  revoke-key <key-id-b64>                force-revoke a pubkey\n"
   "  config                                 dump effective server config\n"
   "\n"
   "Env vars (auth):\n"
   "  CAUTH_ENDPOINT  default http://localhost:8080\n"
   "  CAUTH_HOME      default $XDG_CONFIG_HOME/continuity-auth\n"
   "  CAUTH_HOST_ID   optional host_user_id field\n"
   "\n"
   "Env vars (admin):\n"
   "  CAUTH_ENDPOINT, CAUTH_ADMIN_KEY_ID, CAUTH_ADMIN_SECRET_FILE\n"
   "  (or pass --server / --key-id / --secret-file)\n"))

(defn- subcommand-kw [s]
  (when s (keyword (str/replace s "_" "-"))))

;; The admin namespace is JVM-style today (uses `jsonista` indirectly via
;; the server.admin.hmac path it requires); a parallel bb-compatible
;; surface is provided by `continuity-auth.admin.cli`. Lazy-require to
;; defer loading until/unless admin is actually invoked.
(defn- run-admin [parsed]
  (try
    (require 'continuity-auth.admin.cli)
    (let [run (resolve 'continuity-auth.admin.cli/run-admin)]
      (if run
        (run parsed)
        (do (binding [*out* *err*]
              (println "admin namespace did not expose `run-admin` — internal error"))
            2)))
    (catch Throwable t
      (binding [*out* *err*]
        (println (str "Failed to load admin subsystem: " (.getMessage t))))
      2)))

(defn- parse-auth [args]
  (let [[sub & rest] args]
    {:subcommand (subcommand-kw sub)
     :args       (vec rest)
     :opts       {}}))

(defn- parse-admin [args]
  (let [[sub & rest] args]
    {:subcommand (subcommand-kw sub)
     :args       (vec rest)
     :opts       {}}))

;; --- plugin discovery ----------------------------------------------------
;;
;; Mirrors git's external-subcommand convention: `continuity foo bar` looks
;; for an executable named `continuity-foo` on PATH and runs it with the
;; remaining args. Built-in groups (`auth`, `admin`) take priority. Plugin
;; names must match `[a-zA-Z0-9][a-zA-Z0-9_-]*` to prevent traversal via
;; e.g. `continuity ../bad`.

(def ^:private plugin-name-re #"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")

(defn- plugin-on-path
  "Search PATH for an executable named `continuity-<plugin>`. Returns the
  absolute path string, or nil."
  [plugin]
  (when (re-matches plugin-name-re (or plugin ""))
    (let [path     (or (System/getenv "PATH") "")
          sep      (System/getProperty "path.separator")
          bin-name (str "continuity-" plugin)]
      (some (fn [dir]
              (let [f (io/file dir bin-name)]
                (when (and (.isFile f) (.canExecute f))
                  (.getAbsolutePath f))))
            (remove str/blank? (str/split path (re-pattern (java.util.regex.Pattern/quote sep))))))))

(defn- run-plugin
  "Spawn the external plugin with the given args, inheriting stdio.
  Returns the plugin's exit code."
  [^String plugin-path args]
  (let [pb (doto (ProcessBuilder. ^java.util.List (vec (cons plugin-path args)))
             (.inheritIO))]
    (.waitFor (.start pb))))

(defn main
  "Entry point. Returns an integer exit code; does NOT call System/exit
  itself (callers — bin/continuity, tests — make that decision)."
  [& argv]
  (let [args (vec argv)
        a0   (first args)]
    (cond
      (or (= "--help" a0) (= "-h" a0) (nil? a0))
      (do (println help-text) 0)

      (or (= "--version" a0) (= "-V" a0))
      (do (println (str "continuity " (version-string))) 0)

      (= "auth" a0)
      (client-cli/run-auth (parse-auth (rest args)))

      (= "admin" a0)
      (run-admin (parse-admin (rest args)))

      :else
      (if-let [plugin (plugin-on-path a0)]
        (run-plugin plugin (rest args))
        (do (binding [*out* *err*]
              (println (str "unknown group: " a0))
              (println "")
              (println help-text))
            2)))))
