(ns continuity-auth.server.storage.migrations.runner
  "Schema migrations runner.

  Migrations are ordered, idempotent transformations from one schema
  version to the next. Each migration is a function `(fn [storage] ...)`
  that applies its changes and ends by writing the new
  `:schema/version`. The runner reads the persisted version and applies
  migrations in order until it reaches the code's `schema-version`.

  Invocation:
    clojure -M:migrate -- --uri <uri-or-path>

  The runner is a one-shot process. It refuses to start the main app
  unless the persisted version matches the code's version exactly."
  (:require
   [clojure.tools.cli :as cli]
   [continuity-auth.server.storage.datalevin :as dtlv]
   [continuity-auth.server.storage.protocol :as protocol]
   [continuity-auth.server.storage.schema :as schema]))

(def migrations
  "Ordered list of migrations. Each entry is `[from-version to-version
  migration-fn]`. The runner applies each in turn until reaching the
  code's current schema-version."
  [;; -- v0 → v1: initial install --------------------------------------
   [0 1 (fn install-v1 [storage]
          (protocol/transact! storage [{:schema/version 1}]))]

   ;; -- v1 → v2: add :bucket/key for slot uniqueness ------------------
   ;; The new attribute is declared in the schema map; Datalevin's
   ;; schema-on-open picks it up. Existing buckets (if any survived
   ;; from a pre-v2 deploy) are left as-is — they have no `:bucket/key`
   ;; and won't collide with new keyed buckets. The next sweep at the
   ;; window's expiry retracts them.
   [1 2 (fn install-v2 [storage]
          (protocol/transact! storage [{:schema/version 2}]))]])

(defn- migrations-from [from-version target-version]
  (->> migrations
       (drop-while #(< (first %) from-version))
       (take-while #(<= (second %) target-version))))

(defn migrate!
  "Apply pending migrations against `storage` to reach `target-version`.
  Returns one of:
    :ok            — already at target.
    :installed     — initial install applied.
    :upgraded      — at least one migration applied.
    :no-op         — caller passed a target equal to existing.
  Throws if the persisted version is greater than target."
  ([storage] (migrate! storage schema/schema-version))
  ([storage target-version]
   (let [snap     (protocol/snapshot storage)
         existing (->> (protocol/q storage snap
                                   '[:find [?v ...]
                                     :where [_ :schema/version ?v]]
                                   [])
                       seq
                       sort
                       last)
         existing (or existing 0)]
     (cond
       (> existing target-version)
       (throw (ex-info "persisted schema version is newer than code"
                       {:existing existing :target target-version}))

       (= existing target-version)
       :ok

       :else
       (let [pending (migrations-from existing target-version)]
         (doseq [[from to f] pending]
           (println (str "applying migration: v" from " → v" to))
           (f storage))
         (if (zero? existing) :installed :upgraded))))))

(def ^:private cli-spec
  [["-u" "--uri URI" "Datalevin URI or path"
    :default "/tmp/continuity-auth-dev.dtlv"]
   ["-t" "--target VERSION" "Target schema version (default: current code)"
    :default schema/schema-version :parse-fn parse-long]
   ["-h" "--help" "Show this help"]])

(defn -main [& args]
  (let [{:keys [options summary errors]} (cli/parse-opts args cli-spec)]
    (cond
      errors
      (do (run! println errors)
          (System/exit 1))

      (:help options)
      (do (println summary)
          (System/exit 0))

      :else
      (let [{:keys [uri target]} options
            storage              (dtlv/open uri)]
        (try
          (let [result (migrate! storage target)]
            (println (str "schema: " (name result)
                          " (now at v" target ")"))
            (System/exit 0))
          (catch Exception e
            (println (str "migration failed: " (ex-message e)))
            (when-let [data (ex-data e)] (prn data))
            (System/exit 2))
          (finally
            (protocol/close storage)))))))
