(ns continuity-auth.server.storage.datalevin
  "Datalevin implementation of the Storage protocol.

  Supports two connection modes (transparent at the call site):
    embedded  — file path, e.g. \"/var/data/continuity-auth.dtlv\".
                Single-process; intended for dev/tests.
    server    — dtlv:// URI, e.g.
                \"dtlv://user:pw@host:8898/continuity-auth\".
                Multi-process; intended for production.

  Datalevin is LMDB-backed: writes are serialized on a single writer per
  environment, reads scale via MVCC. We do not configure write batching
  here — async transact via `d/transact-async` is the response-path
  decoupler."
  (:require
   [datalevin.core :as d]
   [continuity-auth.server.storage.protocol :as protocol]
   [continuity-auth.server.storage.schema :as schema])
  (:import
   (java.util.concurrent CompletableFuture ConcurrentHashMap TimeUnit)
   (java.util.function BiConsumer)))

(defn- conn-opts
  "Open options passed to Datalevin. Validation is handled upstream."
  [opts]
  (merge {:validate-data?       true
          :auto-entity-time?    false
          :background-sampling? true}
         (select-keys opts [:kv-opts])))

(defn- to-db
  "Coerce the snapshot value to a Datalevin DB. If it is already a DB,
  return it unchanged; if it is a connection or atom-of-DB, dereference."
  [snap]
  (if (or (map? snap) (record? snap))
    snap
    (d/db snap)))

(def ^:private tuple-pull-attrs
  [:db/id :tuple/id :tuple/identity :tuple/ip-hash
   :tuple/fp-digest :tuple/pubkey
   :tuple/first-seen :tuple/last-seen
   :tuple/observation-count])

(defn- find-tuples-by-attr
  "Query for all tuples whose `attr` equals `value`, then pull the
  standard `tuple-pull-attrs` shape for each. Used by the three
  `find-tuples-by-{ip,fp,pubkey}` protocol methods, which differ
  only in the indexed attribute."
  [db attr value]
  (let [eids (d/q [:find '[?e ...]
                   :in '$ '?v
                   :where ['?e attr '?v]]
                  db value)]
    (mapv #(d/pull db tuple-pull-attrs %) eids)))

(defrecord DatalevinStorage [conn pending]
  protocol/Storage

  (snapshot [_]
    (d/db conn))

  (pull [_ snap eid-or-lookup-ref attrs]
    (let [db (to-db snap)]
      (d/pull db attrs eid-or-lookup-ref)))

  (q [_ snap query inputs]
    (apply d/q query (to-db snap) inputs))

  (find-pubkey-by-thumbprint [_ snap thumbprint]
    (let [db (to-db snap)
          eids (d/q '[:find [?e ...]
                      :in $ ?h
                      :where [?e :pubkey/id ?h]]
                    db thumbprint)]
      (when-let [eid (first eids)]
        (d/pull db
                [:db/id
                 :pubkey/id
                 :pubkey/identity
                 :pubkey/bytes
                 :pubkey/alg
                 :pubkey/created-at
                 :pubkey/revoked-at
                 {:pubkey/rotation-of [:db/id :pubkey/id]}]
                eid))))

  (find-tuples-by-ip [_ snap ip-hash]
    (find-tuples-by-attr (to-db snap) :tuple/ip-hash ip-hash))

  (bootstrap-signals-for-ip [_ snap ip-hash now-ms]
    (let [db (to-db snap)
          ;; Two indexed AVET queries on :tuple/ip-hash — first-seen as Date
          ;; (we take the minimum to get the earliest), and the distinct
          ;; identity set (count its cardinality).
          rows (d/q '[:find ?first-seen ?identity
                      :in $ ?ip
                      :where
                      [?e :tuple/ip-hash ?ip]
                      [?e :tuple/first-seen ?first-seen]
                      [?e :tuple/identity ?identity]]
                    db ip-hash)]
      (if (empty? rows)
        {:ip-age-seconds 0 :identity-count 0}
        (let [earliest-ms (reduce min Long/MAX_VALUE
                                  (map (fn [[^java.util.Date d _]] (.getTime d)) rows))
              age-ms      (max 0 (- (long now-ms) (long earliest-ms)))
              n-identity  (count (into #{} (map second) rows))]
          {:ip-age-seconds (quot age-ms 1000)
           :identity-count (long n-identity)}))))

  (find-tuples-by-fp [_ snap fp-bytes]
    (find-tuples-by-attr (to-db snap) :tuple/fp-digest fp-bytes))

  (find-tuples-by-pubkey [_ snap pubkey-eid]
    (find-tuples-by-attr (to-db snap) :tuple/pubkey pubkey-eid))

  (find-host-link-by-host-user-id [_ snap host-id host-user-id]
    (let [db   (to-db snap)
          eids (d/q '[:find [?e ...]
                      :in $ ?hid ?huid
                      :where
                      [?e :host-link/host-id ?hid]
                      [?e :host-link/host-user-id ?huid]]
                    db host-id host-user-id)]
      (when-let [eid (first eids)]
        (d/pull db
                [:db/id :host-link/id :host-link/host-id
                 :host-link/host-user-id :host-link/identity
                 :host-link/state :host-link/linked-at
                 :host-link/cool-until :host-link/host-sig-verified?] eid))))

  (nonce-seen? [_ snap nonce-hash]
    (let [db (to-db snap)]
      (boolean
       (seq (d/q '[:find [?e ...]
                   :in $ ?h
                   :where [?e :nonce/hash ?h]]
                 db nonce-hash)))))

  (transact! [_ tx-data]
    (d/transact! conn tx-data))

  (transact-async! [_ tx-data]
    ;; `d/transact-async` submits to a process-global async executor. If
    ;; `conn` is closed while a submitted write is still in flight, the
    ;; executor's native LMDB write races env teardown (write-after-free ->
    ;; SIGSEGV/deadlock). Track each future in `pending` so `close` can
    ;; drain in-flight writes before tearing the connection down.
    (let [fut (CompletableFuture.)]
      (.add pending fut)
      (.whenComplete fut (reify BiConsumer
                           (accept [_ _res _err] (.remove pending fut))))
      (try
        (let [dl-result (d/transact-async conn tx-data)]
          (future
            (try
              (.complete fut @dl-result)
              (catch Throwable t
                (.completeExceptionally fut t)))))
        (catch Throwable t
          (.completeExceptionally fut t)))
      fut))

  (sweep-expired! [_ attr expires-attr now]
    (let [db (d/db conn)
          eids (d/q '[:find [?e ...]
                      :in $ ?a ?ea ?now
                      :where
                      [?e ?a _]
                      [?e ?ea ?x]
                      [(<= ?x ?now)]]
                    db attr expires-attr now)
          tx (mapv (fn [eid] [:db/retractEntity eid]) eids)]
      (when (seq tx)
        (d/transact! conn tx))
      (count eids)))

  (close [_]
    ;; Drain in-flight async writes before teardown -- closing the LMDB env
    ;; mid-write is a native write-after-free. Bounded so a wedged executor
    ;; cannot hang close indefinitely.
    (let [in-flight (into-array CompletableFuture pending)]
      (when (pos? (alength in-flight))
        (try
          (.get (CompletableFuture/allOf in-flight) 5 TimeUnit/SECONDS)
          (catch Throwable _ nil))))
    (d/close conn)))

(defn open
  "Open a Datalevin connection. `uri-or-path` may be either an LMDB
  directory path (embedded mode) or a `dtlv://` URI (server mode).
  Returns a DatalevinStorage."
  ([uri-or-path]
   (open uri-or-path {}))
  ([uri-or-path opts]
   (let [conn (d/get-conn uri-or-path schema/schema (conn-opts opts))]
     (->DatalevinStorage conn (ConcurrentHashMap/newKeySet)))))

(defn ensure-schema-version!
  "Read the persisted :schema/version. If absent, write the current
  schema-version and return :installed. If present and equal, return
  :ok. If present and lower, return :pending-upgrade (the caller must
  run migrations). If higher, throw — refusing to run against a future
  schema."
  [storage current-version]
  (let [snap     (protocol/snapshot storage)
        existing (->> (protocol/q storage snap
                                  '[:find [?v ...]
                                    :where [_ :schema/version ?v]]
                                  [])
                      seq
                      sort
                      last)]
    (cond
      (nil? existing)
      (do (protocol/transact! storage [{:schema/version current-version}])
          :installed)

      (= existing current-version)
      :ok

      (< existing current-version)
      :pending-upgrade

      :else
      (throw (ex-info "schema version is newer than this code"
                      {:existing existing :code current-version})))))
