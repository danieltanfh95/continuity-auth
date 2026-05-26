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
   (java.util.concurrent CompletableFuture)))

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
  [:db/id :tuple/id :tuple/identity :tuple/ip
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

(defrecord DatalevinStorage [conn]
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

  (find-tuples-by-ip [_ snap ip]
    (find-tuples-by-attr (to-db snap) :tuple/ip ip))

  (find-tuples-by-fp [_ snap fp-bytes]
    (find-tuples-by-attr (to-db snap) :tuple/fp-digest fp-bytes))

  (find-tuples-by-pubkey [_ snap pubkey-eid]
    (find-tuples-by-attr (to-db snap) :tuple/pubkey pubkey-eid))

  (find-buckets [_ snap identity-eid window]
    (let [db   (to-db snap)
          eids (d/q '[:find [?e ...]
                      :in $ ?ident ?w
                      :where
                      [?e :bucket/identity ?ident]
                      [?e :bucket/window ?w]]
                    db identity-eid window)]
      (->> eids
           (mapv #(d/pull db
                          [:db/id :bucket/identity :bucket/window
                           :bucket/start :bucket/count] %))
           (sort-by :bucket/start)
           reverse
           vec)))

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
    ;; Datalevin's `transact-async` returns a value compatible with deref;
    ;; we wrap to a CompletableFuture for uniform use with java.util.concurrent.
    (let [fut (CompletableFuture.)]
      (try
        (let [pending (d/transact-async conn tx-data)]
          (future
            (try
              (.complete fut @pending)
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
    (d/close conn)))

(defn open
  "Open a Datalevin connection. `uri-or-path` may be either an LMDB
  directory path (embedded mode) or a `dtlv://` URI (server mode).
  Returns a DatalevinStorage."
  ([uri-or-path]
   (open uri-or-path {}))
  ([uri-or-path opts]
   (let [conn (d/get-conn uri-or-path schema/schema (conn-opts opts))]
     (->DatalevinStorage conn))))

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
