(ns continuity-auth.server.identity.merge
  "Identity cluster membership logic — the core of the trust model.

  Two entry points:

    `bootstrap-tx`   — given a verified bootstrap envelope (new pubkey,
                       not yet in the DB), produces the tx-data to
                       create a fresh identity + pubkey + tuple. Always
                       creates a new identity in v1 (see ontology §7,
                       plan §E).

    `classify`       — given a verified /verify envelope (pubkey is
                       already in the DB), classifies the cluster
                       membership outcome for the incoming tuple and
                       produces tx-data.

  Both functions are pure with respect to the storage snapshot they
  receive: they perform reads and compute, but do not transact. The
  caller passes the resulting tx-data to `transact!` or
  `transact-async!`. Separating reads from writes is what enables the
  TOCTOU-safe pattern of §I9 (single read snapshot, write after
  response).

  All cross-axis advisory observations (matches against tuples in
  DIFFERENT identities) are recorded in `:request/match-axes` as
  `:ip-cross-cluster` or `:fp-cross-cluster`. They do not affect
  scores."
  (:require
   [continuity-auth.server.identity.score :as score]
   [continuity-auth.server.storage.protocol :as storage]))

(defn- ->date
  ^java.util.Date [x]
  (cond
    (instance? java.util.Date x) x
    (number? x)                  (java.util.Date. (long x))
    :else                        (java.util.Date.)))

(defn identity->sketch
  "Extract the spaced-continuity sketch (epoch-ms fields, the shape
  `score/score-of` consumes) from a pulled identity map. Missing fields
  (a pre-v5 identity, or one only just bootstrapped) default to a
  fresh-key sketch anchored at `now-ms`: clean-count 0 → score floor →
  :anonymous, so an unmigrated identity simply re-earns trust from the
  safe default."
  [identity ^long now-ms]
  {:clean-count      (long (or (:identity/clean-count identity) 0))
   :spacing          (double (or (:identity/spacing identity) 0.0))
   :violation-count  (long (or (:identity/violation-count identity) 0))
   :created-at-ms    (if-let [^java.util.Date d (:identity/created-at identity)]
                       (.getTime d) now-ms)
   :last-clean-at-ms (if-let [^java.util.Date d (:identity/last-clean-at identity)]
                       (.getTime d) now-ms)})

;; -- bootstrap path --------------------------------------------------------

(defn bootstrap-tx
  "Produce tx-data for a bootstrap request.

  Inputs:
    incoming      — {:ip <string>, :fp-digest <bytes>}
    pubkey        — {:bytes <canonical-bytes>
                     :alg   :ed25519 | :p256
                     :id    <thumbprint-bytes>}
    now           — java.util.Date
    scoring       — spaced-continuity weight constants (`score/default-scoring`)

  Returns a vector of tx maps that:
    - creates a new identity (tempid -1) with a fresh trust sketch
      (clean-count 1, spacing 0.0, violation-count 0, created-at =
      last-clean-at = now)
    - creates the new pubkey (tempid -2) bound to that identity
    - creates the first tuple (tempid -3)
    - emits a :bootstrap trust event
    - emits a :request event with outcome :ok

  The fresh sketch derives to the score floor (≈ :anonymous), so a
  brand-new key — including a farmed sybil — starts unproven and must
  earn trust through spaced clean recurrence. `:identity/score` is a
  write-time cache; the verify path recomputes from the sketch."
  [incoming pubkey now scoring]
  (let [iid    (random-uuid)
        tid    (random-uuid)
        d      (->date now)
        now-ms (.getTime d)
        sketch {:clean-count 1 :spacing 0.0 :violation-count 0
                :created-at-ms now-ms :last-clean-at-ms now-ms}
        score0 (score/score-of sketch now-ms scoring)]
    [{:db/id                    -1
      :identity/id              iid
      :identity/created-at      d
      :identity/last-event-at   d
      :identity/last-clean-at   d
      :identity/clean-count     1
      :identity/spacing         0.0
      :identity/violation-count 0
      :identity/score           score0
      :identity/ever-tracked?   false}
     {:db/id                   -2
      :pubkey/id               (:id pubkey)
      :pubkey/identity         -1
      :pubkey/bytes            (:bytes pubkey)
      :pubkey/alg              (:alg pubkey)
      :pubkey/created-at       d}
     {:db/id                    -3
      :tuple/id                 tid
      :tuple/identity           -1
      :tuple/ip-hash            (:ip incoming)
      :tuple/fp-digest          (:fp-digest incoming)
      :tuple/pubkey             -2
      :tuple/first-seen         d
      :tuple/last-seen          d
      :tuple/observation-count  1}
     {:trust-event/identity     -1
      :trust-event/ts           d
      :trust-event/delta        0.0
      :trust-event/reason       :bootstrap
      :trust-event/score-after  score0}
     {:request/identity         -1
      :request/ts               d
      :request/outcome          :ok
      :request/tuple            -3
      :request/match-axes       #{:bootstrap}}]))

;; -- verify path -----------------------------------------------------------

(defn- find-cluster-tuples
  "All tuples attached to `identity-eid`."
  [store snap identity-eid]
  (storage/q store snap
             '[:find [(pull ?t [:db/id :tuple/id :tuple/ip-hash
                                 :tuple/fp-digest :tuple/pubkey
                                 :tuple/first-seen :tuple/last-seen
                                 :tuple/observation-count]) ...]
               :in $ ?ident
               :where [?t :tuple/identity ?ident]]
             [identity-eid]))

(defn- find-cross-cluster-ip-tuples
  "Tuples whose :tuple/ip-hash = ip-hash and whose :tuple/identity !=
  identity-eid. `ip-hash` is the opaque HMAC token (see
  `continuity-auth.server.crypto.ip-hmac`)."
  [store snap ip-hash identity-eid]
  (storage/q store snap
             '[:find [?t ...]
               :in $ ?ip ?ident
               :where
               [?t :tuple/ip-hash ?ip]
               [?t :tuple/identity ?other]
               [(not= ?other ?ident)]]
             [ip-hash identity-eid]))

(defn- find-cross-cluster-fp-tuples
  [store snap fp-digest identity-eid]
  (storage/q store snap
             '[:find [?t ...]
               :in $ ?fp ?ident
               :where
               [?t :tuple/fp-digest ?fp]
               [?t :tuple/identity ?other]
               [(not= ?other ?ident)]]
             [fp-digest identity-eid]))

(defn- exact-tuple-match
  "Find a tuple in `cluster-tuples` with the same (ip, fp-digest, pubkey)
  as `incoming` + `pubkey-eid`. Returns the tuple or nil."
  [incoming pubkey-eid cluster-tuples]
  (let [ip  (:ip incoming)
        fp  ^bytes (:fp-digest incoming)]
    (some (fn [t]
            (when (and (= ip (:tuple/ip-hash t))
                       (= pubkey-eid (or (:db/id (:tuple/pubkey t))
                                         (:tuple/pubkey t)))
                       (java.security.MessageDigest/isEqual
                        fp ^bytes (:tuple/fp-digest t)))
              t))
          cluster-tuples)))

(defn- revoked-at?
  "True iff `record` has a `:pubkey/revoked-at` that is at or before `now`.
  A future-dated `:pubkey/revoked-at` is the in-grace state (see
  ontology §4 and `envelope-check/resolve-existing-pubkey!`)."
  [record ^java.util.Date now]
  (let [^java.util.Date r (:pubkey/revoked-at record)]
    (and r (not (.before now r)))))

(defn classify
  "Classify the cluster outcome for a verified /verify request.

  Inputs:
    store, snap     — Storage + snapshot
    incoming        — {:ip <string>, :fp-digest <bytes>}
    pubkey-record   — the result of storage/find-pubkey-by-thumbprint:
                      {:db/id ..., :pubkey/identity {:db/id ...}, ...}
    now             — java.util.Date used to evaluate revocation grace

  Returns a map:
    {:kind       :exact-observation | :new-tuple | :revoked-pubkey
                  | :orphan-pubkey
     :identity-eid <eid or nil>
     :existing-tuple <map or nil>
     :mismatch-axes #{:ip :fp} | #{}
     :cross-cluster {:ip <bool> :fp <bool>}}

  `:revoked-pubkey` — pubkey is revoked AS OF `now`; caller must reject.
                     A future-dated revoked-at (rotation grace) is NOT
                     revoked yet.
  `:orphan-pubkey`  — pubkey has no identity attached (an integrity
                      error; caller must reject and alert).
  `:exact-observation` — incoming tuple matches an existing tuple in
                      the cluster; reinforce.
  `:new-tuple`      — incoming tuple is new in the cluster; mismatch-axes
                      lists which axes differ from the closest existing
                      tuple in the cluster.

  The :cross-cluster map records advisory matches against tuples in
  OTHER identities (not used for scoring; only logged)."
  [store snap incoming pubkey-record now]
  (cond
    (revoked-at? pubkey-record (->date now))
    {:kind :revoked-pubkey}

    (nil? (:pubkey/identity pubkey-record))
    {:kind :orphan-pubkey}

    :else
    (let [identity-eid    (or (:db/id (:pubkey/identity pubkey-record))
                              (:pubkey/identity pubkey-record))
          pubkey-eid      (:db/id pubkey-record)
          cluster-tuples  (find-cluster-tuples store snap identity-eid)
          exact           (exact-tuple-match incoming pubkey-eid cluster-tuples)
          cross-ip?       (boolean (seq (find-cross-cluster-ip-tuples
                                          store snap (:ip incoming) identity-eid)))
          cross-fp?       (boolean (seq (find-cross-cluster-fp-tuples
                                          store snap (:fp-digest incoming) identity-eid)))]
      (if exact
        {:kind            :exact-observation
         :identity-eid    identity-eid
         :existing-tuple  exact
         :mismatch-axes   #{}
         :cross-cluster   {:ip cross-ip? :fp cross-fp?}}
        (let [{:keys [mismatch-axes]} (score/axes-vs-cluster
                                       incoming cluster-tuples)]
          {:kind            :new-tuple
           :identity-eid    identity-eid
           :existing-tuple  nil
           :mismatch-axes   mismatch-axes
           :cross-cluster   {:ip cross-ip? :fp cross-fp?}
           :pubkey-eid      pubkey-eid})))))

(defn- match-axes-set
  "Build the :request/match-axes set: tags this request with what
  matched, what mismatched, and any cross-cluster advisory hits."
  [classification]
  (let [{:keys [kind mismatch-axes cross-cluster]} classification
        base (case kind
               :exact-observation #{:pubkey-match :ip-match :fp-match}
               :new-tuple        (-> #{:pubkey-match}
                                     (cond->
                                      (not (contains? mismatch-axes :ip)) (conj :ip-match)
                                      (not (contains? mismatch-axes :fp)) (conj :fp-match)
                                      (contains? mismatch-axes :ip)        (conj :ip-mismatch)
                                      (contains? mismatch-axes :fp)        (conj :fp-mismatch)))
               #{})]
    (cond-> base
      (:ip cross-cluster) (conj :ip-cross-cluster)
      (:fp cross-cluster) (conj :fp-cross-cluster))))

(defn classification-tx
  "Build tx-data that applies a classification's effects to the DB.
  Inputs:
    classification — output of `classify` (must NOT be :revoked-pubkey
                     or :orphan-pubkey; handler rejects those)
    incoming       — same as passed to classify
    sketch         — the identity's current spaced-continuity sketch
                     (epoch-ms fields, from `identity->sketch`)
    scoring        — weight constants (`score/default-scoring`)
    now            — java.util.Date

  Every verify on this path is a clean (pubkey-matched) continuity
  signal: it reinforces the sketch (clean-count++, spacing += inter-
  arrival credit, last-clean-at = now). A new-tuple with an axis mismatch
  ALSO increments violation-count, which erodes the derived score via the
  violation-rate term without erasing the continuity reinforcement.
  `:trust-event/delta` is the change in derived score this event causes
  (score-after − score-before, evaluated at `now`).

  Returns a vector of tx maps."
  [classification incoming sketch scoring now]
  (let [{:keys [kind identity-eid existing-tuple mismatch-axes
                pubkey-eid]} classification
        d            (->date now)
        now-ms       (.getTime d)
        reasons      (case kind
                       :exact-observation [:pubkey-match]
                       :new-tuple        (into [:pubkey-match]
                                                (score/axis-mismatch->reasons
                                                 mismatch-axes)))
        violation?   (boolean (seq mismatch-axes))
        sketch'      (score/sketch-update sketch now-ms violation? scoring)
        score-before (score/score-of sketch now-ms scoring)
        score-after  (score/score-of sketch' now-ms scoring)
        delta        (- score-after score-before)
        match-axes   (match-axes-set classification)
        common       [{:db/id                    identity-eid
                       :identity/last-event-at    d
                       :identity/last-clean-at    d
                       :identity/clean-count      (:clean-count sketch')
                       :identity/spacing          (:spacing sketch')
                       :identity/violation-count  (:violation-count sketch')
                       :identity/score            score-after}
                      {:trust-event/identity   identity-eid
                       :trust-event/ts         d
                       :trust-event/delta      delta
                       :trust-event/reason     (first reasons)
                       :trust-event/score-after score-after}]]
    (case kind
      :exact-observation
      (conj common
            {:db/id                    (:db/id existing-tuple)
             :tuple/last-seen          d
             :tuple/observation-count  (inc (or (:tuple/observation-count existing-tuple) 0))}
            {:request/identity         identity-eid
             :request/ts               d
             :request/outcome          :ok
             :request/tuple            (:db/id existing-tuple)
             :request/match-axes       match-axes})

      :new-tuple
      (let [tid (random-uuid)]
        (into common
              [{:db/id                   -100
                :tuple/id                tid
                :tuple/identity          identity-eid
                :tuple/ip-hash           (:ip incoming)
                :tuple/fp-digest         (:fp-digest incoming)
                :tuple/pubkey            pubkey-eid
                :tuple/first-seen        d
                :tuple/last-seen         d
                :tuple/observation-count 1}
               {:request/identity        identity-eid
                :request/ts              d
                :request/outcome         :ok
                :request/tuple           -100
                :request/match-axes      match-axes}])))))
