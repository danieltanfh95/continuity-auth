(ns continuity-auth.server.http.util
  "Shared helpers for HTTP handlers: payload parsing, ISO-8601 formatting,
  pubkey-record accessors, and revocation transaction shape.

  Centralised here so the bootstrap / verify / rotate / revoke / admin
  handlers do not each carry their own copy."
  (:require
   [continuity-auth.crypto :as crypto]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.http.errors :as errors]))

(defn iso8601
  "Format `d` as ISO-8601 UTC with millisecond precision
  (`yyyy-MM-dd'T'HH:mm:ss.SSS'Z'`)."
  ^String [^java.util.Date d]
  (let [fmt (java.text.SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")]
    (.setTimeZone fmt (java.util.TimeZone/getTimeZone "UTC"))
    (.format fmt d)))

(defn identity-eid-of
  "Extract the identity :db/id from a pubkey-record. Pulls return
  `:pubkey/identity` as either a nested entity-map (with `:db/id`) or a
  bare long, depending on the pull pattern — this normalises both."
  [pubkey-record]
  (or (:db/id (:pubkey/identity pubkey-record))
      (:pubkey/identity pubkey-record)))

(defn revoke-tx
  "Build the two-entity tx vector that revokes a pubkey at `revoked-at`
  and appends a trust-event with `reason` (e.g. `:revoke-key`,
  `:admin-revoke`, or — when called from rotation — used to future-date
  the old key).

  `:event-ts` is the audit timestamp on the trust-event; it defaults to
  `revoked-at`. They differ for rotation: the old key's revocation is
  future-dated to `grace-expires`, but the audit record of the rotation
  itself happens at `now`."
  [{:keys [pubkey-eid identity-eid revoked-at reason event-ts]}]
  (let [ts (or event-ts revoked-at)]
    [{:db/id             pubkey-eid
      :pubkey/revoked-at revoked-at}
     {:trust-event/identity identity-eid
      :trust-event/ts       ts
      :trust-event/delta    0.0
      :trust-event/reason   reason}]))

(defn parse-pubkey-payload
  "Parse `{envelope, <pubkey-key>, <alg-key>}` from a JSON body into the
  structured form `{:envelope :pubkey-bytes :alg}`. Used by /bootstrap
  (`pubkey`/`alg`) and /rotate-key (`new-pubkey`/`new-alg`); the wire
  keys are configurable so the field names in error messages match what
  the caller actually sent.

  Throws E_BAD_REQUEST on any malformed field."
  [body-params {:keys [pubkey-key alg-key]
                :or   {pubkey-key :pubkey alg-key :alg}}]
  (let [envelope     (:envelope body-params)
        pubkey-raw   (get body-params pubkey-key)
        alg          (get body-params alg-key)
        pubkey-label (name pubkey-key)
        alg-label    (name alg-key)]
    (when-not (and envelope pubkey-raw alg)
      (errors/fail! :E_BAD_REQUEST
                    (str "missing envelope / " pubkey-label " / " alg-label)))
    (let [alg-kw (keyword alg)]
      (when-not (crypto/algorithm? alg-kw)
        (errors/fail! :E_BAD_REQUEST (str "unknown " alg-label)))
      (let [env (try (envelope/wire->envelope envelope)
                     (catch Exception _
                       (errors/fail! :E_BAD_REQUEST "malformed envelope")))
            pkb (try (envelope/b64url-decode pubkey-raw)
                     (catch Exception _
                       (errors/fail! :E_BAD_REQUEST
                                     (str "malformed " pubkey-label))))]
        (when-not (= (count pkb) (get crypto/pubkey-byte-length alg-kw))
          (errors/fail! :E_BAD_REQUEST
                        (str pubkey-label " wrong length for " alg-label)))
        {:envelope env :pubkey-bytes pkb :alg alg-kw}))))
