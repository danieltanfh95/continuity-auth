(ns continuity-auth.server.http.envelope-check
  "Shared envelope verification flow used by /bootstrap, /verify, and
  /rotate-key. Sequence (in order; each step short-circuits on failure):

    1. Parse the wire envelope into the structured form.
    2. Validate field sizes / UTF-8 bounds (handled by envelope/validate).
    3. Check the timestamp is within ±tolerance of `now`.
    4. Resolve the pubkey:
         - via :key-id lookup in storage (bootstrap=no; verify=yes), OR
         - via an inline pubkey payload (bootstrap path).
    5. **Route-binding** check: envelope.method/path/body-sha256 match the
       endpoint the request actually hit (control endpoints only).
    6. Verify the signature against the canonical bytes.
    7. Check + atomically record the nonce.

  Returns either:
    {:ok? true  :envelope <envelope-map> :pubkey-record <record-or-payload>}
    OR throws a typed exception via errors/fail!."
  (:require
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.hash :as hash]
   [continuity-auth.server.crypto.pubkey :as pubkey]
   [continuity-auth.server.crypto.verify :as verify]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.replay.nonce :as nonce]
   [continuity-auth.server.storage.protocol :as storage]))

;; -- timestamp / clock ----------------------------------------------------

(defn- parse-iso8601
  ^java.time.Instant [^String s]
  (try
    (java.time.Instant/parse s)
    (catch Exception _ nil)))

(defn check-timestamp!
  "Throws E_BAD_REQUEST if the envelope's ts is malformed or outside
  the tolerance window."
  [envelope tolerance-seconds ^java.util.Date now]
  (let [parsed (parse-iso8601 (:ts envelope))]
    (when-not parsed
      (errors/fail! :E_BAD_REQUEST "invalid timestamp"))
    (let [now-ms     (.getTime now)
          ts-ms      (.toEpochMilli parsed)
          tolerance  (* 1000 (long tolerance-seconds))
          delta      (Math/abs (- now-ms ts-ms))]
      (when (> delta tolerance)
        (errors/fail! :E_UNAUTHORIZED "envelope outside clock-skew window")))))

;; -- pubkey resolution ----------------------------------------------------

(defn resolve-existing-pubkey!
  "Look up the pubkey by :key-id in storage. Returns the record; throws
  if not found or if it has been revoked as of `now`.

  Rotation sets `:pubkey/revoked-at = now + grace_seconds` on the old
  key, so a future-dated `:pubkey/revoked-at` is the in-grace state —
  the key is still valid until the timestamp passes. Explicit revoke
  sets `:pubkey/revoked-at = now` and takes effect immediately. The
  comparison is `revoked? = (revoked-at != nil) && (now >= revoked-at)`."
  [store snap envelope ^java.util.Date now]
  (let [thumb  (:key-id envelope)
        record (storage/find-pubkey-by-thumbprint store snap thumb)]
    (when-not record
      (errors/fail! :E_UNAUTHORIZED "unknown key-id"))
    (let [^java.util.Date revoked-at (:pubkey/revoked-at record)]
      (when (and revoked-at (not (.before now revoked-at)))
        (errors/fail! :E_FORBIDDEN "pubkey revoked")))
    record))

;; -- route binding --------------------------------------------------------

(defn enforce-route-binding!
  "Verify that the envelope's `:method`, `:path`, and (if `:expect-body-sha256`
  is supplied) `:body-sha256` match the endpoint this request actually hit.

  `expect` is `{:method <upper-string>
                :path   <string>
                :body-sha256 <bytes-or-nil>}`.

  Throws `:E_UNAUTHORIZED` on mismatch. We use a single error code (not
  three) so the public response cannot disclose which axis failed."
  [envelope {:keys [method path body-sha256] :as _expect}]
  (when (not= (:method envelope) method)
    (errors/fail! :E_UNAUTHORIZED "envelope route binding failed"))
  (when (not= (:path envelope) path)
    (errors/fail! :E_UNAUTHORIZED "envelope route binding failed"))
  (when (and body-sha256
             (not (hash/constant-time-equal?
                   ^bytes (:body-sha256 envelope) ^bytes body-sha256)))
    (errors/fail! :E_UNAUTHORIZED "envelope route binding failed")))

;; -- signature verification ------------------------------------------------

(defn verify-signature!
  "Verify the envelope's signature against the canonical bytes using
  the provided pubkey bytes + alg. Throws E_UNAUTHORIZED on failure."
  [envelope pubkey-bytes alg]
  (let [bs  (envelope/canonical-bytes envelope)
        sig (:signature envelope)]
    (when-not (verify/verify alg pubkey-bytes bs sig)
      (errors/fail! :E_UNAUTHORIZED "invalid signature"))))

;; -- nonce + record --------------------------------------------------------

(defn check-and-record-nonce!
  "Atomic replay check. Throws E_REPLAY if the nonce has been seen."
  [store envelope ttl-seconds ^java.util.Date now]
  (let [result (nonce/check-and-record! store (:nonce envelope) ttl-seconds now)]
    (when (= :replay result)
      (errors/fail! :E_REPLAY "nonce replay"))))

;; -- top-level flows ------------------------------------------------------

(defn verify-existing-envelope!
  "End-to-end verification for /verify, /rotate-key, /revoke-key paths.

  Returns the pubkey record on success.

  `:expect` (optional) — when supplied, the envelope must be
  route-bound to that method/path/body-sha256 before the signature is
  considered. Control endpoints (rotate-key, revoke-key) MUST pass an
  `:expect`. /verify does NOT pass one — the host backend is
  responsible for cross-checking envelope.path against the request it
  is gating."
  [{:keys [store snap envelope tolerance-seconds nonce-ttl-seconds now expect]}]
  (check-timestamp! envelope tolerance-seconds now)
  (when expect
    (enforce-route-binding! envelope expect))
  (let [record (resolve-existing-pubkey! store snap envelope now)]
    (verify-signature! envelope (:pubkey/bytes record) (:pubkey/alg record))
    ;; Nonce check happens AFTER signature verify so attackers cannot
    ;; pollute the nonce cache with arbitrary values just by sending
    ;; junk. (If they have a valid signature, they could pollute, but
    ;; that requires the private key.)
    (check-and-record-nonce! store envelope nonce-ttl-seconds now)
    record))

(defn verify-bootstrap-envelope!
  "/bootstrap path: the pubkey is in the request payload, not in the DB.

  `:expect` is mandatory here — bootstrap envelopes must be bound to
  POST /v1/bootstrap so a signing oracle on any other path cannot
  install a new identity."
  [{:keys [store envelope pubkey-bytes alg tolerance-seconds
            nonce-ttl-seconds now expect]}]
  (check-timestamp! envelope tolerance-seconds now)
  (when expect
    (enforce-route-binding! envelope expect))
  ;; Confirm the envelope's key-id matches the SHA-256 thumbprint of
  ;; the supplied pubkey bytes — otherwise the client is claiming a
  ;; pubkey it does not actually present.
  (let [computed-thumb (pubkey/alg+canonical->thumbprint alg pubkey-bytes)]
    (when-not (java.security.MessageDigest/isEqual
               ^bytes (:key-id envelope) ^bytes computed-thumb)
      (errors/fail! :E_BAD_REQUEST "key-id does not match supplied pubkey")))
  (verify-signature! envelope pubkey-bytes alg)
  (check-and-record-nonce! store envelope nonce-ttl-seconds now)
  {:bytes pubkey-bytes :alg alg :id (:key-id envelope)})
