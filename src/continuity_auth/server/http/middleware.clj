(ns continuity-auth.server.http.middleware
  "Ring middleware used by all endpoints.

  Composed in `http/router.clj`. Order matters:

    wrap-request-id        ← outermost: stamp every request
    wrap-error             ← catches exceptions from inner middleware
    wrap-json-body
    wrap-json-response
    wrap-trusted-proxy-ip  ← sets :cauth/client-ip from trusted header"
  (:require
   [clojure.string :as str]
   [continuity-auth.server.crypto.ip-hmac :as ip-hmac]
   [continuity-auth.server.http.errors :as errors]
   [continuity-auth.server.storage.protocol :as storage]
   [jsonista.core :as json]))

(defn- random-id []
  (let [b (byte-array 8)]
    (.nextBytes (java.security.SecureRandom.) b)
    (.encodeToString
     (.withoutPadding (java.util.Base64/getUrlEncoder))
     b)))

(defn wrap-request-id
  "Stamps the request with an opaque request-id and echoes it back as
  the `X-Request-Id` response header. If the client sent one, we use
  that value (sanitized) — useful for tracing across a host's logs."
  [handler]
  (fn [request]
    (let [incoming (get-in request [:headers "x-request-id"])
          rid      (or (and incoming
                            (re-matches #"[A-Za-z0-9_-]{1,128}" incoming)
                            incoming)
                       (random-id))
          response (handler (assoc request :cauth/request-id rid))]
      (assoc-in response [:headers "X-Request-Id"] rid))))

(defn wrap-error
  "Catches exceptions and converts them to the uniform error response.
  ex-info with :cauth/error code → typed response. Anything else → 500."
  [handler]
  (fn [request]
    (try
      (handler request)
      (catch clojure.lang.ExceptionInfo ex
        (errors/ex->response ex))
      (catch Throwable ex
        ;; Unexpected — log and return 500 with generic code.
        (binding [*out* *err*]
          (println "unhandled exception in handler:" (ex-message ex)))
        (errors/error-response :E_INTERNAL)))))

(def ^:private json-mapper
  (json/object-mapper
   {:decode-key-fn keyword
    :encode-key-fn name}))

(def ^:private body-bearing-methods
  #{:post :put :patch :delete})

(defn wrap-json-body
  "Parse the request body as JSON into the :body-params key. Only
  triggers on methods that conventionally bear a request body."
  [handler]
  (fn [request]
    (let [method (:request-method request)
          ctype  (or (get-in request [:headers "content-type"]) "")
          body   (:body request)]
      (if (and (body-bearing-methods method)
               (or (str/starts-with? ctype "application/json")
                   (str/blank? ctype))
               body)
        (let [parsed (try
                       (json/read-value body json-mapper)
                       (catch Exception _
                         (errors/fail! :E_BAD_REQUEST "malformed JSON body")))]
          (handler (assoc request :body-params parsed)))
        (handler request)))))

(defn- read-bounded
  "Read at most `limit` bytes from `in`. Returns the byte array if the
  stream is exhausted at or under the limit; throws E_PAYLOAD_TOO_LARGE
  otherwise.

  Buffer size is exactly `limit` (not `inc limit`). The boundary case is:
  if the buffer fills (`total == limit`) and one more byte is available
  on the stream, we reject. The previous implementation used a buffer
  of `limit+1` and could return `limit+1` bytes when the stream EOF'd
  exactly there — off by one."
  ^bytes [^java.io.InputStream in ^long limit]
  (let [buf (byte-array limit)]
    (loop [total 0]
      (let [room (- limit total)]
        (if (zero? room)
          ;; Buffer is full; if there's still a byte on the wire the
          ;; body is over-limit.
          (let [extra (.read in)]
            (if (neg? extra)
              buf
              (errors/fail! :E_PAYLOAD_TOO_LARGE "request body too large")))
          (let [n (.read in buf total room)]
            (cond
              (neg? n)  (java.util.Arrays/copyOf buf total)
              (zero? n) (recur total)
              :else     (recur (+ total n)))))))))

(defn wrap-body-size-limit
  "Enforce a hard upper bound on the request body in bytes.

  Defends against memory-exhaustion attacks via oversized JSON. Two
  signals are honoured:

    - `Content-Length` header: if present and over `max-bytes`, reject
      immediately with 413 before reading any of the body.
    - Otherwise (chunked / missing header): drain at most `max-bytes+1`
      into a buffer; if anything remains after that, reject.

  Only applies to body-bearing methods. On accept the request's `:body`
  is replaced with a `ByteArrayInputStream` over the captured bytes so
  downstream middleware (e.g. wrap-json-body) sees a normal Ring body.
  The captured bytes are ALSO attached at `:cauth/raw-body` so handlers
  that need to compute an HMAC over the raw body (e.g. admin endpoints)
  do not have to round-trip through JSON re-serialization."
  [handler max-bytes]
  (let [limit (long max-bytes)]
    (fn [request]
      (let [method (:request-method request)]
        (if (body-bearing-methods method)
          (let [raw-clen (get-in request [:headers "content-length"])
                clen     (when raw-clen
                           (try (Long/parseLong raw-clen)
                                (catch NumberFormatException _
                                  ;; Codex M6: an unparseable Content-Length
                                  ;; previously fell through to wrap-error
                                  ;; and returned 500. That gave malformed-
                                  ;; header floods a cheap log-spam path.
                                  (errors/fail! :E_BAD_REQUEST
                                                "malformed Content-Length"))))
                _      (when (and clen (> ^long clen limit))
                         (errors/fail! :E_PAYLOAD_TOO_LARGE
                                       "request body too large"))
                ^java.io.InputStream body (:body request)
                bytes  (when body (read-bounded body limit))]
            (handler (cond-> request
                       bytes (assoc :body         (java.io.ByteArrayInputStream. bytes)
                                    :cauth/raw-body bytes))))
          (handler request))))))

(defn wrap-json-response
  "Wrap a Clojure data response into JSON. Skips already-encoded
  string bodies."
  [handler]
  (fn [request]
    (let [response (handler request)
          body     (:body response)]
      (cond
        (nil? body)    response
        (string? body) response
        :else (-> response
                  (update :headers assoc "Content-Type"
                          "application/json; charset=utf-8")
                  (assoc :body (json/write-value-as-string body json-mapper)))))))

;; -- trusted-proxy IP extraction -------------------------------------------

(defn- cidr->long-range
  "Parse a CIDR like \"10.0.0.0/8\" into an [start end] inclusive-Long
  IPv4 range. Returns nil for non-IPv4 or malformed input. (IPv6
  ranges are punted to a separate path — see below.)"
  [cidr]
  (when-let [m (re-matches #"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})" cidr)]
    (let [[_ a b c d bits] m
          ip   (bit-or
                (bit-shift-left (Long/parseLong a) 24)
                (bit-or (bit-shift-left (Long/parseLong b) 16)
                        (bit-or (bit-shift-left (Long/parseLong c) 8)
                                (Long/parseLong d))))
          bits (Long/parseLong bits)
          mask (if (zero? bits) 0 (bit-shift-left -1 (- 32 bits)))
          base (bit-and ip mask 0xffffffff)
          size (bit-shift-left 1 (- 32 bits))]
      [base (+ base (dec size))])))

(defn- ip->long [^String s]
  (when-let [m (re-matches #"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})" s)]
    (let [[_ a b c d] m]
      (bit-or
       (bit-shift-left (Long/parseLong a) 24)
       (bit-or (bit-shift-left (Long/parseLong b) 16)
               (bit-or (bit-shift-left (Long/parseLong c) 8)
                       (Long/parseLong d)))))))

(defn- ip-in-cidrs?
  "Return true iff the IPv4 address falls into any of the ranges."
  [^String ip-string ranges]
  (when-let [n (ip->long ip-string)]
    (some (fn [[lo hi]] (<= lo n hi)) ranges)))

(defn parse-trusted-cidrs
  "Parse a comma-separated CIDR string into a vector of [lo hi] ranges.
  Empty or nil input yields []."
  [s]
  (if (or (nil? s) (str/blank? s))
    []
    (->> (str/split s #",")
         (map str/trim)
         (keep cidr->long-range)
         vec)))

(defn extract-client-ip
  "Given a Ring request, the trusted-CIDR ranges (parsed via
  `parse-trusted-cidrs`), and the header name to consult, return the
  best estimate of the client's IP.

  Algorithm:
    - If `trusted-cidrs` is empty, return `:remote-addr` of the request.
    - If `:remote-addr` is NOT in any trusted CIDR, return `:remote-addr`
      (we don't honor headers from arbitrary callers).
    - Otherwise, read `header-name` from the request; if it contains a
      comma-separated list (`X-Forwarded-For` style), take the FIRST
      entry that is NOT itself a trusted-proxy IP. That's the client.
    - If no such entry, fall back to `:remote-addr`."
  [request trusted-cidrs header-name]
  (let [remote (:remote-addr request)]
    (cond
      (empty? trusted-cidrs)
      remote

      (not (ip-in-cidrs? remote trusted-cidrs))
      remote

      :else
      (let [hdr (get-in request [:headers (str/lower-case header-name)])]
        (or (when (string? hdr)
              (let [chain (->> (str/split hdr #",")
                               (map str/trim)
                               (remove str/blank?))]
                (some (fn [candidate]
                        ;; Must be a parseable IPv4 AND not a trusted
                        ;; proxy. Non-IP strings previously slipped
                        ;; through because
                        ;; `ip-in-cidrs?` returns nil for unparseable
                        ;; input, which `when-not` then treated as
                        ;; "not in trusted" → accepted as the client.
                        (when (and (ip->long candidate)
                                   (not (ip-in-cidrs? candidate trusted-cidrs)))
                          candidate))
                      chain)))
            remote)))))

(defn wrap-trusted-proxy-ip
  "Attach `:cauth/client-ip` (the HMAC of the raw IP, hex-encoded) and
  `:cauth/client-ip-raw` (the plaintext IP) to the request. The raw IP
  is exposed transiently for the in-process CIDR check in
  `wrap-bootstrap-rate-limit`; it MUST NOT be logged or persisted.
  Downstream handlers read only `:cauth/client-ip`.

  Configuration:
     :trusted-cidrs — coll of [lo hi] ranges (see `parse-trusted-cidrs`)
     :ip-header     — the header to consult, e.g. \"x-forwarded-for\"
     :ip-hmac-key   — 32-byte server-side secret (see
                      `continuity-auth.server.crypto.ip-hmac`)"
  [handler {:keys [trusted-cidrs ip-header ip-hmac-key]
            :or {ip-header "x-forwarded-for"}}]
  (when-not ip-hmac-key
    (throw (ex-info "wrap-trusted-proxy-ip: missing :ip-hmac-key" {})))
  (fn [request]
    (let [ip (extract-client-ip request trusted-cidrs ip-header)
          ip-hash (when (and (string? ip) (not (str/blank? ip)))
                    (ip-hmac/hmac-ip-hex ip-hmac-key ip))]
      (handler (assoc request
                      :cauth/client-ip ip-hash
                      :cauth/client-ip-raw ip)))))

;; -- bootstrap rate limit --------------------------------------------------
;;
;; Time-as-resource framing: bootstrap is the one endpoint where the
;; protocol has no identity yet, so the identity-keyed time-resource
;; (tier accumulation, decay curve, host-link cooling-off) hasn't started
;; accumulating. The defence is per-IP exponential backoff with a cap:
;; legitimate users behind shared NAT pay at most floor-ms once before
;; their bootstrap proceeds; an attacker spinning fresh containers from
;; one IP climbs the staircase 1s → 2s → … → cap, capping at cap-ms per
;; identity steady-state.
;;
;; Data shape (per-instance atom):
;;
;;   strike-state = {ip-string → {:last-attempt-ms  long   ; refreshed every attempt
;;                                :penalty-until-ms long   ; gate; attempts before → 429
;;                                :consecutive      long}} ; allows since last reset
;;
;; State transitions per /v1/bootstrap request:
;;   - now-ms ≥ :penalty-until-ms (or no entry) → ALLOW. If quiet
;;     ((now - last-attempt) > reset-threshold) reset :consecutive to 0;
;;     otherwise keep it. Compute penalty-ms = min(cap, floor × factor^consec)
;;     and set :penalty-until-ms = now + penalty-ms. Bump :consecutive.
;;   - now-ms < :penalty-until-ms → DENY with retry-after =
;;     (penalty-until-ms - now). Refresh :last-attempt-ms only; the strike
;;     stands (denied requests do not compound the penalty).
;;
;; Entries whose :last-attempt-ms is older than :reset-threshold-ms are
;; swept inline atomically with each request — bounded growth to
;; recent-IP cardinality. Cross-instance fairness (Datalevin-backed
;; buckets) is deferred to v1.1; see plan §"Out of scope" Tier 4.

(defn- compute-penalty-ms
  "Pure: doubling staircase capped at `cap-ms`, then multiplied by
  `suspicion` (a positive double, typically in [0.5, 100]) and re-capped.

  `consecutive` is the number of allows in the current burst BEFORE this
  one (0 for the first allow after a quiet period). `suspicion = 1.0`
  reduces to the pure exp-backoff staircase (Tier 1 behaviour).

  Note: no primitive type hints — JVM limits prim-typed fns to ≤4 args."
  [floor-ms cap-ms doubling-factor consecutive suspicion]
  (let [pow (Math/pow (double doubling-factor) (double consecutive))
        raw (long (* (double floor-ms) pow (double suspicion)))]
    (min (long cap-ms) (max 0 raw))))

;; -- Tier 2: IP-anchored suspicion multiplier --------------------------------
;;
;; Pure function from {:ip-age-seconds :identity-count :datacenter-hit?}
;; to a multiplier on the staircase floor. Composition is multiplicative
;; so any one strong signal can dominate; clamp to [0.5, 100] keeps a
;; well-behaved IP at half the floor and an extreme attacker at no more
;; than 100× the floor (still capped at cap-ms by compute-penalty-ms).
;;
;; Default curves come from the project plan §"Tier 2":
;;   - ip-age 0/≤1h → ×10, ≤1d → ×3, ≤30d → ×1, ≤365d → ×0.7, > 1yr → ×0.5
;;   - identity-count 0 → ×1, 1–5 → ×2, 6–49 → ×5, ≥50 → ×10
;;   - datacenter-hit? → ×5 multiplicative on top
;;
;; Nil semantics: a nil :ip-age-seconds or :identity-count means "we have
;; no signal for this axis" (e.g. storage read timed out / disabled) and
;; the axis contributes ×1.0 (neutral). Distinguishes "unseen IP" (signal
;; said 0 → ×10) from "couldn't read" (no signal → ×1).
;;
;; Operators who need different shapes can replace this function in v1.1
;; (the config carries `:ip-age-multiplier-fn :default` as the slot).

(defn- ip-age-multiplier ^double [ip-age-seconds]
  (if (nil? ip-age-seconds)
    1.0
    (let [s (long ip-age-seconds)]
      (cond
        (<= s 0)         10.0
        (<= s 3600)      10.0
        (<= s 86400)      3.0
        (<= s 2592000)    1.0
        (<= s 31536000)   0.7
        :else             0.5))))

(defn- identity-count-multiplier ^double [identity-count]
  (if (nil? identity-count)
    1.0
    (let [n (long identity-count)]
      (cond
        (<= n 0)   1.0
        (<= n 5)   2.0
        (<= n 49)  5.0
        :else     10.0))))

(defn bootstrap-suspicion-multiplier
  "Pure: compose ip-age × identity-count × datacenter-hit? into a single
  multiplier on the bootstrap penalty floor. Clamped to [0.5, 100]."
  ^double [{:keys [ip-age-seconds identity-count datacenter-hit?]}]
  (let [a   (ip-age-multiplier ip-age-seconds)
        b   (identity-count-multiplier identity-count)
        c   (if datacenter-hit? 5.0 1.0)
        raw (* a b c)]
    (-> raw (max 0.5) (min 100.0))))

;; -- Tier 2 plumbing: signal cache + storage lookup with timeout ------------

(defn- read-cached-signal
  "Return cached `{:ip-age-seconds :identity-count :cached-at-ms}` for `ip`
  if fresh, else nil."
  [cache ip ^long now-ms ^long ttl-ms]
  (when-let [entry (get cache ip)]
    (when (< (- now-ms (long (:cached-at-ms entry))) ttl-ms)
      entry)))

(defn- fetch-signal!
  "Run the storage signal lookup with a hard timeout. On success populate
  the cache and return the signal map; on timeout / exception call
  `on-fallback` and return nil. The caller composes the multiplier
  separately so a fallback still benefits from the CIDR check."
  [cache-atom store ip now-ms timeout-ms on-fallback]
  (let [fut (future
              (let [snap (storage/snapshot store)]
                (storage/bootstrap-signals-for-ip store snap ip now-ms)))]
    (try
      (let [sig (deref fut timeout-ms ::timeout)]
        (cond
          (identical? sig ::timeout)
          (do (future-cancel fut)
              (on-fallback :timeout nil)
              nil)

          (nil? sig) nil

          :else
          (let [entry (assoc sig :cached-at-ms now-ms)]
            (swap! cache-atom assoc ip entry)
            entry)))
      (catch Throwable t
        (on-fallback :exception t)
        nil))))

(defn make-suspicion-fn
  "Build a per-IP suspicion-multiplier function for `wrap-bootstrap-rate-limit`.

  Returns `(fn [ip-hash raw-ip now-ms] → double)` that:
    1. Looks up cached signals for `ip-hash` (TTL = `:cache-ttl-ms`).
       `ip-hash` is the opaque HMAC token — same as the cache key,
       same as `:tuple/ip-hash` in storage.
    2. On cache miss + `:storage` present, runs an indexed read keyed
       on `ip-hash` with `:read-timeout-ms`; success → cache + use;
       failure → fall back to neutral signals (the multiplier still
       includes the CIDR check).
    3. Composes signals + CIDR membership via
       `bootstrap-suspicion-multiplier`. The CIDR membership test
       uses `raw-ip` because the CIDR ranges are over plaintext IPs.

  Options:
    :storage          Storage protocol instance (nil → signals disabled)
    :signals-enabled? gate (default true if storage present)
    :cache-ttl-ms     freshness window for cached signals (default 300_000)
    :read-timeout-ms  hard deadline for the storage read (default 50)
    :datacenter-cidrs vector of [lo hi] IPv4 ranges (parsed at startup)
    :on-fallback      (fn [kind ex]) called on :timeout or :exception
                       so callers can emit metrics (default no-op)"
  [{:keys [storage signals-enabled? cache-ttl-ms read-timeout-ms
           datacenter-cidrs on-fallback]
    :or   {cache-ttl-ms     300000
           read-timeout-ms  50
           datacenter-cidrs []
           on-fallback      (fn [_kind _ex])}}]
  (let [enabled? (if (some? signals-enabled?)
                   (boolean signals-enabled?)
                   (some? storage))
        ttl     (long cache-ttl-ms)
        timeout (long read-timeout-ms)
        cache   (atom {})]
    (fn suspicion-fn [^String ip-hash ^String raw-ip ^long now-ms]
      (let [dch? (boolean (ip-in-cidrs? raw-ip datacenter-cidrs))
            base (when (and enabled? storage ip-hash)
                   (or (read-cached-signal @cache ip-hash now-ms ttl)
                       (fetch-signal! cache storage ip-hash now-ms
                                      timeout on-fallback)))
            sig  (assoc (or base {:ip-age-seconds nil :identity-count nil})
                        :datacenter-hit? dch?)]
        (bootstrap-suspicion-multiplier sig)))))

(defn- bootstrap-tick
  "Pure: given the OLD per-IP entry and the request's `now-ms` + config,
  return the new entry to write. Outcome is re-derived from the OLD
  entry's :penalty-until-ms vs `now-ms` so the caller can branch after
  the swap without volatile.

  `:suspicion` (default 1.0) is the Tier 2/3 multiplier applied to the
  staircase floor; pass 1.0 for pure Tier 1 behaviour."
  [entry ^long now-ms
   {:keys [^long floor-ms ^long cap-ms ^long doubling-factor
           ^long reset-threshold-ms suspicion]
    :or   {suspicion 1.0}}]
  (let [last-ms (:last-attempt-ms entry)
        until   (long (or (:penalty-until-ms entry) 0))
        consec  (long (or (:consecutive entry) 0))]
    (if (>= now-ms until)
      ;; ALLOW
      (let [quiet?  (or (nil? last-ms)
                        (> (- now-ms (long last-ms)) reset-threshold-ms))
            consec' (if quiet? 0 consec)
            penalty (compute-penalty-ms floor-ms cap-ms doubling-factor
                                        consec' (double suspicion))]
        {:last-attempt-ms  now-ms
         :penalty-until-ms (+ now-ms penalty)
         :consecutive      (inc consec')})
      ;; DENY — refresh last-attempt-ms; strike stands.
      (assoc entry :last-attempt-ms now-ms))))

(defn- sweep-stale
  "Drop entries whose :last-attempt-ms is older than `reset-threshold-ms`
  from `now-ms`. Keeps strike-state bounded to recent-IP cardinality."
  [state ^long now-ms ^long reset-threshold-ms]
  (persistent!
   (reduce-kv (fn [acc ip entry]
                (let [last-ms (:last-attempt-ms entry)]
                  (if (or (nil? last-ms)
                          (> (- now-ms (long last-ms)) reset-threshold-ms))
                    acc
                    (assoc! acc ip entry))))
              (transient {})
              state)))

(defn wrap-bootstrap-rate-limit
  "Rate-limit POST /v1/bootstrap with per-IP exponential backoff.

  Options (defaults match `:bootstrap-rate-limit` in resources/config.edn):

    :path                URI to gate                          \"/v1/bootstrap\"
    :floor-ms            minimum penalty (first allow)        1000
    :cap-ms              maximum penalty regardless of strike 60000
    :doubling-factor     penalty multiplier per consecutive   2
    :reset-threshold-ms  quiet-time → :consecutive resets     300000
    :now-fn              clock injection (no-arg → ms)        #(System/currentTimeMillis)
    :suspicion-fn        (fn [ip-hash raw-ip now-ms] → double) — Tier 2/3
                          multiplier composed by `make-suspicion-fn`. The
                          hash keys storage lookups; the raw IP is used
                          for the datacenter-CIDR membership test.
                          Default `(constantly 1.0)` ⇒ pure Tier 1
                          staircase.

  Rejects with 429 / `E_RATE` and a `Retry-After` header carrying the
  actual remaining milliseconds (ceiling-divided to seconds) BEFORE any
  JSON parsing, signature verification, or DB write."
  [handler {:keys [path floor-ms cap-ms doubling-factor reset-threshold-ms
                   now-fn suspicion-fn]
            :or   {path               "/v1/bootstrap"
                   floor-ms           1000
                   cap-ms             60000
                   doubling-factor    2
                   reset-threshold-ms 300000
                   now-fn             #(System/currentTimeMillis)
                   suspicion-fn       (fn [_ _ _] 1.0)}}]
  (let [base-opts {:floor-ms           (long floor-ms)
                   :cap-ms             (long cap-ms)
                   :doubling-factor    (long doubling-factor)
                   :reset-threshold-ms (long reset-threshold-ms)}
        rth       (long reset-threshold-ms)
        state     (atom {})]
    (fn [request]
      (if (and (= :post (:request-method request))
               (= path (:uri request)))
        (let [ip-hash     (or (:cauth/client-ip request)
                              (:remote-addr request)
                              "unknown")
              raw-ip      (or (:cauth/client-ip-raw request)
                              (:remote-addr request))
              ip          ip-hash
              now-ms      (long (now-fn))
              mult        (try (double (suspicion-fn ip-hash raw-ip now-ms))
                               (catch Throwable _ 1.0))
              opts        (assoc base-opts :suspicion mult)
              [old _new]  (swap-vals!
                           state
                           (fn [s]
                             (let [swept (sweep-stale s now-ms rth)]
                               (assoc swept ip
                                      (bootstrap-tick (get swept ip)
                                                      now-ms opts)))))
              old-until   (long (or (:penalty-until-ms (get old ip)) 0))]
          (if (>= now-ms old-until)
            (handler request)
            (errors/error-response :E_RATE (- old-until now-ms))))
        (handler request)))))
