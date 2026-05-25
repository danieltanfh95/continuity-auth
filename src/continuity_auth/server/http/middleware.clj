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
   [continuity-auth.server.http.errors :as errors]
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
  otherwise. We read into a fixed-size buffer to make the upper bound
  hard (no chunked-upload escape hatch)."
  ^bytes [^java.io.InputStream in ^long limit]
  (let [buf (byte-array (inc limit))]
    (loop [total 0]
      (let [room (- (alength buf) total)]
        (if (zero? room)
          ;; We read limit+1 bytes; one more byte still available means
          ;; the actual length exceeds the limit.
          (let [extra (.read in)]
            (if (neg? extra)
              (java.util.Arrays/copyOf buf total)
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
          (let [clen   (some-> (get-in request [:headers "content-length"])
                                (Long/parseLong))
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
                        (when-not (ip-in-cidrs? candidate trusted-cidrs)
                          candidate))
                      chain)))
            remote)))))

(defn wrap-trusted-proxy-ip
  "Attach `:cauth/client-ip` to the request. Configuration:
     :trusted-cidrs — coll of [lo hi] ranges (see `parse-trusted-cidrs`)
     :ip-header     — the header to consult, e.g. \"x-forwarded-for\""
  [handler {:keys [trusted-cidrs ip-header] :or {ip-header "x-forwarded-for"}}]
  (fn [request]
    (let [ip (extract-client-ip request trusted-cidrs ip-header)]
      (handler (assoc request :cauth/client-ip ip)))))
