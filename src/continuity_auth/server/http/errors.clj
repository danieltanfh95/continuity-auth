(ns continuity-auth.server.http.errors
  "Uniform error model for HTTP responses.

  Every error response from every endpoint has the same shape:

      {\"ok\": false,
       \"retry_after_ms\": <long>,
       \"code\": \"E_<UPPER>\"}

  The `code` is a public-stable opaque token. We DO NOT disclose
  which check failed (signature vs replay vs malformed input) in the
  response body — that would create a differential side channel
  (cf. ontology §A.10). Codes are logged separately for ops.

  The mapping from internal exception types to error codes is centralized
  here. Use `throw-bad` etc. from handlers to abort cleanly."
  (:require
   [jsonista.core :as json]))

(def error-codes
  "Closed set of public-stable codes returned to clients."
  #{:E_BAD_REQUEST        ; 400 — malformed input, schema violation, decode failure
    :E_UNAUTHORIZED       ; 401 — signature / HMAC verify failure
    :E_FORBIDDEN          ; 403 — revoked pubkey, banned tier
    :E_NOT_FOUND          ; 404 — identity not found, etc.
    :E_REPLAY             ; 409 — duplicate nonce / idempotency replay
    :E_RATE               ; 429 — rate limit hit
    :E_CONFLICT           ; 409 — integrity error (orphan pubkey, etc.)
    :E_PAYLOAD_TOO_LARGE  ; 413 — request body exceeds configured limit
    :E_INTERNAL           ; 500 — unhandled exception
    :E_UNAVAILABLE})      ; 503 — DB unavailable etc.

(def code->status
  {:E_BAD_REQUEST       400
   :E_UNAUTHORIZED      401
   :E_FORBIDDEN         403
   :E_NOT_FOUND         404
   :E_CONFLICT          409
   :E_REPLAY            409
   :E_PAYLOAD_TOO_LARGE 413
   :E_RATE              429
   :E_INTERNAL          500
   :E_UNAVAILABLE       503})

(defn error-response
  "Build a Ring response map for `code` with optional `retry-after-ms`
  and an optional `extras` map merged into the JSON body. Use `extras`
  for additive, non-leaky context (e.g. `:priority_weight` on
  rate-limit denials), never for which-check-failed disclosure."
  ([code]
   (error-response code 0 nil))
  ([code retry-after-ms]
   (error-response code retry-after-ms nil))
  ([code retry-after-ms extras]
   {:pre [(contains? error-codes code)]}
   (let [ms (long retry-after-ms)
         ;; HTTP `Retry-After` is integer seconds and clients wait AT
         ;; LEAST that long. Use ceiling so a 1500 ms penalty reports as
         ;; "2", not "1" — under-reporting would let a polled client
         ;; retry inside the penalty window.
         secs (quot (+ ms 999) 1000)
         body (merge {:ok             false
                      :retry_after_ms ms
                      :code           (name code)}
                     (or extras {}))]
     {:status  (get code->status code 500)
      :headers {"Content-Type"  "application/json; charset=utf-8"
                "Cache-Control" "no-store"
                "Retry-After"   (str secs)}
      :body    (json/write-value-as-string body)})))

(defn fail!
  "Throw an ex-info that will be converted to an error response by the
  wrap-error middleware. The exception's `:cauth/error` key holds the
  error code; `:cauth/retry-after-ms` carries the optional retry value."
  ([code]            (fail! code 0 nil))
  ([code msg]        (fail! code 0 msg))
  ([code retry-ms msg]
   {:pre [(contains? error-codes code)]}
   (throw (ex-info (or msg (name code))
                   {:cauth/error          code
                    :cauth/retry-after-ms retry-ms}))))

(defn ex->response
  "Map an exception (or its ex-data) to a uniform error response."
  [^Throwable ex]
  (let [data (ex-data ex)
        code (or (:cauth/error data) :E_INTERNAL)
        rms  (or (:cauth/retry-after-ms data) 0)]
    (error-response code rms)))
