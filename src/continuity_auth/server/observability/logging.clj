(ns continuity-auth.server.observability.logging
  "Structured JSON event logging via mu/log.

  Every /verify, /bootstrap, /rotate-key, /revoke-key, /link-account
  invocation should emit one structured event with these fields:
    :event-name    — keyword, e.g. :cauth/verify-completed
    :outcome       — :ok | :throttled | :forbidden | :unauthorized | :replay
    :identity-ref  — uuid string or nil
    :tier          — keyword or nil
    :latency-ms    — long
    :request-id    — opaque correlation id

  mu/log publishers (console, file, OTLP) are configured at startup."
  (:require
   [com.brunobonacci.mulog :as mu]))

(defn start-publishers!
  "Initialize mu/log publishers. Returns a stop function.

  In v1 we default to a console JSON publisher; production should add
  the host's chosen sink (e.g., file/Elasticsearch/OTLP). Returns the
  stop function returned by `mu/start-publisher!`."
  [{:keys [type] :as cfg}]
  (mu/start-publisher!
   (merge {:type :console-json
           :transform identity}
          (when (some? type) cfg))))

(defmacro log!
  "Emit a structured event. Use this from inside a handler to record
  outcome + telemetry; mu/log handles JSON encoding and dispatch.

  `event-name` is a namespaced keyword like :cauth/verify-completed.
  `pairs` is an even-arity sequence of key/value pairs."
  [event-name & pairs]
  `(mu/log ~event-name ~@pairs))

(defn with-context*
  "Macro-style helper. Wraps `body` in mu/log's with-context to attach
  shared fields (request-id, route, etc.) to all log events emitted
  inside."
  [ctx body-fn]
  (mu/with-context ctx
    (body-fn)))
