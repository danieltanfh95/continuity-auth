(ns continuity-auth.client.json
  "JSON read/write shim used by the bb-compatible client + admin CLI
  namespaces. Uses cheshire — bb ships it in the default binary and the
  JVM project picks it up as a transitive dep, so the same call sites
  work under both runtimes.

  The existing JVM server uses jsonista via `continuity-auth.server.*`;
  this shim deliberately does not touch that surface."
  (:require
   [cheshire.core :as cheshire]))

(defn ->json
  "Serialize a Clojure map/value to a JSON string. Keyword keys are
  encoded as their name."
  ^String [x]
  (cheshire/generate-string x))

(defn <-json
  "Parse a JSON string into a Clojure map. Top-level keys are coerced
  to keywords."
  [^String s]
  (cheshire/parse-string s keyword))
