(ns continuity-auth.server.http.handlers.token-pubkey
  "GET /v1/token-pubkey — publish the Biscuit root public key.

  Public material by design: a host fetches and pins this key so it can
  verify issued capability tokens OFFLINE (see `handlers/issue-token`).
  Unauthenticated; cacheable. The private half never leaves the server."
  (:require
   [continuity-auth.server.crypto.biscuit-token :as bt]))

(defn make-handler
  "deps: {:biscuit-token {:keypair <KeyPair> ...}}"
  [{:keys [biscuit-token]}]
  (when-not biscuit-token
    (throw (ex-info "token-pubkey/make-handler: missing :biscuit-token" {})))
  (let [hex (bt/root-public-key-hex (:keypair biscuit-token))]
    (fn [_request]
      {:status  200
       :headers {"Content-Type"  "application/json; charset=utf-8"
                 "Cache-Control" "public, max-age=3600"}
       :body    {:alg            "ed25519"
                 :public_key_hex hex}})))
