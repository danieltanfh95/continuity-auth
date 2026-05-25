(ns continuity-auth.client.crypto
  "Web Crypto wrappers for continuity-auth's signing operations.

  Hard requirements:
    - The private key is created with `extractable: false`. It cannot be
      exported, period. Even if XSS runs in our origin, it can only USE
      the key (request signatures), not exfiltrate it.
    - All operations go through the native SubtleCrypto API. No
      third-party JS crypto libraries are loaded. (Compare: pdsa loads
      CryptoJS + elliptic.js from a CDN — supply-chain risk we
      deliberately avoid.)

  Public surface:
    generate-keypair   — async Ed25519 or P-256 keypair, non-extractable
    export-public      — async export of pubkey in canonical 'raw' form
    sign               — async signature over `bytes`
    sha256             — async SHA-256 of bytes
    thumbprint         — async 32-byte SHA-256 of canonical pubkey bytes"
  (:require
   [promesa.core :as p]
   [continuity-auth.crypto :as crypto]))

;; -- platform-native shims -------------------------------------------------

(defn- subtle []
  (or (some-> js/window .-crypto .-subtle)
      (throw (ex-info "SubtleCrypto unavailable" {}))))

(def alg->params
  {:ed25519 {:web-name "Ed25519"
             :usages   #js ["sign" "verify"]}
   :p256    {:web-name "ECDSA"
             :curve    "P-256"
             :hash     "SHA-256"
             :usages   #js ["sign" "verify"]}})

(defn- ->key-spec [alg]
  (case alg
    :ed25519 #js {:name "Ed25519"}
    :p256    #js {:name "ECDSA" :namedCurve "P-256"}))

(defn- ->sign-params [alg]
  (case alg
    :ed25519 #js {:name "Ed25519"}
    :p256    #js {:name "ECDSA" :hash #js {:name "SHA-256"}}))

;; -- key generation --------------------------------------------------------

(defn generate-keypair
  "Generate a non-extractable signing keypair for `alg`. Returns a
  promise resolving to {:private-key <CryptoKey>, :public-key <CryptoKey>}.

  The private key has `extractable: false` — neither this code nor any
  attacker JS in the same origin can read its bytes."
  [alg]
  (when-not (crypto/algorithm? alg)
    (throw (ex-info "unknown algorithm" {:alg alg})))
  (p/let [kp (.generateKey (subtle)
                            (->key-spec alg)
                            false                        ; extractable=false
                            (get-in alg->params [alg :usages]))]
    {:private-key (.-privateKey kp)
     :public-key  (.-publicKey  kp)}))

;; -- pubkey export ---------------------------------------------------------

(defn export-public
  "Export `public-key` (a CryptoKey) in the canonical 'raw' format that
  matches the JVM-side `:pubkey/bytes` shape (32 bytes for Ed25519,
  65 bytes uncompressed SEC1 for P-256).

  Returns a promise resolving to a Uint8Array."
  [public-key]
  (p/let [buf (.exportKey (subtle) "raw" public-key)]
    (js/Uint8Array. buf)))

;; -- signing ---------------------------------------------------------------

(defn sign
  "Sign `bytes` (a Uint8Array) with the given private CryptoKey using
  the algorithm `alg`. Returns a promise resolving to a 64-byte
  Uint8Array (raw R||S, NOT DER)."
  [alg private-key bytes]
  (p/let [buf (.sign (subtle) (->sign-params alg) private-key bytes)]
    (js/Uint8Array. buf)))

;; -- digest ----------------------------------------------------------------

(defn sha256
  "Return a promise resolving to the SHA-256 digest of `bytes` as a
  32-byte Uint8Array."
  [bytes]
  (p/let [buf (.digest (subtle) "SHA-256" bytes)]
    (js/Uint8Array. buf)))

(defn thumbprint
  "Convenience: 32-byte SHA-256 of canonical pubkey bytes. This is the
  :pubkey/id in the database and the :key-id field of the envelope."
  [canonical-pubkey-bytes]
  (sha256 canonical-pubkey-bytes))
