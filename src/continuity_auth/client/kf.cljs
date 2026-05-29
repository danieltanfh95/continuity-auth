(ns continuity-auth.client.kf
  "Knowledge-factor key derivation for identity recovery (v6).

  A knowledge factor is a secret only the user knows (a password, or a
  generated high-entropy phrase). From it we derive an Ed25519 keypair the
  server can store a *verifier* for and challenge against — the secret
  itself never leaves the browser.

      salt = blake2s(\"cauth-kf-salt-v1\" ‖ uuid-bytes)   ; 32 bytes
      seed = Argon2id(secret-utf8, salt)                  ; 32 bytes, t=3 m=64MiB p=1
      kf-keypair = Ed25519(priv = seed)

  The salt is derived from the identity UUID (the recovery locator the user
  writes down as a BIP-39 phrase), not stored — UUIDs are unique, and the
  client always holds the locator at derive time. This makes derivation a
  single step with no salt round-trip.

  These three primitives are NOT available in SubtleCrypto, so this is the
  one place the client links audited third-party crypto (paulmillr's
  @noble/@scure stack: pure-JS, dependency-free, byte-for-byte matched
  against the JVM BouncyCastle reference in
  `continuity-auth.server.crypto.kf-test`). The device key remains a
  non-extractable native WebCrypto key — see `client.crypto`. KF derivation
  is a COLD path (set-verifier / recover only), never the hot verify path."
  (:require
   ["@noble/ed25519" :as ed]
   ["@noble/hashes/argon2" :refer (argon2id)]
   ["@noble/hashes/blake2s" :refer (blake2s)]
   ["@scure/bip39" :as bip39]
   ["@scure/bip39/wordlists/english" :refer (wordlist)]
   [promesa.core :as p]))

(def ^:private salt-tag "cauth-kf-salt-v1")

;; Fixed :argon2id-v1 protocol constants (mirrored by the JVM reference and
;; stored as :identity/kf-kdf for future versioning).
(def ^:private argon2-opts #js {:t 3 :m 65536 :p 1 :dkLen 32})

(defn- utf8 ^js [^String s]
  (.encode (js/TextEncoder.) s))

(defn- uuid->bytes
  "Parse a canonical UUID string into its 16 big-endian bytes (identical to
  the JVM `ByteBuffer.putLong(msb).putLong(lsb)` encoding the reference
  salt uses)."
  ^js [^String identity-ref]
  (let [hex (.replaceAll identity-ref "-" "")
        out (js/Uint8Array. 16)]
    (dotimes [i 16]
      (aset out i (js/parseInt (.substr hex (* 2 i) 2) 16)))
    out))

(defn- kf-salt
  "salt = blake2s(salt-tag ‖ uuid-bytes), 32-byte output."
  ^js [^String identity-ref]
  (let [tag (utf8 salt-tag)
        ub  (uuid->bytes identity-ref)
        cat (js/Uint8Array. (+ (.-length tag) 16))]
    (.set cat tag 0)
    (.set cat ub (.-length tag))
    (blake2s cat #js {:dkLen 32})))

(defn derive-kf-keypair
  "Derive the knowledge-factor Ed25519 keypair from `secret` (a string) and
  `identity-ref` (the identity UUID string). Returns a promise resolving to
  `{:priv <Uint8Array 32 seed> :pub <Uint8Array 32 pubkey>}`. Deterministic
  for fixed (secret, identity-ref)."
  [^String secret ^String identity-ref]
  (let [seed (argon2id (utf8 secret) (kf-salt identity-ref) argon2-opts)]
    (p/let [pub (ed/getPublicKeyAsync seed)]
      {:priv seed :pub pub})))

(defn kf-sign
  "Sign `msg` (a Uint8Array — typically the kf-challenge bytes) with the
  derived KF private seed. Returns a promise resolving to a 64-byte
  Uint8Array Ed25519 signature."
  [^js seed ^js msg]
  (ed/signAsync msg seed))

;; -- recovery locator ↔ BIP-39 mnemonic -----------------------------------

(defn mnemonic-of
  "Encode the 16-byte identity UUID as a 12-word BIP-39 English mnemonic —
  the recovery phrase the user writes down. Pure client-side; the server
  always works in UUIDs."
  ^String [^String identity-ref]
  (bip39/entropyToMnemonic (uuid->bytes identity-ref) wordlist))

(defn- bytes->uuid ^String [^js b]
  (let [hex (->> (array-seq b)
                 (map (fn [x] (.padStart (.toString (bit-and x 0xff) 16) 2 "0")))
                 (apply str))]
    (str (subs hex 0 8) "-" (subs hex 8 12) "-" (subs hex 12 16) "-"
         (subs hex 16 20) "-" (subs hex 20 32))))

(defn uuid-of
  "Decode a 12-word BIP-39 mnemonic back to the identity UUID string.
  Throws if the mnemonic is invalid (bad word or checksum)."
  ^String [^String mnemonic]
  (when-not (bip39/validateMnemonic mnemonic wordlist)
    (throw (ex-info "invalid recovery phrase" {})))
  (bytes->uuid (bip39/mnemonicToEntropy mnemonic wordlist)))
