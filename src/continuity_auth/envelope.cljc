(ns continuity-auth.envelope
  "Canonical signing-input codec for continuity-auth envelopes.

  This namespace is the single source of truth for the binary signing input
  used by both the JVM server (verification path) and the ClojureScript client
  (signing path). It MUST produce byte-identical output on both platforms for
  any given input, or signatures will not verify.

  Wire format on the network is JSON; this namespace also provides the
  envelope↔wire codec so that fields originally given as byte arrays (nonce,
  digest, signature, etc.) round-trip via base64url.

  ============================================================================
  Signing input layout (binary, length-prefixed, big-endian uint32 lengths):

      \"FPL2\\n\"                          ; literal version tag, 5 bytes
      uint32-BE(len) || method-utf8       ; e.g. \"POST\"
      uint32-BE(len) || path-utf8         ; pathname + canonical query string
      uint32-BE(len) || body-sha256       ; 32 raw bytes (BLAKE2/SHA not allowed
                                            here — fixed to SHA-256 of the body
                                            on the wire; empty body → SHA-256(\"\"))
      uint32-BE(len) || ts-iso8601-utf8   ; e.g. \"2026-05-24T12:34:56.789Z\"
      uint32-BE(len) || nonce             ; 16 raw bytes
      uint32-BE(len) || fp-digest         ; 32 raw bytes (BLAKE2s of fp signals)
      uint32-BE(len) || host-user-id-utf8 ; empty string allowed (len=0)
      uint32-BE(len) || key-id            ; 32 raw bytes (BLAKE2s of pubkey)

  Field ordering is fixed; LENs are uint32 big-endian. The version tag prevents
  any future reuse from accidentally signing-compatible with v1.

  No JSON canonicalization is involved in the signed bytes — that route has
  too many footguns (Unicode normalization, number formatting, key ordering,
  whitespace). Length-prefixed binary removes all of them.")

;; -- platform shims --------------------------------------------------------

(def ^:const version-tag-str
  "Wire+canonical version tag. Bumped from FPL1 to FPL2 on 2026-05-25 in
  conjunction with the route-binding tightening on control endpoints; old
  envelopes signed under FPL1 will not verify against the FPL2 server.
  The cljs client always emits the current tag."
  "FPL2\n")

(def ^:const body-sha256-len 32)
(def ^:const nonce-len       16)
(def ^:const fp-digest-len   32)
(def ^:const key-id-len      32)

(def ^:const max-method-len      16)
(def ^:const max-path-len        4096)
(def ^:const max-host-user-id    256)
(def ^:const max-ts-len          40)

#?(:clj
   (defn utf8-encode
     "Encode a Clojure string to a byte array using UTF-8."
     ^bytes [^String s]
     (when (some? s)
       (.getBytes s "UTF-8")))
   :cljs
   (defn utf8-encode
     "Encode a JS string to a Uint8Array using UTF-8."
     [s]
     (when (some? s)
       (.encode (js/TextEncoder.) s))))

#?(:clj
   (defn byte-array-of
     "Allocate a JVM byte array of the given length."
     ^bytes [n]
     (byte-array n))
   :cljs
   (defn byte-array-of
     "Allocate a Uint8Array of the given length."
     [n]
     (js/Uint8Array. n)))

#?(:clj
   (defn ba-length
     "Length of a platform byte array."
     [ba]
     (alength ^bytes ba))
   :cljs
   (defn ba-length
     [ba]
     (.-length ba)))

#?(:clj
   (defn ba-get
     "Read byte at index as unsigned int (0..255)."
     [ba i]
     (bit-and 0xff (aget ^bytes ba i)))
   :cljs
   (defn ba-get
     [ba i]
     (aget ba i)))

#?(:clj
   (defn ba-set!
     "Set byte at index. v must be in 0..255."
     [ba i v]
     (aset-byte ^bytes ba i (unchecked-byte v)))
   :cljs
   (defn ba-set!
     [ba i v]
     (aset ba i (bit-and v 0xff))))

#?(:clj
   (defn ba-copy!
     "Copy src[s-off..s-off+n) into dst[d-off..)."
     [src s-off dst d-off n]
     (System/arraycopy ^bytes src (int s-off) ^bytes dst (int d-off) (int n)))
   :cljs
   (defn ba-copy!
     [src s-off dst d-off n]
     (dotimes [i n]
       (aset dst (+ d-off i) (aget src (+ s-off i))))))

(defn uint32-be!
  "Write the unsigned 32-bit integer n at dst[off..off+4) in big-endian order."
  [dst off n]
  (when (or (neg? n) (> n 4294967295))
    (throw (ex-info "uint32-be! out of range" {:n n})))
  (ba-set! dst (+ off 0) (bit-and 0xff (bit-shift-right n 24)))
  (ba-set! dst (+ off 1) (bit-and 0xff (bit-shift-right n 16)))
  (ba-set! dst (+ off 2) (bit-and 0xff (bit-shift-right n 8)))
  (ba-set! dst (+ off 3) (bit-and 0xff n)))

(defn uint32-be-read
  "Read a big-endian unsigned 32-bit integer from src starting at off."
  [src off]
  (+ (bit-shift-left (ba-get src off) 24)
     (bit-shift-left (ba-get src (+ off 1)) 16)
     (bit-shift-left (ba-get src (+ off 2)) 8)
     (ba-get src (+ off 3))))

(defn concat-bytes
  "Concatenate a sequence of byte arrays into a single byte array of the
  matching platform type."
  [byte-arrays]
  (let [total (reduce + 0 (map ba-length byte-arrays))
        out   (byte-array-of total)]
    (loop [arrs   byte-arrays
           offset 0]
      (if-let [a (first arrs)]
        (let [n (ba-length a)]
          (ba-copy! a 0 out offset n)
          (recur (rest arrs) (+ offset n)))
        out))))

;; -- canonical signing input -----------------------------------------------

(defn- prefixed
  "Return a 4-byte uint32-BE length prefix followed by the bytes themselves."
  [bs]
  (let [len    (ba-length bs)
        prefix (byte-array-of 4)]
    (uint32-be! prefix 0 len)
    [prefix bs]))

(defn- check-len!
  [field bs expected]
  (let [actual (ba-length bs)]
    (when-not (= actual expected)
      (throw (ex-info (str field " must be exactly " expected " bytes")
                      {:field    field
                       :expected expected
                       :actual   actual})))))

(defn- check-max-utf8!
  [field s max-bytes]
  (let [bs (utf8-encode s)]
    (when (> (ba-length bs) max-bytes)
      (throw (ex-info (str field " UTF-8 length exceeds maximum")
                      {:field field
                       :max   max-bytes
                       :actual (ba-length bs)})))
    bs))

(defn canonical-bytes
  "Build the canonical signing-input byte array for the given envelope fields.

  Required fields (all keys must be present; nil where empty allowed):
    :method        — string, e.g. \"POST\"
    :path          — string, e.g. \"/api/foo?bar=baz\" (canonicalize upstream)
    :body-sha256   — byte array, exactly 32 bytes
    :ts            — ISO-8601 timestamp string
    :nonce         — byte array, exactly 16 bytes
    :fp-digest     — byte array, exactly 32 bytes
    :host-user-id  — string or nil/empty (empty allowed)
    :key-id        — byte array, exactly 32 bytes"
  [{:keys [method path body-sha256 ts nonce fp-digest host-user-id key-id]}]
  (let [method-b      (check-max-utf8! :method method max-method-len)
        path-b        (check-max-utf8! :path path max-path-len)
        ts-b          (check-max-utf8! :ts ts max-ts-len)
        host-id-b     (check-max-utf8! :host-user-id (or host-user-id "") max-host-user-id)
        _             (check-len! :body-sha256 body-sha256 body-sha256-len)
        _             (check-len! :nonce nonce nonce-len)
        _             (check-len! :fp-digest fp-digest fp-digest-len)
        _             (check-len! :key-id key-id key-id-len)
        version       (utf8-encode version-tag-str)]
    (concat-bytes
     (concat [version]
             (prefixed method-b)
             (prefixed path-b)
             (prefixed body-sha256)
             (prefixed ts-b)
             (prefixed nonce)
             (prefixed fp-digest)
             (prefixed host-id-b)
             (prefixed key-id)))))

;; -- base64url codec (platform shims) --------------------------------------

#?(:clj
   (defn b64url-encode
     ^String [bs]
     (.encodeToString (.withoutPadding (java.util.Base64/getUrlEncoder)) ^bytes bs))
   :cljs
   (defn b64url-encode
     [bs]
     (let [s (-> (apply js/String.fromCharCode (array-seq bs))
                 (js/btoa))]
       (-> s
           (.replace (js/RegExp. "\\+" "g") "-")
           (.replace (js/RegExp. "/" "g") "_")
           (.replace (js/RegExp. "=+$") "")))))

#?(:clj
   (defn b64url-decode
     ^bytes [^String s]
     ;; Strict variant — strict decoder rejects unexpected padding and chars.
     (.decode (java.util.Base64/getUrlDecoder) s))
   :cljs
   (defn b64url-decode
     [s]
     (let [s (-> s
                 (.replace (js/RegExp. "-" "g") "+")
                 (.replace (js/RegExp. "_" "g") "/"))
           pad-needed (mod (- 4 (mod (.-length s) 4)) 4)
           padded (str s (apply str (repeat pad-needed "=")))
           raw    (js/atob padded)
           n      (.-length raw)
           out    (js/Uint8Array. n)]
       (dotimes [i n] (aset out i (.charCodeAt raw i)))
       out)))

;; -- intent strings for control-endpoint route binding -------------------

(defn rotate-key-intent-utf8
  "UTF-8 bytes of the rotate-key intent string. The client signs an
  envelope whose `:body-sha256` is `sha256(this)`; the server verifies
  by reconstructing from `(new-pubkey-bytes, new-alg)` in the request
  payload. Binding the signature to the new key prevents an attacker
  who captured any other envelope from this user from re-purposing it
  to install their own key.

  Shape: `\"<b64url(new-pubkey-bytes)>:<name(new-alg)>\"`.

  Producer: cljs client (rotate-key signer). Consumer: server
  `handlers/rotate-key`. Contract: byte-identical on both platforms."
  [^bytes new-pubkey-bytes new-alg]
  (utf8-encode (str (b64url-encode new-pubkey-bytes) ":" (name new-alg))))

;; -- envelope ↔ wire --------------------------------------------------------

(def required-envelope-keys
  #{:method :path :body-sha256 :ts :nonce :fp-digest :key-id})

(defn validate
  "Throw if `env` is structurally invalid. Returns env on success."
  [env]
  (doseq [k required-envelope-keys]
    (when (nil? (get env k))
      (throw (ex-info (str "missing required envelope key " k)
                      {:key k}))))
  (check-len! :body-sha256 (:body-sha256 env) body-sha256-len)
  (check-len! :nonce       (:nonce env)       nonce-len)
  (check-len! :fp-digest   (:fp-digest env)   fp-digest-len)
  (check-len! :key-id      (:key-id env)      key-id-len)
  (check-max-utf8! :method       (:method env)               max-method-len)
  (check-max-utf8! :path         (:path env)                 max-path-len)
  (check-max-utf8! :ts           (:ts env)                   max-ts-len)
  (check-max-utf8! :host-user-id (or (:host-user-id env) "") max-host-user-id)
  env)

(defn envelope->wire
  "Convert an envelope map (with byte-array fields) into a JSON-safe map
  with base64url strings."
  [{:keys [method path body-sha256 ts nonce fp-digest host-user-id
           key-id alg signature]
    :as env}]
  (validate env)
  (cond-> {:v          version-tag-str
           :method     method
           :path       path
           :body_sha   (b64url-encode body-sha256)
           :ts         ts
           :nonce      (b64url-encode nonce)
           :fp         (b64url-encode fp-digest)
           :key_id     (b64url-encode key-id)}
    host-user-id          (assoc :host_user_id host-user-id)
    alg                   (assoc :alg (name alg))
    signature             (assoc :sig (b64url-encode signature))))

(defn wire->envelope
  "Parse a wire-format map back into an envelope with byte-array fields.

  The wire must carry an explicit `:v` matching `version-tag-str`. We do
  NOT silently accept envelopes without `:v` — that would let a future
  endpoint that reads `:method/:path/:body-sha256` directly from the wire
  forget to re-derive the canonical bytes and accept any version."
  [{:keys [v method path body_sha ts nonce fp key_id host_user_id alg sig]}]
  (when (nil? v)
    (throw (ex-info "envelope missing version tag" {:expected version-tag-str})))
  (when (not= v version-tag-str)
    (throw (ex-info "envelope version mismatch" {:got v :expected version-tag-str})))
  (let [env (cond-> {:method        method
                     :path          path
                     :body-sha256   (b64url-decode body_sha)
                     :ts            ts
                     :nonce         (b64url-decode nonce)
                     :fp-digest     (b64url-decode fp)
                     :key-id        (b64url-decode key_id)}
              host_user_id (assoc :host-user-id host_user_id)
              alg          (assoc :alg (keyword alg))
              sig          (assoc :signature (b64url-decode sig)))]
    (validate env)
    env))
