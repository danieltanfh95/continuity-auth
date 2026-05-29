(ns continuity-auth.server.crypto.biscuit-token-test
  "Tests for the Biscuit capability-token namespace.

  Covers: deterministic keypair-from-seed, mint→offline-verify round-trip,
  authority facts (identity/tier/audience) assertable by a host authorizer,
  expiry enforced offline, wrong-root-pubkey rejection, fact-injection guard,
  and the root-seed keystore loader (auto-generate 0600 file, file
  continuity, inline-b64 precedence, length validation, purpose separation)."
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.biscuit-token :as bt])
  (:import
   (com.clevercloud.biscuit.crypto KeyPair)
   (com.clevercloud.biscuit.token Biscuit)
   (java.nio.file Files)
   (java.nio.file.attribute FileAttribute PosixFilePermissions)
   (java.time Instant)))

;; -- helpers --------------------------------------------------------------

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "cauth-biscuit-" (into-array FileAttribute [])))

(defn- delete-recursively [^java.nio.file.Path p]
  (let [f (.toFile p)]
    (when (.isDirectory f)
      (doseq [c (.listFiles f)]
        (delete-recursively (.toPath c))))
    (.delete f)))

(defn- fixed-seed ^bytes []
  (byte-array (map unchecked-byte (range 32))))

(defn- distinct-seed ^bytes []
  (byte-array (map (fn [i] (unchecked-byte (+ i 64))) (range 32))))

(defn- token-allows?
  "Verify `token` under root `kp` with set_time(now), returning true iff it
  authorizes under `policy`. Mirrors a host's offline check; any failure
  (bad sig / expired / unsatisfied policy) returns false."
  [^KeyPair kp ^String token ^String policy]
  (try
    (let [b (Biscuit/from_b64url token (.public_key kp))
          a (doto (.authorizer b) (.set_time) (.add_policy policy))]
      (.authorize a)
      true)
    (catch Exception _ false)))

(defn- mint-now+ [^KeyPair kp tier audience ttl-secs]
  (bt/mint kp {:identity-ref (str (random-uuid))
               :tier         tier
               :audience     audience
               :expires-at   (.plusSeconds (Instant/now) ttl-secs)}))

;; -- keypair / pubkey -----------------------------------------------------

(deftest keypair-from-seed-is-deterministic
  (testing "the same 32-byte seed yields the same root public key; a
            different seed yields a different one (cross-device parity rests
            on this)."
    (let [hex1 (bt/root-public-key-hex (bt/keypair-from-seed (fixed-seed)))
          hex2 (bt/root-public-key-hex (bt/keypair-from-seed (fixed-seed)))
          hex3 (bt/root-public-key-hex (bt/keypair-from-seed (distinct-seed)))]
      (is (= hex1 hex2))
      (is (not= hex1 hex3))
      (is (= 64 (count hex1)) "Ed25519 pubkey is 32 bytes = 64 hex chars"))))

;; -- mint / verify --------------------------------------------------------

(deftest mint-round-trips-and-asserts-claims
  (testing "a minted token verifies offline with the root pubkey and carries
            the identity/tier/audience facts the host can authorize against."
    (let [kp  (bt/keypair-from-seed (fixed-seed))
          tok (mint-now+ kp :tracked "my-app" 300)]
      (is (string? tok))
      (is (token-allows? kp tok "allow if tier(\"tracked\")"))
      (is (token-allows? kp tok "allow if audience(\"my-app\")"))
      (is (not (token-allows? kp tok "allow if tier(\"anonymous\")"))
          "the token does not assert a tier it was not minted with")
      (is (not (token-allows? kp tok "allow if audience(\"other\")"))))))

(deftest expired-token-is-denied-offline
  (testing "an expired token fails the authority TTL check at verify time —
            short TTL is the revocation model."
    (let [kp  (bt/keypair-from-seed (fixed-seed))
          tok (mint-now+ kp :tracked "my-app" -60)]   ; already expired
      (is (not (token-allows? kp tok "allow if tier(\"tracked\")"))))))

(deftest wrong-root-pubkey-is-rejected
  (testing "a token minted under one root key does not verify under a
            different published pubkey (forgery / key-confusion blocked)."
    (let [kp    (bt/keypair-from-seed (fixed-seed))
          other (bt/keypair-from-seed (distinct-seed))
          tok   (mint-now+ kp :tracked "my-app" 300)]
      (is (not (token-allows? other tok "allow if tier(\"tracked\")"))))))

(deftest mint-rejects-fact-injection
  (testing "a value containing a quote/newline that would break out of a
            Datalog term is refused, not silently signed."
    (let [kp (bt/keypair-from-seed (fixed-seed))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (bt/mint kp {:identity-ref "x\") or admin(\"y"
                                :tier         :tracked
                                :audience     "my-app"
                                :expires-at   (.plusSeconds (Instant/now) 300)})))
      (is (thrown? clojure.lang.ExceptionInfo
                   (bt/mint kp {:identity-ref (str (random-uuid))
                                :tier         :tracked
                                :audience     "evil\nfact"
                                :expires-at   (.plusSeconds (Instant/now) 300)}))))))

;; -- load-or-create-seed! -------------------------------------------------

(defn- with-clean-env
  "Run `f` with the biscuit-root env vars unset, asserting the precondition
  so a misconfigured CI run fails loudly rather than picking up a global key."
  [f]
  (when (System/getenv "CONTINUITY_AUTH_BISCUIT_ROOT_KEY")
    (throw (ex-info "test precondition: CONTINUITY_AUTH_BISCUIT_ROOT_KEY must be unset" {})))
  (when (System/getenv "CONTINUITY_AUTH_BISCUIT_ROOT_KEY_PATH")
    (throw (ex-info "test precondition: CONTINUITY_AUTH_BISCUIT_ROOT_KEY_PATH must be unset" {})))
  (f))

(deftest load-or-create-seed-auto-generates-and-persists
  (with-clean-env
    (fn []
      (let [dir  (temp-dir)
            path (str dir "/biscuit-root.key")]
        (try
          (testing "first call writes a fresh 32-byte seed file."
            (let [bs (bt/load-or-create-seed! {:key-path path})]
              (is (= 32 (alength ^bytes bs)))
              (is (.exists (java.io.File. path)))))
          (testing "subsequent calls return the same seed (restart continuity =
                    stable published pubkey)."
            (let [bs1 (bt/load-or-create-seed! {:key-path path})
                  bs2 (bt/load-or-create-seed! {:key-path path})]
              (is (java.util.Arrays/equals ^bytes bs1 ^bytes bs2))
              (is (= (bt/root-public-key-hex (bt/keypair-from-seed bs1))
                     (bt/root-public-key-hex (bt/keypair-from-seed bs2))))))
          (finally
            (delete-recursively dir)))))))

(deftest auto-generated-seedfile-has-0600-perms-on-posix
  (with-clean-env
    (fn []
      (let [dir  (temp-dir)
            path (str dir "/biscuit-root.key")]
        (try
          (bt/load-or-create-seed! {:key-path path})
          (let [fs        (java.nio.file.FileSystems/getDefault)
                supports? (-> fs .supportedFileAttributeViews (.contains "posix"))]
            (if supports?
              (let [perms (Files/getPosixFilePermissions
                           (.toPath (java.io.File. path))
                           (into-array java.nio.file.LinkOption []))]
                (is (= "rw-------" (PosixFilePermissions/toString perms))))
              (testing "non-POSIX filesystem: skip perm assertion"
                (is true))))
          (finally
            (delete-recursively dir)))))))

(deftest config-key-b64-precedes-file-fallback
  (with-clean-env
    (fn []
      (let [dir        (temp-dir)
            path       (str dir "/biscuit-root.key")
            inline-bs  (fixed-seed)
            inline-b64 (envelope/b64url-encode inline-bs)]
        (try
          (let [bs (bt/load-or-create-seed! {:key-path path :key-b64 inline-b64})]
            (testing "inline :key-b64 is used directly — never written to disk."
              (is (java.util.Arrays/equals ^bytes inline-bs ^bytes bs))
              (is (not (.exists (java.io.File. path))))))
          (finally
            (delete-recursively dir)))))))

(deftest load-or-create-seed-rejects-wrong-length
  (with-clean-env
    (fn []
      (testing "an inline seed of the wrong length is refused."
        (is (thrown? clojure.lang.ExceptionInfo
                     (bt/load-or-create-seed!
                      {:key-b64 (envelope/b64url-encode (byte-array 16))}))))
      (testing "a stored seed of the wrong length is refused."
        (let [dir  (temp-dir)
              path (str dir "/biscuit-root.key")]
          (try
            (spit path (pr-str {:secret-b64 (envelope/b64url-encode (byte-array 16))}))
            (is (thrown? clojure.lang.ExceptionInfo
                         (bt/load-or-create-seed! {:key-path path})))
            (finally
              (delete-recursively dir))))))))

(deftest biscuit-root-default-path-is-distinct
  (with-clean-env
    (fn []
      (testing "the default biscuit-root path is distinct from ip-hmac/kf-wrap
                (purpose separation)."
        (is (str/ends-with? (bt/resolve-key-path {})
                            "/continuity-auth/biscuit-root.key"))))))
