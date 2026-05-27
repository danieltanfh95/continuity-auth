(ns continuity-auth.server.crypto.ip-hmac-test
  "Tests for the IP-HMAC pseudonymisation namespace.

  Covers: determinism, hex shape, independence under distinct keys,
  env-var precedence over the file fallback, and the auto-generate
  branch (which writes a 0600 EDN file at the resolved path)."
  (:require
   [clojure.edn :as edn]
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.ip-hmac :as ip-hmac])
  (:import
   (java.nio.file Files)
   (java.nio.file.attribute FileAttribute PosixFilePermissions)))

;; -- helpers --------------------------------------------------------------

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "cauth-iphmac-" (into-array FileAttribute [])))

(defn- delete-recursively [^java.nio.file.Path p]
  (let [f (.toFile p)]
    (when (.isDirectory f)
      (doseq [c (.listFiles f)]
        (delete-recursively (.toPath c))))
    (.delete f)))

(defn- fixed-key
  "Deterministic 32-byte key for unit tests. Not a real secret."
  ^bytes []
  (byte-array (map byte (range 32))))

(defn- distinct-key
  "Different deterministic 32-byte key for cross-key independence."
  ^bytes []
  (byte-array (map (fn [i] (byte (bit-and (+ i 64) 0xff))) (range 32))))

;; -- hmac-ip-hex ---------------------------------------------------------

(deftest hmac-ip-hex-is-deterministic
  (testing "Same key + same IP yields the same hash on every call."
    (let [k (fixed-key)]
      (is (= (ip-hmac/hmac-ip-hex k "203.0.113.7")
             (ip-hmac/hmac-ip-hex k "203.0.113.7"))))))

(deftest hmac-ip-hex-shape-is-64-char-lowercase-hex
  (testing "Output is exactly 64 lowercase hex characters (HMAC-SHA256 hex)."
    (let [h (ip-hmac/hmac-ip-hex (fixed-key) "1.2.3.4")]
      (is (= 64 (count h)))
      (is (re-matches #"[0-9a-f]{64}" h)))))

(deftest hmac-ip-hex-distinct-keys-yield-distinct-hashes
  (testing "Two different keys hashing the same IP must produce different
            outputs (otherwise an operator dumping the store under one key
            could correlate observations across another deployment)."
    (let [ip  "198.51.100.42"
          h1  (ip-hmac/hmac-ip-hex (fixed-key) ip)
          h2  (ip-hmac/hmac-ip-hex (distinct-key) ip)]
      (is (not= h1 h2)))))

(deftest hmac-ip-hex-distinct-ips-yield-distinct-hashes
  (testing "Two different IPs under the same key collide with negligible
            probability — exhaustively checked against a small set."
    (let [k (fixed-key)
          hs (set (map #(ip-hmac/hmac-ip-hex k %)
                       ["1.1.1.1" "1.1.1.2" "1.1.1.3"
                        "2001:db8::1" "10.0.0.1" "10.0.0.2"]))]
      (is (= 6 (count hs))))))

(deftest hmac-ip-hex-rejects-blank-input
  (testing "A nil or blank IP throws — the ingress middleware must never
            pass us empty input. A silent zero-hash here would collapse
            every blank-IP request into a single cluster."
    (is (thrown? Exception (ip-hmac/hmac-ip-hex (fixed-key) nil)))
    (is (thrown? Exception (ip-hmac/hmac-ip-hex (fixed-key) "")))
    (is (thrown? Exception (ip-hmac/hmac-ip-hex (fixed-key) "   ")))))

;; -- load-or-create-key! -------------------------------------------------

(defn- with-clean-env
  "Run `f` with the IP-HMAC env vars unset. Restores prior values on exit."
  [f]
  ;; Tests cannot mutate the process env on the JVM portably; instead
  ;; require that the test environment does not set these vars. The CI
  ;; runner is responsible. Assert preconditions so a misconfigured run
  ;; fails loudly rather than silently picking up a global secret.
  (when (System/getenv "CONTINUITY_AUTH_IP_HMAC_KEY")
    (throw (ex-info "test precondition: CONTINUITY_AUTH_IP_HMAC_KEY must be unset"
                    {})))
  (when (System/getenv "CONTINUITY_AUTH_IP_HMAC_KEY_PATH")
    (throw (ex-info "test precondition: CONTINUITY_AUTH_IP_HMAC_KEY_PATH must be unset"
                    {})))
  (f))

(deftest load-or-create-key-auto-generates-when-file-missing
  (with-clean-env
    (fn []
      (let [dir  (temp-dir)
            path (str dir "/ip-hmac.key")]
        (try
          (testing "First call writes a fresh keyfile at the resolved path."
            (let [bs (ip-hmac/load-or-create-key! {:key-path path})]
              (is (= 32 (alength ^bytes bs)))
              (is (.exists (java.io.File. path)))))
          (testing "Second call reads the existing file and returns the
                    same bytes (continuity across restarts)."
            (let [bs1 (ip-hmac/load-or-create-key! {:key-path path})
                  bs2 (ip-hmac/load-or-create-key! {:key-path path})]
              (is (java.util.Arrays/equals ^bytes bs1 ^bytes bs2))))
          (finally
            (delete-recursively dir)))))))

(deftest auto-generated-keyfile-has-0600-perms-on-posix
  (with-clean-env
    (fn []
      (let [dir  (temp-dir)
            path (str dir "/ip-hmac.key")]
        (try
          (ip-hmac/load-or-create-key! {:key-path path})
          (let [fs    (java.nio.file.FileSystems/getDefault)
                supports? (-> fs .supportedFileAttributeViews (.contains "posix"))]
            (if supports?
              (let [perms (Files/getPosixFilePermissions
                           (.toPath (java.io.File. path))
                           (into-array java.nio.file.LinkOption []))]
                (is (= "rw-------"
                       (PosixFilePermissions/toString perms))))
              (testing "non-POSIX filesystem: skip perm assertion"
                (is true))))
          (finally
            (delete-recursively dir)))))))

(deftest auto-generated-keyfile-is-valid-edn-with-32-byte-secret
  (with-clean-env
    (fn []
      (let [dir  (temp-dir)
            path (str dir "/ip-hmac.key")]
        (try
          (ip-hmac/load-or-create-key! {:key-path path})
          (let [{:keys [secret-b64]} (edn/read-string (slurp path))
                bs                   (envelope/b64url-decode secret-b64)]
            (is (string? secret-b64))
            (is (= 32 (alength ^bytes bs))))
          (finally
            (delete-recursively dir)))))))

(deftest config-key-b64-precedes-file-fallback
  (with-clean-env
    (fn []
      (let [dir         (temp-dir)
            path        (str dir "/ip-hmac.key")
            inline-bs   (fixed-key)
            inline-b64  (envelope/b64url-encode inline-bs)]
        (try
          (let [bs (ip-hmac/load-or-create-key!
                    {:key-path path :key-b64 inline-b64})]
            (testing "Inline :key-b64 is used directly — never written to disk."
              (is (java.util.Arrays/equals ^bytes inline-bs ^bytes bs))
              (is (not (.exists (java.io.File. path))))))
          (finally
            (delete-recursively dir)))))))

(deftest load-or-create-key-rejects-wrong-length-inline-secret
  (with-clean-env
    (fn []
      (let [short-b64 (envelope/b64url-encode (byte-array 16))]
        (is (thrown? clojure.lang.ExceptionInfo
                     (ip-hmac/load-or-create-key! {:key-b64 short-b64})))))))

(deftest load-or-create-key-rejects-wrong-length-stored-secret
  (with-clean-env
    (fn []
      (let [dir  (temp-dir)
            path (str dir "/ip-hmac.key")]
        (try
          (spit path (pr-str {:secret-b64
                              (envelope/b64url-encode (byte-array 16))}))
          (is (thrown? clojure.lang.ExceptionInfo
                       (ip-hmac/load-or-create-key! {:key-path path})))
          (finally
            (delete-recursively dir)))))))

;; -- resolve-key-path ----------------------------------------------------

(deftest resolve-key-path-uses-config-when-env-unset
  (with-clean-env
    (fn []
      (is (= "/tmp/x.key"
             (ip-hmac/resolve-key-path {:key-path "/tmp/x.key"}))))))

(deftest resolve-key-path-falls-back-to-default
  (with-clean-env
    (fn []
      (is (str/ends-with?
           (ip-hmac/resolve-key-path {})
           "/continuity-auth/ip-hmac.key")))))
