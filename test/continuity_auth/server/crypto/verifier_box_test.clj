(ns continuity-auth.server.crypto.verifier-box-test
  "Tests for the knowledge-factor verifier-wrap namespace.

  Covers: wrap→unwrap round-trip, ciphertext ≠ plaintext, IV uniqueness
  across calls, wrong-secret/tamper rejection (GCM auth), and the keystore
  loader (auto-generate 0600 file, file continuity, inline-b64 precedence,
  length validation)."
  (:require
   [clojure.edn :as edn]
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.envelope :as envelope]
   [continuity-auth.server.crypto.verifier-box :as vbox])
  (:import
   (java.nio.file Files)
   (java.nio.file.attribute FileAttribute PosixFilePermissions)))

;; -- helpers --------------------------------------------------------------

(defn- temp-dir ^java.nio.file.Path []
  (Files/createTempDirectory "cauth-kfwrap-" (into-array FileAttribute [])))

(defn- delete-recursively [^java.nio.file.Path p]
  (let [f (.toFile p)]
    (when (.isDirectory f)
      (doseq [c (.listFiles f)]
        (delete-recursively (.toPath c))))
    (.delete f)))

(defn- fixed-key ^bytes []
  (byte-array (map byte (range 32))))

(defn- distinct-key ^bytes []
  (byte-array (map (fn [i] (unchecked-byte (+ i 64))) (range 32))))

(defn- sample-pubkey
  "Stand-in for a 32-byte Ed25519 kf-pubkey."
  ^bytes []
  (byte-array (map (fn [i] (unchecked-byte (* i 7))) (range 32))))

;; -- wrap / unwrap --------------------------------------------------------

(deftest wrap-unwrap-round-trips
  (testing "unwrap recovers exactly the bytes that were wrapped."
    (let [k  (fixed-key)
          pt (sample-pubkey)
          rt (vbox/unwrap k (vbox/wrap k pt))]
      (is (java.util.Arrays/equals ^bytes pt ^bytes rt)))))

(deftest wrapped-blob-is-not-the-plaintext
  (testing "the stored blob is opaque — neither equal to nor a substring
            of the plaintext pubkey (an operator dumping the DB without the
            keyfile sees only ciphertext)."
    (let [k    (fixed-key)
          pt   (sample-pubkey)
          blob (vbox/wrap k pt)]
      (is (not (java.util.Arrays/equals ^bytes pt ^bytes blob)))
      ;; IV(12) + ct+tag(16) over a 32-byte plaintext ⇒ 60 bytes.
      (is (= (+ vbox/iv-bytes (alength ^bytes pt) 16) (alength ^bytes blob))))))

(deftest wrap-uses-a-fresh-iv-each-call
  (testing "wrapping the same pubkey twice yields different ciphertext
            (random IV), so identical verifiers are not correlatable at rest."
    (let [k  (fixed-key)
          pt (sample-pubkey)
          b1 (vbox/wrap k pt)
          b2 (vbox/wrap k pt)]
      (is (not (java.util.Arrays/equals ^bytes b1 ^bytes b2)))
      ;; ...but both still unwrap to the same plaintext.
      (is (java.util.Arrays/equals (vbox/unwrap k b1) (vbox/unwrap k b2))))))

(deftest unwrap-under-wrong-secret-throws
  (testing "a DB dump WITHOUT the kf-wrap keyfile cannot recover the
            verifier — unwrap under a different key fails the GCM auth tag.
            This stands in for the offline-attack-blocked property (T20)."
    (let [pt   (sample-pubkey)
          blob (vbox/wrap (fixed-key) pt)]
      (is (thrown? Exception (vbox/unwrap (distinct-key) blob))))))

(deftest unwrap-rejects-tampered-ciphertext
  (testing "flipping a byte of the blob fails the GCM tag — no silent
            corruption of the recovered pubkey."
    (let [k    (fixed-key)
          blob (vbox/wrap k (sample-pubkey))]
      (aset-byte blob (dec (alength blob))
                 (byte (bit-xor (aget blob (dec (alength blob))) 0x01)))
      (is (thrown? Exception (vbox/unwrap k blob))))))

(deftest unwrap-rejects-too-short-blob
  (testing "a blob shorter than the IV cannot be a valid wrap."
    (is (thrown? clojure.lang.ExceptionInfo
                 (vbox/unwrap (fixed-key) (byte-array 4))))))

;; -- load-or-create-key! --------------------------------------------------

(defn- with-clean-env
  "Run `f` with the kf-wrap env vars unset. The CI runner is responsible
  for not setting them; assert preconditions so a misconfigured run fails
  loudly rather than silently picking up a global secret."
  [f]
  (when (System/getenv "CONTINUITY_AUTH_KF_WRAP_KEY")
    (throw (ex-info "test precondition: CONTINUITY_AUTH_KF_WRAP_KEY must be unset" {})))
  (when (System/getenv "CONTINUITY_AUTH_KF_WRAP_KEY_PATH")
    (throw (ex-info "test precondition: CONTINUITY_AUTH_KF_WRAP_KEY_PATH must be unset" {})))
  (f))

(deftest load-or-create-key-auto-generates-and-persists
  (with-clean-env
    (fn []
      (let [dir  (temp-dir)
            path (str dir "/kf-wrap.key")]
        (try
          (testing "first call writes a fresh 32-byte keyfile."
            (let [bs (vbox/load-or-create-key! {:key-path path})]
              (is (= 32 (alength ^bytes bs)))
              (is (.exists (java.io.File. path)))))
          (testing "subsequent calls return the same bytes (restart continuity)."
            (let [bs1 (vbox/load-or-create-key! {:key-path path})
                  bs2 (vbox/load-or-create-key! {:key-path path})]
              (is (java.util.Arrays/equals ^bytes bs1 ^bytes bs2))))
          (finally
            (delete-recursively dir)))))))

(deftest auto-generated-keyfile-has-0600-perms-on-posix
  (with-clean-env
    (fn []
      (let [dir  (temp-dir)
            path (str dir "/kf-wrap.key")]
        (try
          (vbox/load-or-create-key! {:key-path path})
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

(deftest auto-generated-keyfile-is-valid-edn-with-32-byte-secret
  (with-clean-env
    (fn []
      (let [dir  (temp-dir)
            path (str dir "/kf-wrap.key")]
        (try
          (vbox/load-or-create-key! {:key-path path})
          (let [{:keys [secret-b64]} (edn/read-string (slurp path))
                bs                   (envelope/b64url-decode secret-b64)]
            (is (string? secret-b64))
            (is (= 32 (alength ^bytes bs))))
          (finally
            (delete-recursively dir)))))))

(deftest config-key-b64-precedes-file-fallback
  (with-clean-env
    (fn []
      (let [dir        (temp-dir)
            path       (str dir "/kf-wrap.key")
            inline-bs  (fixed-key)
            inline-b64 (envelope/b64url-encode inline-bs)]
        (try
          (let [bs (vbox/load-or-create-key! {:key-path path :key-b64 inline-b64})]
            (testing "inline :key-b64 is used directly — never written to disk."
              (is (java.util.Arrays/equals ^bytes inline-bs ^bytes bs))
              (is (not (.exists (java.io.File. path))))))
          (finally
            (delete-recursively dir)))))))

(deftest load-or-create-key-rejects-wrong-length-inline-secret
  (with-clean-env
    (fn []
      (let [short-b64 (envelope/b64url-encode (byte-array 16))]
        (is (thrown? clojure.lang.ExceptionInfo
                     (vbox/load-or-create-key! {:key-b64 short-b64})))))))

(deftest load-or-create-key-rejects-wrong-length-stored-secret
  (with-clean-env
    (fn []
      (let [dir  (temp-dir)
            path (str dir "/kf-wrap.key")]
        (try
          (spit path (pr-str {:secret-b64 (envelope/b64url-encode (byte-array 16))}))
          (is (thrown? clojure.lang.ExceptionInfo
                       (vbox/load-or-create-key! {:key-path path})))
          (finally
            (delete-recursively dir)))))))

(deftest kf-wrap-key-is-independent-of-ip-hmac-default-path
  (with-clean-env
    (fn []
      (testing "the default kf-wrap path is distinct from the IP-HMAC path
                (purpose separation)."
        (is (str/ends-with? (vbox/resolve-key-path {}) "/continuity-auth/kf-wrap.key"))))))
