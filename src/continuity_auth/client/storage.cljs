(ns continuity-auth.client.storage
  "Browser-side storage for the LS keypair handle and key metadata.

  Storage policy:
    - IndexedDB holds the actual CryptoKey objects (private and public).
      CryptoKey is structured-cloneable, so IndexedDB can store it
      directly without exposing the underlying bytes.
    - localStorage holds ONLY metadata:
        :key-id        — 32-byte base64url thumbprint
        :alg           — :ed25519 or :p256 (as string)
        :created-at    — ISO-8601 timestamp
        :version       — schema version of this storage layout
      Never any key material.

  Note: We use a tiny custom IndexedDB wrapper rather than pulling in
  Dexie or idb-keyval. The surface we need is minimal (single object
  store, get/put), and the bundle budget (≤ 25 KB gzipped) cannot
  absorb a library."
  (:require
   [goog.object :as gobj]
   [promesa.core :as p]))

;; -- localStorage metadata -------------------------------------------------

(def ^:private ^:const ls-key "continuity-auth:meta")

(defn read-meta
  "Read the current key metadata from localStorage, or nil if not yet
  initialized."
  []
  (when-let [s (.getItem (.-localStorage js/window) ls-key)]
    (try
      (js->clj (.parse js/JSON s) :keywordize-keys true)
      (catch :default _ nil))))

(defn write-meta!
  "Write the key metadata to localStorage."
  [meta]
  (.setItem (.-localStorage js/window)
            ls-key
            (.stringify js/JSON (clj->js meta))))

(defn clear-meta! []
  (.removeItem (.-localStorage js/window) ls-key))

;; -- IndexedDB -------------------------------------------------------------

(def ^:private ^:const idb-name  "continuity-auth")
(def ^:private ^:const idb-store "keys")
(def ^:private ^:const idb-version 1)

(defn- open-idb
  "Open (and create-if-missing) the continuity-auth IndexedDB."
  []
  (p/create
   (fn [resolve reject]
     (let [req (.open (.-indexedDB js/window) idb-name idb-version)]
       (set! (.-onupgradeneeded req)
             (fn [_]
               (let [db (.-result req)]
                 (when-not (.contains (.-objectStoreNames db) idb-store)
                   (.createObjectStore db idb-store)))))
       (set! (.-onerror req)   (fn [_] (reject (.-error req))))
       (set! (.-onsuccess req) (fn [_] (resolve (.-result req))))))))

(defn- with-store
  "Run `f` against the IDB object store in mode `mode` (\"readonly\" or
  \"readwrite\"). `f` is a 1-arg fn of the object store."
  [mode f]
  (p/let [db (open-idb)]
    (p/create
     (fn [resolve reject]
       (let [tx    (.transaction db #js [idb-store] mode)
             store (.objectStore tx idb-store)
             result (volatile! nil)
             req   (f store)]
         (set! (.-onsuccess req) (fn [_] (vreset! result (.-result req))))
         (set! (.-oncomplete tx) (fn [_] (resolve @result)))
         (set! (.-onerror tx)    (fn [_] (reject (.-error tx)))))))))

(defn put-keypair!
  "Persist the keypair handle to IndexedDB. CryptoKey objects are
  structured-cloneable; their underlying bytes remain non-extractable."
  [{:keys [private-key public-key]}]
  (with-store "readwrite"
    (fn [store]
      (.put store (clj->js {:private-key private-key
                            :public-key  public-key})
            "keypair"))))

(defn get-keypair
  "Fetch the keypair handle. Returns nil if not present."
  []
  (p/let [v (with-store "readonly"
              (fn [store] (.get store "keypair")))]
    (when v
      ;; goog.object/get uses string property names — survives :advanced
      ;; renaming, which is required because the object came from
      ;; IndexedDB and its property names were not introduced as JS
      ;; symbols the Closure compiler knows about.
      {:private-key (gobj/get v "private-key")
       :public-key  (gobj/get v "public-key")})))

(defn delete-keypair!
  "Remove the keypair from IndexedDB."
  []
  (with-store "readwrite"
    (fn [store] (.delete store "keypair"))))

(defn clear-all!
  "Wipe both localStorage metadata and IndexedDB keypair. Used on
  explicit user 'log out everywhere' UX."
  []
  (clear-meta!)
  (delete-keypair!))
