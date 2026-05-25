(ns continuity-auth.client.tabs
  "Cross-tab coordination for the continuity-auth client.

  Two coordination mechanisms:

  - `navigator.locks` — used to serialize key generation. The first tab
    to load on a fresh browser must run keygen; concurrent tabs hold a
    lock so only one keygen actually occurs.

  - `BroadcastChannel` — used to notify peer tabs of key-rotation or
    revoke events, so each tab can invalidate its in-memory CryptoKey
    handle and reload from IndexedDB.

  Both APIs are available in all browsers that satisfy our baseline
  (Chrome 64+, Firefox 96+, Safari 15.4+). Graceful fallback to no
  coordination if missing — concurrent tabs may then race on keygen
  and the loser's keypair is discarded when it writes after the winner
  (last-write-wins on IndexedDB)."
  (:require
   [promesa.core :as p]))

;; -- navigator.locks -------------------------------------------------------

(defn- locks-available? []
  (some? (some-> js/navigator .-locks)))

(defn with-keygen-lock
  "Run `thunk` while holding the 'continuity-auth:keygen' lock.
  Resolves to thunk's result (which is itself a promise).

  If `navigator.locks` is unavailable, falls back to running `thunk`
  unprotected — racing tabs may both generate keys, but the
  last-write-wins on IndexedDB keeps the layout consistent."
  [thunk]
  (if (locks-available?)
    (p/create
     (fn [resolve reject]
       (-> (.request (.-locks js/navigator) "continuity-auth:keygen"
                     (fn [_lock]
                       (p/-> (thunk)
                             (p/then resolve)
                             (p/catch reject))))
           (.catch reject))))
    (thunk)))

;; -- BroadcastChannel ------------------------------------------------------

(def ^:private ^:const channel-name "continuity-auth")

(defn- channel-available? []
  (some? (some-> js/window .-BroadcastChannel)))

(defonce ^:private channel-state
  (atom {:channel nil
         :listeners []}))

(defn ensure-channel!
  "Lazily open the BroadcastChannel if not yet open. No-op if the API
  is unavailable."
  []
  (when (and (channel-available?)
             (nil? (:channel @channel-state)))
    (let [ch (js/BroadcastChannel. channel-name)]
      (set! (.-onmessage ch)
            (fn [event]
              (let [data (js->clj (.-data event) :keywordize-keys true)]
                (doseq [f (:listeners @channel-state)]
                  (try (f data) (catch :default _ nil))))))
      (swap! channel-state assoc :channel ch))))

(defn post!
  "Broadcast an event to peer tabs. `event` is a Clojure map."
  [event]
  (ensure-channel!)
  (when-let [ch (:channel @channel-state)]
    (.postMessage ch (clj->js event))))

(defn subscribe!
  "Register a callback `f` invoked for every cross-tab event. Returns
  an unsubscribe fn."
  [f]
  (ensure-channel!)
  (swap! channel-state update :listeners conj f)
  (fn unsubscribe []
    (swap! channel-state update :listeners
           (fn [xs] (remove #(= % f) xs)))))

(defn close!
  "Close the channel (used on page unload, but most browsers handle this
  automatically; provided for completeness)."
  []
  (when-let [ch (:channel @channel-state)]
    (.close ch)
    (swap! channel-state assoc :channel nil :listeners [])))
