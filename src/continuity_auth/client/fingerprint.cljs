(ns continuity-auth.client.fingerprint
  "Browser fingerprint signal collection and digest.

  Produces a 32-byte SHA-256 digest of a canonical concatenation of
  browser signals. The exact format is specified in
  `docs/crypto-protocol.md` and MUST match the server's reconstruction.

  Privacy / robustness:
    - Missing signals (e.g. WebGL returns null) become the empty string.
      The digest is still well-defined, just contains less entropy.
    - If three or more signals are detected as 'normalized' (privacy-tool
      values like Tor's standard UA), set `:low-confidence` true. The
      server uses this to skip fp-axis advisory matching for the
      request — privacy-tool users aren't penalized for blending in;
      they just don't get fp-corroboration uplift."
  (:require
   [clojure.string :as str]
   [continuity-auth.client.crypto :as crypto]
   [promesa.core :as p]))

;; -- signal collectors -----------------------------------------------------

(defn- safe [thunk]
  (try (thunk) (catch :default _ nil)))

(defn- ua []
  (safe #(.-userAgent (.-navigator js/window))))

(defn- screen-str []
  (safe #(let [s (.-screen js/window)]
           (str (.-width s) "x" (.-height s) "x" (.-colorDepth s)))))

(defn- timezone []
  (safe #(.-timeZone (.resolvedOptions (.DateTimeFormat js/Intl)))))

(defn- hardware-concurrency []
  (safe #(str (.-hardwareConcurrency (.-navigator js/window)))))

(defn- languages []
  (safe #(let [n (.-navigator js/window)
               langs (or (.-languages n) #js [])]
           (str (.-language n) ","
                (str/join "," (js->clj langs))))))

;; -- canvas digest ---------------------------------------------------------

(defn- canvas-hash []
  (safe
   (fn []
     (let [canvas (.createElement js/document "canvas")
           _      (set! (.-width canvas) 220)
           _      (set! (.-height canvas) 30)
           ctx    (.getContext canvas "2d")]
       (set! (.-textBaseline ctx) "top")
       (set! (.-font ctx) "14px 'Arial'")
       (.fillStyle ctx "#f60")
       (.fillRect ctx 125 1 62 20)
       (.fillStyle ctx "#069")
       (.fillText ctx "continuity-auth 🔒" 2 15)
       (let [data-url (.toDataURL canvas)]
         data-url)))))

;; -- WebGL parameters ------------------------------------------------------

(defn- webgl-info []
  (safe
   (fn []
     (let [canvas (.createElement js/document "canvas")
           gl     (or (.getContext canvas "webgl")
                      (.getContext canvas "experimental-webgl"))]
       (when gl
         (let [vendor   (.getParameter gl 0x1F00)
               renderer (.getParameter gl 0x1F01)]
           (str (or vendor "") "," (or renderer ""))))))))

;; -- audio context fingerprint (deferred — kept stub for now) -------------

(defn- audio-hash []
  ;; A full implementation renders 100 ms of a fixed oscillator and
  ;; hashes the buffer. Some privacy-tool browsers will quantize the
  ;; output to a fixed value, which is itself a signal. For v1 we
  ;; return the empty string; v1.1 can fill this in without changing
  ;; the canonical-format contract (the field is positional).
  "")

;; -- font probing ---------------------------------------------------------

(def ^:private probe-fonts
  ["serif" "sans-serif" "monospace" "Arial" "Helvetica" "Times New Roman"
   "Courier New" "Georgia" "Verdana" "Comic Sans MS"])

(defn- font-widths []
  (safe
   (fn []
     (let [span (.createElement js/document "span")
           _    (set! (.-innerHTML span) "continuity-auth font probe")
           _    (set! (-> span .-style .-position) "absolute")
           _    (set! (-> span .-style .-left) "-9999px")
           body (.-body js/document)]
       (.appendChild body span)
       (let [widths (mapv (fn [f]
                            (set! (-> span .-style .-fontFamily) f)
                            (.-offsetWidth span))
                          probe-fonts)]
         (.removeChild body span)
         (str/join "," widths))))))

;; -- canonical signal layout ----------------------------------------------

(defn- canonical-signals
  "Concatenate signals in fixed order, each prefixed by its name and
  separator. Matches the order specified in docs/crypto-protocol.md
  §'Fingerprint digest'."
  []
  (str
   "ua:"        (or (ua)                   "") "\n"
   "screen:"    (or (screen-str)           "") "\n"
   "tz:"        (or (timezone)             "") "\n"
   "hc:"        (or (hardware-concurrency) "") "\n"
   "langs:"     (or (languages)            "") "\n"
   "canvas:"    (or (canvas-hash)          "") "\n"
   "webgl:"     (or (webgl-info)           "") "\n"
   "audio:"     (or (audio-hash)           "") "\n"
   "fonts:"     (or (font-widths)          "") "\n"))

(defn- utf8-encode [s]
  (.encode (js/TextEncoder.) s))

;; -- low-confidence detection ----------------------------------------------

(def ^:private known-normalized-values
  ;; Sentinel values associated with privacy tools normalizing fingerprints.
  ;; Heuristic; expanded over time.
  #{"Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"  ; Tor's UA
    "1280x720x24"                                                          ; common normalized screen
    "UTC"                                                                  ; normalized timezone
    "2"                                                                    ; normalized hardwareConcurrency
    "en-US,en-US"})

(defn- low-confidence?
  "Return true if at least 3 signals look like privacy-tool defaults."
  []
  (let [signals [(ua) (screen-str) (timezone) (hardware-concurrency) (languages)]]
    (>= (count (filter known-normalized-values signals)) 3)))

;; -- public API ------------------------------------------------------------

(defn compute-digest
  "Compute the 32-byte fingerprint digest. Returns a promise resolving
  to {:digest <Uint8Array(32)>, :low-confidence boolean}."
  []
  (let [signals (canonical-signals)
        bytes   (utf8-encode signals)]
    (p/let [digest (crypto/sha256 bytes)]
      {:digest         digest
       :low-confidence (low-confidence?)})))
