(ns continuity-auth.server.http.middleware-test
  "Unit tests for the Ring middleware stack — body-size limits, Content-Length
  parsing, XFF-strict IP extraction, and the bootstrap per-IP rate limit."
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.server.crypto.ip-hmac :as ip-hmac]
   [continuity-auth.server.http.middleware :as mw]
   [continuity-auth.server.storage.protocol :as storage])
  (:import
   (java.io ByteArrayInputStream)))

;; -- read-bounded / wrap-body-size-limit -----------------------------------

(defn- exec-body-size
  "Run wrap-body-size-limit at `limit` against an in-memory body, returning
  the inner handler's view of the request map OR the error response."
  [limit body-bytes content-length]
  (let [captured (atom nil)
        inner    (fn [req] (reset! captured req) {:status 200 :body "ok"})
        handler  (mw/wrap-error
                  (mw/wrap-body-size-limit inner limit))
        request  {:request-method :post
                  :headers (cond-> {}
                             content-length (assoc "content-length" content-length))
                  :body (ByteArrayInputStream. body-bytes)}
        response (handler request)]
    {:response response :captured @captured}))

(deftest body-of-exactly-limit-accepted
  (testing "A body whose length equals the limit is accepted; the captured
            bytes match exactly."
    (let [limit 128
          bs    (byte-array limit (byte 65))   ; 128 'A' bytes
          {:keys [response captured]} (exec-body-size limit bs nil)]
      (is (= 200 (:status response)))
      (is (= limit (alength ^bytes (:cauth/raw-body captured)))))))

(deftest body-of-exactly-limit-plus-one-rejected
  (testing "Off-by-one regression: with the old `inc limit` buffer, a body of
            exactly limit+1 bytes (chunked, no Content-Length) would slip
            through as a `limit+1`-byte array. The tight buffer must reject."
    (let [limit 128
          bs    (byte-array (inc limit) (byte 65))
          {:keys [response]} (exec-body-size limit bs nil)]
      (is (= 413 (:status response)))
      (is (str/includes? (str (:body response)) "E_PAYLOAD_TOO_LARGE")))))

(deftest content-length-over-limit-rejected
  (testing "Content-Length header over the limit is rejected before the
            body is read at all."
    (let [limit 128
          bs    (byte-array 10 (byte 65))   ; small actual body
          {:keys [response]} (exec-body-size limit bs (str (inc limit)))]
      (is (= 413 (:status response))))))

(deftest content-length-malformed-returns-400
  (testing "Content-Length parse regression: a non-numeric value like `abc`
            previously threw NumberFormatException → fell through wrap-error
            → 500. Must return 400 E_BAD_REQUEST."
    (let [limit 128
          bs    (byte-array 10 (byte 65))
          {:keys [response]} (exec-body-size limit bs "abc")]
      (is (= 400 (:status response)))
      (is (str/includes? (str (:body response)) "E_BAD_REQUEST")))))

;; -- extract-client-ip -----------------------------------------------------

(deftest xff-non-ip-candidate-falls-back-to-remote
  (testing "If the chosen X-Forwarded-For candidate is not a parseable
            IPv4, fall back to :remote-addr instead of returning the
            garbage string."
    (let [trusted (mw/parse-trusted-cidrs "10.0.0.0/8")
          req {:remote-addr "10.0.0.1"
               :headers {"x-forwarded-for" "not-an-ip, 10.0.0.5"}}]
      ;; "not-an-ip" is the first non-trusted candidate AND not a real IP;
      ;; "10.0.0.5" is the next, but it's in trusted CIDR.
      ;; The strict version must return :remote-addr.
      (is (= "10.0.0.1"
             (mw/extract-client-ip req trusted "x-forwarded-for"))))))

(deftest xff-real-client-ip-still-extracted
  (testing "A genuine client IP outside the trusted set is still returned
            (regression bound for the strict-IP fix)."
    (let [trusted (mw/parse-trusted-cidrs "10.0.0.0/8")
          req {:remote-addr "10.0.0.1"
               :headers {"x-forwarded-for" "203.0.113.7, 10.0.0.5"}}]
      (is (= "203.0.113.7"
             (mw/extract-client-ip req trusted "x-forwarded-for"))))))

;; -- wrap-bootstrap-rate-limit ---------------------------------------------
;;
;; Behavioural contract: exponential-backoff with cap on /v1/bootstrap.
;; Each allow sets up a penalty (floor × factor^consecutive, capped at cap)
;; that the NEXT attempt must wait out. Denied attempts do not compound;
;; the strike escalates only on the next allow. A quiet period >
;; reset-threshold resets :consecutive to 0.

(defn- mk-clock
  "Mutable now-fn for tests. Call (advance n) to move forward n ms."
  [start-ms]
  (let [t (atom (long start-ms))]
    {:now-fn  (fn [] @t)
     :advance (fn [ms] (swap! t + (long ms)))
     :set     (fn [ms] (reset! t (long ms)))}))

(defn- mk-bootstrap-handler
  "Wrap a counting inner handler with bootstrap rate-limit using a
  mutable clock. Returns a map of {:handler :clock} for tests to drive."
  [opts]
  (let [clock (mk-clock 1000000)
        seen  (atom 0)
        inner (fn [_] (swap! seen inc) {:status 201})
        h     (mw/wrap-bootstrap-rate-limit
               inner
               (assoc opts :now-fn (:now-fn clock)))]
    {:handler h :clock clock :seen seen}))

(defn- bootstrap-req
  "Build a synthetic /v1/bootstrap request for tests. `ip` plays both
  roles (rate-limit bucket key + CIDR check input); in production these
  are decoupled (hash vs raw), but for unit tests of the rate-limit
  staircase they are identical opaque strings."
  ([ip] (bootstrap-req ip "/v1/bootstrap"))
  ([ip uri] {:request-method :post :uri uri
             :cauth/client-ip ip
             :cauth/client-ip-raw ip}))

(deftest bootstrap-rate-limit-fresh-ip-allowed
  (testing "First bootstrap from a never-seen IP is allowed without delay."
    (let [{:keys [handler]} (mk-bootstrap-handler
                              {:floor-ms 1000 :cap-ms 60000
                               :doubling-factor 2 :reset-threshold-ms 300000})
          r (handler (bootstrap-req "1.2.3.4"))]
      (is (= 201 (:status r))))))

(deftest bootstrap-rate-limit-staircase-doubles
  (testing "Successive allows produce a doubling penalty: 1s, 2s, 4s, 8s …"
    (let [{:keys [handler clock]} (mk-bootstrap-handler
                                    {:floor-ms 1000 :cap-ms 60000
                                     :doubling-factor 2
                                     :reset-threshold-ms 300000})
          advance (:advance clock)
          step    (fn [wait-ms]
                    (advance wait-ms)
                    (:status (handler (bootstrap-req "1.2.3.4"))))]
      ;; First attempt at t=0 → allow; penalty-until set to t+1000.
      (is (= 201 (step 0)))
      ;; Try again 1ms later → in penalty window (999ms still to go) → 429.
      (is (= 429 (step 1)))
      ;; Advance past first 1s penalty → allow; new penalty = 2000ms.
      (is (= 201 (step 1000)))
      ;; Inside 2s penalty → 429.
      (is (= 429 (step 100)))
      ;; Past 2s penalty → allow; new penalty = 4000ms.
      (is (= 201 (step 2000)))
      ;; Inside 4s penalty → 429.
      (is (= 429 (step 100)))
      ;; Past 4s penalty → allow; new penalty = 8000ms.
      (is (= 201 (step 4000))))))

(deftest bootstrap-rate-limit-cap-converges
  (testing "Penalty caps at cap-ms once floor × factor^consec exceeds it.
            With floor=1000, factor=2, cap=4000: 1s→2s→4s→4s→4s …"
    (let [{:keys [handler clock]} (mk-bootstrap-handler
                                    {:floor-ms 1000 :cap-ms 4000
                                     :doubling-factor 2
                                     :reset-threshold-ms 300000})
          advance (:advance clock)]
      ;; Walk the staircase: each step waits the previous penalty out,
      ;; then asserts the next allow.
      (is (= 201 (:status (handler (bootstrap-req "9.9.9.9")))))     ; penalty 1s
      (advance 1000)
      (is (= 201 (:status (handler (bootstrap-req "9.9.9.9")))))     ; penalty 2s
      (advance 2000)
      (is (= 201 (:status (handler (bootstrap-req "9.9.9.9")))))     ; penalty 4s
      (advance 4000)
      (is (= 201 (:status (handler (bootstrap-req "9.9.9.9")))))     ; capped 4s
      (advance 4000)
      (is (= 201 (:status (handler (bootstrap-req "9.9.9.9")))))     ; capped 4s
      ;; Inside cap window: 429. Wait exactly cap-1 ms → still 429.
      (advance 3999)
      (is (= 429 (:status (handler (bootstrap-req "9.9.9.9"))))))))

(deftest bootstrap-rate-limit-reset-after-quiet
  (testing "After reset-threshold-ms of quiet, :consecutive resets to 0 —
            penalty drops back to floor."
    (let [{:keys [handler clock]} (mk-bootstrap-handler
                                    {:floor-ms 1000 :cap-ms 60000
                                     :doubling-factor 2
                                     :reset-threshold-ms 300000})
          advance (:advance clock)]
      ;; Build up some strikes.
      (is (= 201 (:status (handler (bootstrap-req "7.7.7.7")))))
      (advance 1000)
      (is (= 201 (:status (handler (bootstrap-req "7.7.7.7")))))    ; consec=1
      (advance 2000)
      (is (= 201 (:status (handler (bootstrap-req "7.7.7.7")))))    ; consec=2 → next penalty 4s
      ;; Quiet period exceeds reset threshold.
      (advance 400000)
      ;; Next allow: consec resets to 0 → penalty = floor = 1000ms.
      (is (= 201 (:status (handler (bootstrap-req "7.7.7.7")))))
      ;; 500ms later → still in floor window → 429.
      (advance 500)
      (is (= 429 (:status (handler (bootstrap-req "7.7.7.7"))))))))

(deftest bootstrap-rate-limit-only-applies-to-bootstrap
  (testing "Other endpoints are not rate-limited by this middleware."
    (let [{:keys [handler clock]} (mk-bootstrap-handler
                                    {:floor-ms 1000 :cap-ms 60000
                                     :doubling-factor 2
                                     :reset-threshold-ms 300000})
          advance (:advance clock)]
      ;; First /verify allowed; would be 429 on /v1/bootstrap second hit.
      (dotimes [_ 5]
        (is (= 201 (:status (handler (bootstrap-req "1.2.3.4" "/v1/verify"))))))
      (advance 0))))

(deftest bootstrap-rate-limit-isolates-by-ip
  (testing "Different IPs have independent strike state."
    (let [{:keys [handler]} (mk-bootstrap-handler
                              {:floor-ms 1000 :cap-ms 60000
                               :doubling-factor 2
                               :reset-threshold-ms 300000})]
      (is (= 201 (:status (handler (bootstrap-req "1.2.3.4")))))
      ;; Another IP — still passes immediately.
      (is (= 201 (:status (handler (bootstrap-req "5.6.7.8")))))
      ;; First IP again with no advance → inside its 1s floor → 429.
      (is (= 429 (:status (handler (bootstrap-req "1.2.3.4"))))))))

(deftest bootstrap-rate-limit-retry-after-reflects-actual-remaining
  (testing "On 429, Retry-After header (ceil seconds) and body
            retry_after_ms (exact ms) match the actual penalty remaining,
            not the full window-ms — closes the prior under-reporting bug
            where clients were told to wait 60s for a 1s penalty."
    (let [{:keys [handler clock]} (mk-bootstrap-handler
                                    {:floor-ms 1000 :cap-ms 60000
                                     :doubling-factor 2
                                     :reset-threshold-ms 300000})
          advance (:advance clock)]
      ;; First allow at t=0 → penalty-until = t+1000.
      (is (= 201 (:status (handler (bootstrap-req "1.2.3.4")))))
      ;; 200ms later → 800ms remaining.
      (advance 200)
      (let [r (handler (bootstrap-req "1.2.3.4"))]
        (is (= 429 (:status r)))
        ;; Retry-After header: ceil(800 / 1000) = 1.
        (is (= "1" (get-in r [:headers "Retry-After"])))
        (is (str/includes? (str (:body r)) "\"retry_after_ms\":800")))
      ;; Build up to a 2s penalty.
      (advance 1000)
      (is (= 201 (:status (handler (bootstrap-req "1.2.3.4")))))
      ;; 500ms in → 1500ms remaining.
      (advance 500)
      (let [r (handler (bootstrap-req "1.2.3.4"))]
        (is (= 429 (:status r)))
        ;; Retry-After header: ceil(1500 / 1000) = 2 (not 1).
        (is (= "2" (get-in r [:headers "Retry-After"])))
        (is (str/includes? (str (:body r)) "\"retry_after_ms\":1500"))))))

;; -- bootstrap-suspicion-multiplier (Tier 2 pure curve) --------------------

(deftest suspicion-multiplier-nil-signals-neutral
  (testing "Missing :ip-age-seconds / :identity-count both contribute ×1 —
            the no-signal case (storage timeout/disabled) must not inflate
            the penalty."
    (is (= 1.0 (mw/bootstrap-suspicion-multiplier {})))
    (is (= 1.0 (mw/bootstrap-suspicion-multiplier
                {:ip-age-seconds nil :identity-count nil})))
    ;; Only the CIDR hit fires when other signals are nil.
    (is (= 5.0 (mw/bootstrap-suspicion-multiplier {:datacenter-hit? true})))))

(deftest suspicion-multiplier-default-shape
  (testing "Bands match the project plan defaults."
    (is (= 10.0 (mw/bootstrap-suspicion-multiplier
                  {:ip-age-seconds 0 :identity-count 0})))
    (is (= 20.0 (mw/bootstrap-suspicion-multiplier
                  {:ip-age-seconds 3600 :identity-count 5})))
    (is (= 1.0 (mw/bootstrap-suspicion-multiplier
                 {:ip-age-seconds 2592000 :identity-count 0})))
    (is (= 0.7 (mw/bootstrap-suspicion-multiplier
                 {:ip-age-seconds 31536000 :identity-count 0})))
    (is (= 0.5 (mw/bootstrap-suspicion-multiplier
                 {:ip-age-seconds 99999999 :identity-count 0})))
    (is (= 100.0 (mw/bootstrap-suspicion-multiplier
                   {:ip-age-seconds 3600 :identity-count 50})))))

(deftest suspicion-multiplier-clamped
  (testing "Composition is clamped to [0.5, 100]."
    (let [m (mw/bootstrap-suspicion-multiplier
              {:ip-age-seconds 0 :identity-count 50 :datacenter-hit? true})]
      (is (= 100.0 m) "10×10×5 = 500 → clamped at 100"))
    (let [m (mw/bootstrap-suspicion-multiplier
              {:ip-age-seconds 99999999 :identity-count 0})]
      (is (= 0.5 m) "0.5×1×1 = 0.5 → at lower bound"))))

(deftest suspicion-multiplier-monotone
  (testing "Higher ip-age does NOT increase the multiplier;
            higher identity-count does NOT decrease it."
    ;; ip-age monotone non-increasing (identity-count fixed at 0)
    (let [ms (mapv (fn [age]
                     (mw/bootstrap-suspicion-multiplier
                       {:ip-age-seconds age :identity-count 0}))
                   [0 3600 86400 2592000 31536000 99999999])]
      (is (= ms (sort #(compare %2 %1) ms))
          (str "ip-age multiplier must be non-increasing: " ms)))
    ;; identity-count monotone non-decreasing (ip-age fixed at 0)
    (let [ms (mapv (fn [n]
                     (mw/bootstrap-suspicion-multiplier
                       {:ip-age-seconds 0 :identity-count n}))
                   [0 1 5 6 49 50 100])]
      (is (= ms (sort ms))
          (str "identity-count multiplier must be non-decreasing: " ms)))))

;; -- make-suspicion-fn (cache + timeout fallback) ----------------------------

(defn- stub-storage
  "Build a minimal Storage stub that returns `signals` for the configured
  ip, sleeps `sleep-ms` first (to exercise timeout), and counts reads in
  `read-count`. The Datalevin storage protocol has many methods — we only
  need snapshot + bootstrap-signals-for-ip here."
  [{:keys [signals sleep-ms read-count throw?]
    :or {sleep-ms 0 read-count (atom 0) throw? false}}]
  (reify storage/Storage
    (snapshot [_] :stub-snap)
    (bootstrap-signals-for-ip [_ _snap ip _now-ms]
      (swap! read-count inc)
      (when (pos? sleep-ms) (Thread/sleep ^long sleep-ms))
      (when throw? (throw (ex-info "stub failure" {})))
      (get signals ip {:ip-age-seconds 0 :identity-count 0}))))

(deftest make-suspicion-fn-no-storage-is-neutral
  (testing "Without storage, signals are nil-on-each-axis so the multiplier
            collapses to ×1 (or ×5 if the IP hits a datacenter CIDR)."
    (let [f (mw/make-suspicion-fn {})]
      (is (= 1.0 (f "1.2.3.4" "1.2.3.4" 1000))))
    (let [dcr (mw/parse-trusted-cidrs "10.0.0.0/8")
          f   (mw/make-suspicion-fn {:datacenter-cidrs dcr})]
      (is (= 1.0 (f "1.2.3.4" "1.2.3.4" 1000)))
      (is (= 5.0 (f "10.0.0.5" "10.0.0.5" 1000))))))

(deftest make-suspicion-fn-cache-hit-skips-read
  (testing "After a cache miss + read, a second call within TTL must NOT
            re-read storage."
    (let [reads (atom 0)
          store (stub-storage
                  {:signals    {"1.2.3.4" {:ip-age-seconds 3600 :identity-count 1}}
                   :read-count reads})
          f     (mw/make-suspicion-fn
                  {:storage         store
                   :cache-ttl-ms    60000
                   :read-timeout-ms 1000})]
      (f "1.2.3.4" "1.2.3.4" 1000)
      (is (= 1 @reads) "first call triggers a storage read")
      (f "1.2.3.4" "1.2.3.4" 1500)
      (f "1.2.3.4" "1.2.3.4" 2000)
      (is (= 1 @reads) "subsequent calls within TTL are served from cache"))))

(deftest make-suspicion-fn-cache-expires
  (testing "After TTL, a fresh read happens."
    (let [reads (atom 0)
          store (stub-storage
                  {:signals    {"1.2.3.4" {:ip-age-seconds 3600 :identity-count 1}}
                   :read-count reads})
          f     (mw/make-suspicion-fn
                  {:storage         store
                   :cache-ttl-ms    1000
                   :read-timeout-ms 1000})]
      (f "1.2.3.4" "1.2.3.4" 1000)
      (is (= 1 @reads))
      (f "1.2.3.4" "1.2.3.4" 2500) ; > 1000ms after cached-at — TTL expired
      (is (= 2 @reads) "stale entry triggered a re-read"))))

(deftest make-suspicion-fn-timeout-falls-back-to-neutral
  (testing "Storage that overshoots :read-timeout-ms produces a neutral
            multiplier (1.0) and ticks the on-fallback metric with :timeout."
    (let [fallback-events (atom [])
          store (stub-storage
                  {:signals  {"1.2.3.4" {:ip-age-seconds 0 :identity-count 0}}
                   :sleep-ms 200}) ; 200ms > 25ms timeout
          f     (mw/make-suspicion-fn
                  {:storage         store
                   :read-timeout-ms 25
                   :on-fallback     (fn [kind ex] (swap! fallback-events conj [kind ex]))})]
      (is (= 1.0 (f "1.2.3.4" "1.2.3.4" 1000))
          "neutral multiplier when the read times out")
      (is (= 1 (count @fallback-events)))
      (is (= :timeout (-> @fallback-events first first))))))

(deftest make-suspicion-fn-exception-falls-back
  (testing "Storage that throws produces neutral multiplier + :exception event."
    (let [fallback-events (atom [])
          store (stub-storage {:throw? true})
          f     (mw/make-suspicion-fn
                  {:storage     store
                   :on-fallback (fn [kind ex]
                                  (swap! fallback-events conj [kind (some? ex)]))})]
      (is (= 1.0 (f "1.2.3.4" "1.2.3.4" 1000)))
      (is (= 1 (count @fallback-events)))
      (is (= :exception (-> @fallback-events first first))))))

(deftest make-suspicion-fn-datacenter-cidr-multiplies
  (testing "An IP in a configured datacenter CIDR contributes ×5 even when
            storage signals are otherwise mid-band."
    (let [store (stub-storage
                  {:signals {"203.0.113.5" {:ip-age-seconds 86400 :identity-count 0}}})
          dcr   (mw/parse-trusted-cidrs "203.0.113.0/24")
          f     (mw/make-suspicion-fn
                  {:storage          store
                   :datacenter-cidrs dcr})]
      ;; 1d-old IP with 0 identities = 3.0; datacenter-hit ×5 = 15.0
      (is (= 15.0 (f "203.0.113.5" "203.0.113.5" 1000)))
      ;; Outside the CIDR: just 3.0
      (let [store2 (stub-storage
                     {:signals {"198.51.100.5" {:ip-age-seconds 86400 :identity-count 0}}})
            f2    (mw/make-suspicion-fn
                    {:storage          store2
                     :datacenter-cidrs dcr})]
        (is (= 3.0 (f2 "198.51.100.5" "198.51.100.5" 1000)))))))

(deftest bootstrap-rate-limit-honours-suspicion-multiplier
  (testing "When suspicion-fn returns 10.0, the staircase floor is 10× as
            long. First allow at t=0 sets penalty-until = t+10_000."
    (let [{:keys [handler clock]} (mk-bootstrap-handler
                                    {:floor-ms 1000 :cap-ms 60000
                                     :doubling-factor 2
                                     :reset-threshold-ms 300000
                                     :suspicion-fn (fn [_ip _raw _now] 10.0)})
          advance (:advance clock)]
      ;; t=0: allow.
      (is (= 201 (:status (handler (bootstrap-req "1.2.3.4")))))
      ;; t=5000 (still inside the 10s floor under ×10): 429.
      (advance 5000)
      (is (= 429 (:status (handler (bootstrap-req "1.2.3.4")))))
      ;; t=10500 (past 10s): allow.
      (advance 5500)
      (is (= 201 (:status (handler (bootstrap-req "1.2.3.4"))))))))

(deftest bootstrap-rate-limit-honours-cap-with-suspicion
  (testing "cap-ms is the absolute upper bound regardless of suspicion."
    (let [{:keys [handler clock]} (mk-bootstrap-handler
                                    {:floor-ms 1000 :cap-ms 5000
                                     :doubling-factor 2
                                     :reset-threshold-ms 300000
                                     :suspicion-fn (fn [_ip _raw _now] 100.0)})
          advance (:advance clock)]
      (is (= 201 (:status (handler (bootstrap-req "1.2.3.4")))))
      ;; Penalty would be 1000 × 100 = 100s without the cap; with cap=5s
      ;; the limiter clears at t=5000.
      (advance 4999)
      (is (= 429 (:status (handler (bootstrap-req "1.2.3.4")))))
      (advance 2)
      (is (= 201 (:status (handler (bootstrap-req "1.2.3.4"))))))))

;; -- IP / CIDR parsing (T3.4) ----------------------------------------------

(deftest cidr-membership-ipv4
  (testing "parse-trusted-cidrs + ip-in-cidrs? handle IPv4 inclusion / exclusion."
    ;; The internal `ip-in-cidrs?` is private; test through
    ;; make-suspicion-fn which uses it.
    (let [ranges (mw/parse-trusted-cidrs "203.0.113.0/24,10.0.0.0/8")
          f      (mw/make-suspicion-fn {:datacenter-cidrs ranges})]
      (is (= 5.0 (f "203.0.113.5" "203.0.113.5" 1)))
      (is (= 5.0 (f "10.5.5.5"    "10.5.5.5"    1)))
      (is (= 1.0 (f "198.51.100.5" "198.51.100.5" 1)))
      ;; Non-IPv4 input must not crash; treat as miss.
      (is (= 1.0 (f "not-an-ip" "not-an-ip" 1))))))

(deftest bootstrap-rate-limit-denies-do-not-compound
  (testing "Repeated denied attempts inside a single penalty window do not
            escalate :consecutive — the strike is set by the prior allow,
            and a burst of 429s leaves the staircase position unchanged."
    (let [{:keys [handler clock]} (mk-bootstrap-handler
                                    {:floor-ms 1000 :cap-ms 60000
                                     :doubling-factor 2
                                     :reset-threshold-ms 300000})
          advance (:advance clock)]
      ;; t=0 allow → penalty = 1000ms.
      (is (= 201 (:status (handler (bootstrap-req "1.2.3.4")))))
      ;; Burst 100 denied attempts inside the 1s window.
      (dotimes [_ 100]
        (advance 5)
        (is (= 429 (:status (handler (bootstrap-req "1.2.3.4"))))))
      ;; Move past the penalty (started at t=0, expires at t=1000;
      ;; after 100×5=500ms the clock is at t=500, so 600ms more
      ;; gets us safely past).
      (advance 600)
      (let [r (handler (bootstrap-req "1.2.3.4"))]
        (is (= 201 (:status r))))
      ;; The next penalty must be 2000ms (consec went 0 → 1 over the
      ;; 100 denials → 1 → 2 after this allow), not something larger.
      ;; Verify by checking exactly the 2s boundary.
      (advance 1999)
      (is (= 429 (:status (handler (bootstrap-req "1.2.3.4")))))
      (advance 2)
      (is (= 201 (:status (handler (bootstrap-req "1.2.3.4"))))))))

;; -- wrap-trusted-proxy-ip + ingress IP hashing ----------------------------
;;
;; At HTTP ingress we hash the raw IP under a per-deployment HMAC key.
;; `:cauth/client-ip`     — hex hash; flows downstream, persists into the store.
;; `:cauth/client-ip-raw` — plaintext; consumed only by the CIDR check in
;;                          `wrap-bootstrap-rate-limit`; never logged, never
;;                          persisted.
;; The handler MUST throw at construction time if no key is supplied —
;; running without one would silently regress to plaintext IP storage.

(def ^:private test-ip-hmac-key
  (byte-array (map byte (range 32))))

(defn- capture-handler []
  (let [captured (atom nil)]
    {:handler (fn [req] (reset! captured req) {:status 200})
     :captured captured}))

(deftest wrap-trusted-proxy-ip-sets-both-hashed-and-raw
  (testing "Ingress hashes the resolved client IP, sets :cauth/client-ip
            to the hex hash, and keeps the plaintext IP on
            :cauth/client-ip-raw for the in-process CIDR check."
    (let [{:keys [handler captured]} (capture-handler)
          h (mw/wrap-trusted-proxy-ip
             handler
             {:trusted-cidrs (mw/parse-trusted-cidrs "10.0.0.0/8")
              :ip-header     "x-forwarded-for"
              :ip-hmac-key   test-ip-hmac-key})
          _ (h {:remote-addr "10.0.0.1"
                :headers {"x-forwarded-for" "203.0.113.7, 10.0.0.5"}})
          req @captured]
      (is (= "203.0.113.7" (:cauth/client-ip-raw req)))
      (is (= (ip-hmac/hmac-ip-hex test-ip-hmac-key "203.0.113.7")
             (:cauth/client-ip req)))
      (is (re-matches #"[0-9a-f]{64}" (:cauth/client-ip req)))
      (testing "the hashed key and the raw key are distinct strings"
        (is (not= (:cauth/client-ip req) (:cauth/client-ip-raw req)))))))

(deftest wrap-trusted-proxy-ip-determinism-same-ip-same-hash
  (testing "Two requests from the same IP through the same instance
            (and therefore the same key) hash to the same value — this
            is what makes cluster-by-IP still work after pseudonymisation."
    (let [{:keys [handler captured]} (capture-handler)
          h (mw/wrap-trusted-proxy-ip
             handler
             {:trusted-cidrs (mw/parse-trusted-cidrs "10.0.0.0/8")
              :ip-header     "x-forwarded-for"
              :ip-hmac-key   test-ip-hmac-key})
          req {:remote-addr "10.0.0.1"
               :headers {"x-forwarded-for" "198.51.100.42, 10.0.0.5"}}
          _ (h req)
          h1 (:cauth/client-ip @captured)
          _ (h req)
          h2 (:cauth/client-ip @captured)]
      (is (= h1 h2)))))

(deftest wrap-trusted-proxy-ip-distinct-ips-distinct-hashes
  (testing "Different IPs produce different hashes (cluster discrimination
            is preserved post-pseudonymisation)."
    (let [{:keys [handler captured]} (capture-handler)
          h (mw/wrap-trusted-proxy-ip
             handler
             {:trusted-cidrs (mw/parse-trusted-cidrs "10.0.0.0/8")
              :ip-header     "x-forwarded-for"
              :ip-hmac-key   test-ip-hmac-key})
          _ (h {:remote-addr "10.0.0.1"
                :headers {"x-forwarded-for" "198.51.100.1, 10.0.0.5"}})
          a (:cauth/client-ip @captured)
          _ (h {:remote-addr "10.0.0.1"
                :headers {"x-forwarded-for" "198.51.100.2, 10.0.0.5"}})
          b (:cauth/client-ip @captured)]
      (is (not= a b)))))

(deftest wrap-trusted-proxy-ip-rejects-missing-key
  (testing "Constructor refuses to build the handler without an IP-HMAC
            key. The wrong failure mode would be silent fallback to
            plaintext, which is exactly what this work is undoing."
    (is (thrown? clojure.lang.ExceptionInfo
                 (mw/wrap-trusted-proxy-ip
                  (fn [_] {:status 200})
                  {:trusted-cidrs []
                   :ip-header     "x-forwarded-for"})))))

(deftest wrap-trusted-proxy-ip-distinct-keys-distinct-hashes
  (testing "Two deployments with different keys hashing the same IP must
            produce different downstream cluster keys — otherwise an
            attacker dumping one store could correlate against another."
    (let [k1 test-ip-hmac-key
          k2 (byte-array (map (fn [i] (byte (bit-and (+ i 64) 0xff)))
                              (range 32)))
          {h1 :handler c1 :captured} (capture-handler)
          {h2 :handler c2 :captured} (capture-handler)
          mw1 (mw/wrap-trusted-proxy-ip
               h1 {:trusted-cidrs [] :ip-hmac-key k1})
          mw2 (mw/wrap-trusted-proxy-ip
               h2 {:trusted-cidrs [] :ip-hmac-key k2})
          req {:remote-addr "203.0.113.10" :headers {}}]
      (mw1 req)
      (mw2 req)
      (is (not= (:cauth/client-ip @c1)
                (:cauth/client-ip @c2)))
      (testing "the plaintext IP is preserved identically in both"
        (is (= "203.0.113.10" (:cauth/client-ip-raw @c1)))
        (is (= "203.0.113.10" (:cauth/client-ip-raw @c2)))))))
