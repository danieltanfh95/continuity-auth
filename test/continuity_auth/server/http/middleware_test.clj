(ns continuity-auth.server.http.middleware-test
  "Unit tests for the Ring middleware stack — body-size limits, Content-Length
  parsing, XFF-strict IP extraction, and the bootstrap per-IP rate limit."
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [continuity-auth.server.http.middleware :as mw])
  (:import
   (java.io ByteArrayInputStream)))

;; -- read-bounded / wrap-body-size-limit (codex M5, claude M6) -------------

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
  (testing "Codex M5 regression: with the old `inc limit` buffer, a body of
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
  (testing "Claude 9 / codex M6 regression: Content-Length `abc` previously
            threw NumberFormatException → fell through wrap-error → 500.
            Must return 400 E_BAD_REQUEST."
    (let [limit 128
          bs    (byte-array 10 (byte 65))
          {:keys [response]} (exec-body-size limit bs "abc")]
      (is (= 400 (:status response)))
      (is (str/includes? (str (:body response)) "E_BAD_REQUEST")))))

;; -- extract-client-ip (codex 7 / claude 3) --------------------------------

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

;; -- wrap-bootstrap-rate-limit (codex 4 / H4) ------------------------------

(deftest bootstrap-rate-limit-allows-up-to-cap
  (testing "Up to `limit-per-minute` requests from the same IP pass through."
    (let [seen (atom 0)
          h    (mw/wrap-bootstrap-rate-limit
                (fn [_] (swap! seen inc) {:status 201})
                {:limit-per-minute 3 :window-ms 60000})]
      (dotimes [_ 3]
        (let [r (h {:request-method :post :uri "/v1/bootstrap"
                    :cauth/client-ip "1.2.3.4"})]
          (is (= 201 (:status r)))))
      (is (= 3 @seen)))))

(deftest bootstrap-rate-limit-rejects-over-cap
  (testing "The fourth request (limit=3) is rejected with 429."
    (let [h (mw/wrap-bootstrap-rate-limit
             (fn [_] {:status 201})
             {:limit-per-minute 3 :window-ms 60000})]
      (dotimes [_ 3]
        (h {:request-method :post :uri "/v1/bootstrap"
            :cauth/client-ip "1.2.3.4"}))
      (let [r (h {:request-method :post :uri "/v1/bootstrap"
                  :cauth/client-ip "1.2.3.4"})]
        (is (= 429 (:status r)))
        (is (str/includes? (str (:body r)) "E_RATE"))))))

(deftest bootstrap-rate-limit-only-applies-to-bootstrap
  (testing "Other endpoints are not rate-limited by this middleware."
    (let [h (mw/wrap-bootstrap-rate-limit
             (fn [_] {:status 200})
             {:limit-per-minute 1 :window-ms 60000})]
      (dotimes [_ 5]
        (let [r (h {:request-method :post :uri "/v1/verify"
                    :cauth/client-ip "1.2.3.4"})]
          (is (= 200 (:status r))))))))

(deftest bootstrap-rate-limit-isolates-by-ip
  (testing "Different IPs have independent buckets."
    (let [h (mw/wrap-bootstrap-rate-limit
             (fn [_] {:status 201})
             {:limit-per-minute 1 :window-ms 60000})]
      (is (= 201 (:status (h {:request-method :post :uri "/v1/bootstrap"
                              :cauth/client-ip "1.2.3.4"}))))
      ;; Another IP — still passes.
      (is (= 201 (:status (h {:request-method :post :uri "/v1/bootstrap"
                              :cauth/client-ip "5.6.7.8"}))))
      ;; First IP again — now over its bucket.
      (let [r (h {:request-method :post :uri "/v1/bootstrap"
                  :cauth/client-ip "1.2.3.4"})]
        (is (= 429 (:status r)))))))
