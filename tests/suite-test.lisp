(in-package #:compute-backend-seatbelt/tests)

;;; R4d-1 verdict: compute-protocol's confinement suite against the real
;;; backend (macOS). Seatbelt has :deny-read, so the base is READ :ALL and
;;; every one of the 21 cases runs (none needs :network-hosts or
;;; :memory-limit); no failures allowed.

(deftest-macos suite-all-laws
  (multiple-value-bind (failures ran skipped)
      (stack-compute-suite:run-confinement-suite *backend*)
    (ok (null failures)
        (format nil "~{~&  ~s~}" failures))
    (ok (equal (stack-compute-suite:suite-case-names) ran) "all 21 cases ran")
    (ok (= 21 (length ran)))
    (ok (null skipped) (format nil "skipped ~s" skipped))))

(deftest suite-refused-off-macos
  (if (macos-p)
      (skip "macOS runs the suite")
      (ok (condition-of sc:confinement-unavailable
            (stack-compute-suite:run-confinement-suite *backend*))
          "off macOS the suite refuses: the backend is unavailable")))
