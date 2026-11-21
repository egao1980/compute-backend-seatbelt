(in-package #:compute-backend-seatbelt/tests)

;;; R4d-1: the backend object, its features and availability. Every OS: off
;;; macOS the backend loads, claims nothing and is unavailable.

(deftest backend-construction
  (let ((b (seatbelt:make-seatbelt-backend)))
    (ok (typep b 'sc:confining-backend))
    (ok (typep b 'sc:compute-backend))
    (ok (string= "/usr/bin/sandbox-exec" (seatbelt:seatbelt-backend-sandbox-exec b))))
  (ok (string= "/opt/x/sandbox-exec"
               (seatbelt:seatbelt-backend-sandbox-exec
                (seatbelt:make-seatbelt-backend :sandbox-exec "/opt/x/sandbox-exec"))))
  (ok (signals (seatbelt:make-seatbelt-backend :sandbox-exec 42) 'type-error)))

(deftest backend-feature-table
  (ok (equal '(:filesystem :read-system :deny-read :network-none :network-allow :network-ports
               :cpu-limit :file-size-limit :process-limit)
             seatbelt:+seatbelt-features+))
  (ok (equal seatbelt:+seatbelt-features+
             (remove-if-not (lambda (f) (member f seatbelt:+seatbelt-features+))
                            sc:+confinement-features+))
      "a subset of +confinement-features+, in its order")
  (ng (member :network-hosts seatbelt:+seatbelt-features+) "host allowlists need the proxy (R4d-5)")
  (ng (member :memory-limit seatbelt:+seatbelt-features+) "macOS ignores RLIMIT_AS"))

(deftest backend-features-per-os
  (let ((b (seatbelt:make-seatbelt-backend)))
    (if (macos-p)
        (progn (ok (equal seatbelt:+seatbelt-features+ (sc:confinement-features b)))
               (ok (sc:confinement-supports-p b :deny-read))
               (ng (sc:confinement-supports-p b :memory-limit)))
        (ok (null (sc:confinement-features b)) "no features off macOS"))))

(deftest backend-availability
  (multiple-value-bind (ok-p reason) (sc:confinement-available-p (seatbelt:make-seatbelt-backend))
    (if (macos-p)
        (progn (ok (eq t ok-p) (format nil "sandbox-exec runs here (reason ~s)" reason))
               (ok (null reason)))
        (progn (ng ok-p)
               (ok (equal "not macOS" reason)))))
  (multiple-value-bind (ok-p reason)
      (sc:confinement-available-p (seatbelt:make-seatbelt-backend :sandbox-exec "/nonexistent/sandbox-exec"))
    (ng ok-p)
    (ok (stringp reason))
    (when (macos-p)
      (ok (search "/nonexistent/sandbox-exec" reason) "the reason names the missing path"))))

(deftest-macos backend-availability-probe-fails
  ;; An executable that is not a working sandbox-exec (as when the harness is
  ;; itself sandboxed and sandbox_apply fails): the probe's exit code decides.
  (let ((b (seatbelt:make-seatbelt-backend :sandbox-exec "/usr/bin/false")))
    (multiple-value-bind (ok-p reason) (sc:confinement-available-p b)
      (ng ok-p)
      (ok (and (stringp reason) (uiop:string-prefix-p "sandbox-exec does not run here" reason))
          reason))
    (multiple-value-bind (ok-p2 reason2) (sc:confinement-available-p b)
      (ng ok-p2)
      (ok (stringp reason2) "the cached answer is the same"))))

(deftest backend-check-off-macos
  (unless (macos-p)
    (let ((e (condition-of sc:confinement-unavailable
               (sc:check-confinement (seatbelt:make-seatbelt-backend)
                                     (sc:make-confinement :writable '("/w/"))))))
      (ok e)
      (ok (and e (equal "not macOS" (sc:confinement-unavailable-reason e))))))
  (when (macos-p)
    (skip "off-macOS refusal")))

(deftest-parametrize backend-check-refuses
    ((args missing)
     :ids ("memory-limit" "network-hosts" "both")
     ('(:memory-limit 1000000) '(:memory-limit))
     ((list :network (policy "example.com" 443)) '(:network-hosts))
     ((list :network (policy "*" 80 "example.com" 443) :memory-limit 1000000)
      '(:network-hosts :memory-limit)))
  (if (macos-p)
      (let ((e (condition-of sc:confinement-unsupported
                 (sc:check-confinement *backend* (apply #'sc:make-confinement args)))))
        (ok e)
        (ok (and e (equal missing (sc:confinement-unsupported-missing e)))))
      (skip +skip-note+)))

(deftest-parametrize backend-check-accepts
    ((args)
     :ids ("default" "read-system" "allow" "ports" "limits")
     ('())
     ('(:read :system))
     ('(:network :allow))
     ((list :network (policy :dns "*" 443)))
     ('(:cpu-limit 5 :file-size-limit 4096 :process-limit 256 :wall-clock 30)))
  (if (macos-p)
      (let ((c (apply #'sc:make-confinement args)))
        (ok (eq c (sc:check-confinement *backend* c))))
      (skip +skip-note+)))

(deftest backend-use-as-default
  (let ((old sc:*compute-backend*))
    (unwind-protect
         (let ((b (seatbelt:use-seatbelt-backend :sandbox-exec "/opt/x/sandbox-exec")))
           (ok (eq b sc:*compute-backend*))
           (ok (string= "/opt/x/sandbox-exec" (seatbelt:seatbelt-backend-sandbox-exec b))))
      (setf sc:*compute-backend* old))))
