(in-package #:compute-backend-seatbelt/tests)

;;; R4d-1: the sandbox-exec argv and the limits prefix, pure, every OS.

(defparameter +exec-tail+ " && exec \"$@\"")

(deftest argv-wraps-the-command
  (let ((c (sc:make-confinement :deny-read '())))
    (ok (equal '("/usr/bin/sandbox-exec" "-p" "PROFILE" "--" "/bin/echo" "x")
               (seatbelt:seatbelt-argv c "PROFILE" '("/bin/echo" "x"))))
    (ok (equal '("/opt/x/sandbox-exec" "-p" "P" "--" "/bin/true")
               (seatbelt:seatbelt-argv c "P" '("/bin/true") :sandbox-exec "/opt/x/sandbox-exec")))
    (ok (string= "/usr/bin/sandbox-exec" seatbelt:+sandbox-exec+))))

(deftest-parametrize limit-script
    ((args script)
     :ids ("cpu" "file-size" "file-size-rounds-down" "file-size-below-1k" "processes" "all-in-order")
     ('(:cpu-limit 5) "ulimit -t 5")
     ('(:file-size-limit 4096) "ulimit -f 4")
     ('(:file-size-limit 1500) "ulimit -f 1")
     ('(:file-size-limit 1000) "ulimit -f 0")
     ('(:process-limit 64) "ulimit -u 64")
     ('(:process-limit 64 :file-size-limit 4096 :cpu-limit 5)
      "ulimit -t 5 && ulimit -f 4 && ulimit -u 64"))
  (let ((c (apply #'sc:make-confinement args)))
    (ok (equal (list "/bin/bash" "-c" (concatenate 'string script +exec-tail+) "stack-compute-limits")
               (seatbelt:seatbelt-limit-argv c)))
    (ok (string= "/bin/bash" seatbelt:+limit-shell+))))

(deftest-parametrize no-limit-prefix
    ((args)
     :ids ("none" "memory-only" "wall-clock-only")
     ('())
     ('(:memory-limit 1000000))
     ('(:wall-clock 5)))
  (ok (null (seatbelt:seatbelt-limit-argv (apply #'sc:make-confinement args)))
      "memory and wall clock are not applied by the backend"))

(deftest argv-puts-limits-inside-the-sandbox
  (let ((c (sc:make-confinement :cpu-limit 2)))
    (ok (equal (list* "/usr/bin/sandbox-exec" "-p" "P" "--"
                      (append (seatbelt:seatbelt-limit-argv c) '("/bin/sh" "-c" "true")))
               (seatbelt:seatbelt-argv c "P" '("/bin/sh" "-c" "true"))))))

(deftest-parametrize argv-profile-size
    ((profile octets accepted)
     :ids ("at-limit" "one-over" "utf-8-at-limit" "utf-8-over")
     ((make-string 65536 :initial-element #\a) 65536 t)
     ((make-string 65537 :initial-element #\a) 65537 nil)
     ((make-string 32768 :initial-element (code-char 233)) 65536 t)
     ((make-string 32769 :initial-element (code-char 233)) 65538 nil))
  (let* ((c (sc:make-confinement))
         (e (condition-of sc:invalid-confinement (seatbelt:seatbelt-argv c profile '("/bin/true")))))
    (ok (= 65536 seatbelt:+profile-size-limit+))
    (if accepted
        (ok (null e) "accepted")
        (progn
          (ok e "refused")
          (ok (and e (eq :profile (sc:invalid-confinement-field e))))
          (ok (and e (eql octets (sc:invalid-confinement-value e))) "value: the octet length")))))

(deftest argv-refuses-a-huge-confinement
  (let* ((c (sc:make-confinement
             :read :system
             :readable (loop for i below 2000
                             collect (u (format nil "/w/readable/number-~5,'0d/with/a/rather/long/name/" i)))))
         (profile (golden-profile c +test-tmp+)))
    (ok (> (length profile) seatbelt:+profile-size-limit+))
    (ok (condition-of sc:invalid-confinement (seatbelt:seatbelt-argv c profile '("/bin/true"))))))
