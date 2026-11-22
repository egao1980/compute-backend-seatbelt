(in-package #:compute-backend-seatbelt/tests)

;;; R4d-1: common tools work inside the sandbox, limits apply, and a confined
;;; SBCL image in the area loads the area's system but cannot read the real
;;; project (macOS). The laws themselves are the suite's (suite-test).

(deftest-macos tools-shell-basics
  (with-temp-tree (root "area/")
    (let ((area (sub root "area/")))
      (multiple-value-bind (code out err)
          (run-in (area-confinement area)
                  (sh "echo hello > a.txt && cat a.txt && mkdir sub && ls && /bin/echo done"))
        (ok (eql 0 code) err)
        (ok (equal '("hello" "a.txt" "sub" "done")
                   (uiop:split-string (string-right-trim '(#\Newline) out) :separator '(#\Newline)))
            out)
        (ok (uiop:directory-exists-p (sub area "sub/")))
        (ok (equal (format nil "hello~%") (uiop:read-file-string (sub area "a.txt"))))))))

(deftest-macos tools-user-lookup
  ;; getpwuid needs the opendirectoryd libinfo mach service of the base profile.
  (with-temp-tree (root "area/")
    (let ((me (string-trim '(#\Newline) (uiop:run-program '("/usr/bin/id" "-un") :output :string))))
      (multiple-value-bind (code out) (run-in (area-confinement (sub root "area/")) '("/usr/bin/id" "-un"))
        (ok (eql 0 code))
        (ok (equal me (string-trim '(#\Newline) out)))))))

(deftest-macos tools-write-outside-refused
  (with-temp-tree (root "area/" "outside/")
    (multiple-value-bind (code)
        (run-in (area-confinement (sub root "area/"))
                (sh (format nil "echo x > '~a'" (ns (sub root "outside/new")))))
      (ng (eql 0 code))
      (ng (uiop:file-exists-p (sub root "outside/new"))))))

(deftest-macos tools-cat-to-captured-stdio-read-system
  ;; #2: under READ :SYSTEM a confined cat(1) fstat()s its stdout; that must
  ;; work on whatever RUN-CONFINED captures stdout / stderr with.
  (with-temp-tree (root "area/")
    (let ((c (area-confinement (sub root "area/") :read :system)))
      (dolist (case '(("echo hi > x.txt; cat x.txt" "hi" "")
                      ("echo hi | cat" "hi" "")
                      ("echo hi > x.txt; cat x.txt >&2" "" "hi")
                      ("echo hi | cat | head -1" "hi" "")))
        (destructuring-bind (script want-out want-err) case
          (multiple-value-bind (code out err) (run-in c (sh script))
            (ok (eql 0 code) (format nil "~a: exit ~a, stderr ~s" script code err))
            (ok (equal want-out (string-right-trim '(#\Newline) out)) script)
            (ok (equal want-err (string-right-trim '(#\Newline) err)) script)))))))

(defun %git-works-p ()
  (ignore-errors
   (zerop (nth-value 2 (uiop:run-program '("git" "--version") :ignore-error-status t)))))

(deftest-macos tools-git-status
  (if (not (%git-works-p))
      (skip "git is not installed")
      (with-temp-tree (root "area/")
        (let ((area (sub root "area/")))
          (uiop:run-program (list "git" "init" "-q" (ns area)))
          (write-text (sub area "x.txt") "x")
          (multiple-value-bind (code out err)
              (run-in (area-confinement area) '("/usr/bin/env" "git" "status" "--porcelain"))
            (ok (eql 0 code) err)
            (ok (search "x.txt" out) out))))))

;;; Limits

(deftest-macos tools-cpu-limit
  (with-temp-tree (root "area/")
    (let ((start (get-internal-real-time)))
      (multiple-value-bind (code)
          (run-in (area-confinement (sub root "area/") :cpu-limit 1)
                  (sh "while :; do :; done") :wall-clock 30)
        (ng (eql 0 code) "killed by SIGXCPU, not by the wall clock")
        (ok (< (/ (- (get-internal-real-time) start) internal-time-units-per-second) 20))))))

(deftest-macos tools-file-size-limit
  (with-temp-tree (root "area/")
    (let ((area (sub root "area/")))
      (run-in (area-confinement area :file-size-limit 4096) (sh "head -c 10000 /dev/zero > big"))
      (let ((size (with-open-file (s (sub area "big") :element-type '(unsigned-byte 8)
                                                      :if-does-not-exist nil)
                    (and s (file-length s)))))
        (ok (and size (<= size 4096)) (format nil "big is ~a bytes" size))))))

(deftest-macos tools-process-limit
  ;; RLIMIT_NPROC counts every process of the user: 1 leaves no fork at all.
  (with-temp-tree (root "area/")
    (multiple-value-bind (code out)
        (run-in (area-confinement (sub root "area/") :process-limit 1)
                (sh "/bin/echo child; echo parent"))
      (declare (ignore code))
      (ng (search "child" out) out))))

;;; A confined SBCL image (R4d-4's area image, :read :system)

(defparameter +demo-asd+ "(defsystem \"seatbelt-demo\" :components ((:file \"demo\")))")

(defparameter +demo-lisp+
  "(defpackage #:seatbelt-demo (:use #:cl) (:export #:hello))
(in-package #:seatbelt-demo)
(defun hello () \"hello from the area\")")

(defun %image-argv (area project-file)
  (list (ns sb-ext:*runtime-pathname*)
        "--core" (ns sb-ext:*core-pathname*)
        "--noinform" "--non-interactive" "--no-sysinit" "--no-userinit"
        "--eval" "(require :asdf)"
        "--eval" (format nil "(asdf:load-asd ~s)" (ns (sub area "seatbelt-demo.asd")))
        "--eval" "(asdf:load-system \"seatbelt-demo\")"
        "--eval" "(print (uiop:symbol-call :seatbelt-demo :hello))"
        "--eval" (format nil "(print (handler-case (with-open-file (s ~s) (read-line s) :read) (error () :denied)))"
                         (ns project-file))))

(deftest-macos tools-confined-image-loads-only-the-area
  (with-temp-tree (root "area/")
    (let* ((area (sub root "area/"))
           (project-file (asdf:system-source-file "compute-backend-seatbelt"))
           (sbcl-home (ignore-errors (sb-int:sbcl-homedir-pathname))))
      (write-text (sub area "seatbelt-demo.asd") +demo-asd+)
      (write-text (sub area "demo.lisp") +demo-lisp+)
      (ok (probe-file project-file) "unconfined, this image reads the project")
      (multiple-value-bind (code out err)
          (run-in (area-confinement area :read :system)
                  (%image-argv area project-file)
                  :env (append (list (cons "XDG_CACHE_HOME" (ns (sub area "cache/"))))
                               (when sbcl-home (list (cons "SBCL_HOME" (ns sbcl-home)))))
                  :wall-clock 120)
        (ok (eql 0 code) err)
        (ok (search "\"hello from the area\"" out) out)
        (ok (search ":DENIED" out) "the confined image cannot read the real project")
        (ok (uiop:directory-exists-p (sub area "cache/")) "fasls were written inside the area")))))
