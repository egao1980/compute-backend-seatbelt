(in-package #:compute-backend-seatbelt/tests)

;;; Test support. Profile and argv tests are pure and run on every OS. Tests
;;; that run sandbox-exec are DEFTEST-MACOS: elsewhere they record a skip.

(defun macos-p () (uiop:os-macosx-p))

(defparameter +skip-note+
  "Seatbelt is macOS only: skipped on this OS (the backend loads, has no features and is unavailable here)")

(defmacro deftest-macos (name &body body)
  "A DEFTEST whose BODY runs on macOS; elsewhere it records a skip with a note."
  `(deftest ,name
     (if (macos-p)
         (progn ,@body)
         (skip +skip-note+))))

(defmacro condition-of (type &body body)
  "The condition of TYPE BODY signals, or NIL when it returns normally."
  `(handler-case (progn ,@body nil)
     (,type (c) c)))

(defun u (namestring)
  "A Unix namestring as a pathname, the same on every OS (golden inputs)."
  (uiop:parse-unix-namestring namestring))

;;; Golden inputs: fixed paths so SEATBELT-PROFILE is a pure function.

(defparameter +test-system-paths+
  (list (u "/usr/") (u "/System/") (u "/opt/homebrew/Cellar/sbcl/2.6.9/lib/sbcl/")))

(defparameter +test-tmp+ (u "/t/stack-compute-0123456789abcdef/"))

(defparameter +test-shared-tmp+ (u "/private/var/folders/xy/T/"))

(defun golden-profile (confinement tmp)
  (seatbelt:seatbelt-profile confinement tmp
                             :system-read-paths +test-system-paths+
                             :shared-tmp +test-shared-tmp+))

(defun golden-text (name)
  "tests/golden/NAME.sb (UTF-8)."
  (uiop:read-file-string
   (asdf:system-relative-pathname "compute-backend-seatbelt/tests"
                                  (format nil "tests/golden/~a.sb" name))
   :external-format :utf-8))

(defun profile-lines (profile)
  (remove "" (uiop:split-string profile :separator '(#\Newline)) :test #'string=))

(defun policy (&rest host-port)
  "A SANDBOX-NETWORK-POLICY from host port pairs; a leading :DNS sets DNS."
  (let ((dns (when (eq (first host-port) :dns) (pop host-port) t)))
    (sc:make-sandbox-network-policy
     :dns dns
     :egress (loop for (host port) on host-port by #'cddr
                   collect (sc:make-egress-rule :host host :port port)))))

;;; Live helpers (macOS)

(defvar *backend* (seatbelt:make-seatbelt-backend))

(defun physical-dir (p)
  (uiop:ensure-directory-pathname (truename p)))

(defun make-temp-tree (&rest subdirs)
  "A new physical temp directory with SUBDIRS created in it. → the root."
  (let ((root (physical-dir
               (ensure-directories-exist
                (merge-pathnames (format nil "seatbelt-test-~36r-~36r/"
                                         (get-universal-time)
                                         (random (expt 36 6) (make-random-state t)))
                                 (uiop:temporary-directory))))))
    (dolist (d subdirs)
      (ensure-directories-exist (merge-pathnames (uiop:ensure-directory-pathname d) root)))
    root))

(defmacro with-temp-tree ((var &rest subdirs) &body body)
  `(let ((,var (make-temp-tree ,@subdirs)))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,var :validate t :if-does-not-exist :ignore))))

(defun sub (root rel)
  (merge-pathnames (uiop:parse-unix-namestring rel) root))

(defun ns (p) (uiop:native-namestring p))

(defun write-text (path text)
  (ensure-directories-exist path)
  (with-open-file (s path :direction :output :if-exists :supersede)
    (write-string text s))
  path)

(defun sh (script)
  (list "/bin/sh" "-c" script))

(defun run-in (confinement argv &rest keys)
  "SC:RUN-CONFINED on *BACKEND* → (values exit-code stdout stderr)."
  (let ((r (apply #'sc:run-confined *backend* confinement argv keys)))
    (values (sc:sandbox-result-exit-code r)
            (sc:sandbox-result-stdout r)
            (sc:sandbox-result-stderr r))))

(defun area-confinement (area &rest keys)
  "The plan-mode shape: AREA writable, read all minus the default deny-read, no network."
  (apply #'sc:make-confinement :writable (list area) keys))

(defun private-tmp-dirs ()
  "The stack-compute-* directories now in the physical system temp directory."
  (remove-if-not (lambda (d)
                   (uiop:string-prefix-p "stack-compute-" (car (last (pathname-directory d)))))
                 (uiop:subdirectories (sc:physical-path (uiop:temporary-directory)))))
