(in-package #:compute-backend-seatbelt)

;;; SEATBELT-BACKEND: compute-protocol's confining-backend protocol
;;; (CONFINEMENT-FEATURES, CONFINEMENT-AVAILABLE-P, BACKEND-CONFINE-ARGV) over
;;; sandbox-exec. compute-protocol 0.3.0 has no backend registry: a consumer
;;; makes one with MAKE-SEATBELT-BACKEND and passes it to SC:CONFINE-COMMAND,
;;; SC:RUN-CONFINED or the supervisor's compute executor. Loading this system
;;; changes no global; USE-SEATBELT-BACKEND makes one the default
;;; SC:*COMPUTE-BACKEND* (as compute-backend-landlock's USE-LANDLOCK-BACKEND).
;;;
;;; Given (R4d-1 contract): +SEATBELT-FEATURES+, the class, its constructor and
;;; reader, USE-SEATBELT-BACKEND, CONFINEMENT-FEATURES. Implemented in R4d-1: CONFINEMENT-AVAILABLE-P,
;;; BACKEND-CONFINE-ARGV.

(defparameter +seatbelt-features+
  '(:filesystem :read-system :deny-read :network-none :network-allow :network-ports
    :cpu-limit :file-size-limit :process-limit)
  "What Seatbelt enforces on macOS, in SC:+CONFINEMENT-FEATURES+ order. Not
:NETWORK-HOSTS (needs a filtering proxy, R4d-5) nor :MEMORY-LIMIT (macOS does not
enforce RLIMIT_AS).")

(defclass seatbelt-backend (sc:confining-backend)
  ((sandbox-exec :initarg :sandbox-exec :reader seatbelt-backend-sandbox-exec
                 :initform +sandbox-exec+
                 :documentation "Absolute path of the sandbox-exec executable.")
   (availability :initform nil :accessor %seatbelt-availability
                 :documentation "NIL until probed, then (available-p . reason)."))
  (:documentation "Confines one command and its children with a generated Seatbelt
\(SBPL) profile run through sandbox-exec (macOS only). Never runs anything itself,
except the one availability probe of sandbox-exec."))

(defun make-seatbelt-backend (&key (sandbox-exec +sandbox-exec+))
  "A SEATBELT-BACKEND. SANDBOX-EXEC (a string, absolute) is for tests and unusual
installs."
  (check-type sandbox-exec string)
  (make-instance 'seatbelt-backend :sandbox-exec sandbox-exec))

(defun use-seatbelt-backend (&rest args)
  "Make a SEATBELT-BACKEND (MAKE-SEATBELT-BACKEND ARGS) the default SC:*COMPUTE-BACKEND*."
  (setf sc:*compute-backend* (apply #'make-seatbelt-backend args)))

(defmethod print-object ((b seatbelt-backend) stream)
  (print-unreadable-object (b stream :type t)
    (write-string (seatbelt-backend-sandbox-exec b) stream)))

(defmethod sc:confinement-features ((backend seatbelt-backend))
  (if (uiop:os-macosx-p)
      (copy-list +seatbelt-features+)
      '()))

(defmethod sc:confinement-available-p ((backend seatbelt-backend))
  "→ (values available-p reason). Not macOS → NIL \"not macOS\" (nothing is run).
SANDBOX-EXEC missing or not executable → NIL, a reason naming the path. Otherwise one
probe, cached in the backend: SANDBOX-EXEC -p \"(version 1)(allow default)\" --
/usr/bin/true through PROCESS-PROTOCOL:RUN; exit 0 → T NIL, else NIL and a reason
starting \"sandbox-exec does not run here\" with the probe's trimmed stderr (e.g. the
harness itself already sandboxed: sandbox_apply EPERM)."
  (let ((path (seatbelt-backend-sandbox-exec backend)))
    (cond ((not (uiop:os-macosx-p))
           (values nil "not macOS"))
          ((let ((pathname (uiop:parse-native-namestring path)))
             (or (not (uiop:file-exists-p pathname))
                 (uiop:directory-exists-p pathname)))
           ;; Not cached: a stat, and sandbox-exec may appear later.
           (values nil (format nil "~a: no such executable file" path)))
          (t
           ;; Two threads probing at once store equal answers; the last SETF wins.
           (let ((cached (or (%seatbelt-availability backend)
                             (setf (%seatbelt-availability backend)
                                   (%probe-sandbox-exec path)))))
             (values (car cached) (cdr cached)))))))

(defun %probe-sandbox-exec (path)
  "Run PATH -p \"(version 1)(allow default)\" -- /usr/bin/true once.
→ (available-p . reason). A spawn failure (e.g. PATH not executable) is
process-protocol's PROCESS-ERROR, answered as unavailable with a reason naming PATH."
  (handler-case
      (multiple-value-bind (code out err)
          (pp:run (list path "-p" "(version 1)(allow default)" "--" "/usr/bin/true")
                  :output :string :error-output :string)
        (declare (ignore out))
        (if (eql code 0)
            (cons t nil)
            (cons nil (format nil "sandbox-exec does not run here: ~a (~a exited ~a)"
                              (string-trim '(#\Space #\Tab #\Newline #\Return) (or err ""))
                              path code))))
    (pp:process-error (e)
      (cons nil (format nil "sandbox-exec does not run here: ~a cannot be run: ~a" path e)))))

(defmethod sc:backend-confine-argv ((backend seatbelt-backend) confinement argv directory tmp)
  "→ (values (SEATBELT-ARGV CONFINEMENT (SEATBELT-PROFILE CONFINEMENT TMP) ARGV
:SANDBOX-EXEC (SEATBELT-BACKEND-SANDBOX-EXEC BACKEND))
          ((\"STACK_COMPUTE_CONFINEMENT\" . \"seatbelt\"))
          NIL)
CONFINEMENT is resolved and checked by SC:CONFINE-COMMAND; DIRECTORY needs no rule of
its own (it is readable under the confinement, CONFINE-COMMAND checked it). No
cleanups: the profile is inline, nothing is written."
  (declare (ignore directory))
  (values (seatbelt-argv confinement (seatbelt-profile confinement tmp) argv
                         :sandbox-exec (seatbelt-backend-sandbox-exec backend))
          (list (cons "STACK_COMPUTE_CONFINEMENT" "seatbelt"))
          nil))
