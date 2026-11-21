(in-package #:compute-backend-seatbelt/tests)

;;; R4d-1: SC:CONFINE-COMMAND through the Seatbelt backend, end to end (macOS).

(deftest-macos launch-shape
  (with-temp-tree (root "area/")
    (let ((c (area-confinement (sub root "area/"))))
      (sc:with-confined-launch (l *backend* c '("/bin/echo" "hi"))
        (let ((argv (sc:confined-launch-argv l))
              (env (sc:confined-launch-env l)))
          (ok (equal '("/usr/bin/sandbox-exec" "-p") (subseq argv 0 2)))
          (ok (string= "--" (fourth argv)))
          (ok (equal '("/bin/echo" "hi") (nthcdr 4 argv)) "no limits: the command follows --")
          (ok (string= (third argv)
                       (seatbelt:seatbelt-profile (sc:confined-launch-confinement l)
                                                  (sc:confined-launch-tmp l)))
              "the inline profile is SEATBELT-PROFILE of the resolved confinement and the launch tmp")
          (ok (search (seatbelt:sbpl-string (seatbelt:sbpl-path (sc:confined-launch-tmp l)))
                      (third argv))
              "the private tmp is in the profile")
          (ok (equal "seatbelt" (cdr (assoc "STACK_COMPUTE_CONFINEMENT" env :test #'string=))))
          (ok (equal (ns (sc:confined-launch-tmp l))
                     (cdr (assoc "TMPDIR" env :test #'string=))))
          (ok (equal (ns (physical-dir (sub root "area/")))
                     (ns (sc:confined-launch-directory l)))))))))

(deftest-macos launch-release
  (with-temp-tree (root "area/")
    (let* ((l (sc:confine-command *backend* (area-confinement (sub root "area/")) '("/bin/true")))
           (tmp (sc:confined-launch-tmp l)))
      (ok (uiop:directory-exists-p tmp))
      (ok (eq t (sc:release-confined-launch l)) "no backend cleanups: release just removes tmp")
      (ng (uiop:directory-exists-p tmp))
      (ng (sc:release-confined-launch l)))))

(deftest-macos launch-with-limits
  (with-temp-tree (root "area/")
    (sc:with-confined-launch (l *backend* (area-confinement (sub root "area/") :cpu-limit 30)
                                '("/bin/echo" "x"))
      (let ((argv (sc:confined-launch-argv l)))
        (ok (equal (list* "--" (append (seatbelt:seatbelt-limit-argv (sc:confined-launch-confinement l))
                                       '("/bin/echo" "x")))
                   (nthcdr 3 argv)))))))

(deftest-macos launch-runs
  (with-temp-tree (root "area/")
    (multiple-value-bind (code out) (run-in (area-confinement (sub root "area/")) '("/bin/echo" "hi"))
      (ok (eql 0 code))
      (ok (equal (format nil "hi~%") out)))))

(deftest-macos launch-refuses-an-oversized-profile
  (with-temp-tree (root "area/")
    (let* ((before (length (private-tmp-dirs)))
           (c (area-confinement
               (sub root "area/")
               :read :system
               :readable (loop for i below 2000
                               collect (sub root (format nil "missing/number-~5,'0d/with/a/long/name/" i)))))
           (e (condition-of sc:invalid-confinement (sc:confine-command *backend* c '("/bin/true")))))
      (ok e)
      (ok (and e (eq :profile (sc:invalid-confinement-field e))))
      (ok (= before (length (private-tmp-dirs))) "the private tmp made for it was removed"))))

(deftest-macos launch-unavailable-backend
  (with-temp-tree (root "area/")
    (let ((before (length (private-tmp-dirs))))
      (ok (condition-of sc:confinement-unavailable
            (sc:confine-command (seatbelt:make-seatbelt-backend :sandbox-exec "/nonexistent/sandbox-exec")
                                (area-confinement (sub root "area/")) '("/bin/true"))))
      (ok (= before (length (private-tmp-dirs))) "nothing created"))))
