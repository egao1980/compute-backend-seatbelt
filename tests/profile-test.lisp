(in-package #:compute-backend-seatbelt/tests)

;;; R4d-1: the SBPL profile, pure, every OS. Goldens in tests/golden/*.sb are
;;; the spec of SEATBELT-PROFILE's exact text (each compiles with sandbox-exec
;;; on macOS 26: `sandbox-exec -p "$(cat f.sb)" -- /usr/bin/true`).

;;; Escaping

(deftest-parametrize sbpl-string-escapes
    ((in out)
     :ids ("plain" "empty" "space" "quote" "backslash" "backslash-quote" "utf-8" "sbpl-syntax")
     ("abc" "\"abc\"")
     ("" "\"\"")
     ("a b" "\"a b\"")
     ("a\"b" "\"a\\\"b\"")
     ("a\\b" "\"a\\\\b\"")
     ("\\\"" "\"\\\\\\\"\"")
     ("é→ü" "\"é→ü\"")
     ("(x);#y #\"z" "\"(x);#y #\\\"z\""))
  (ok (string= out (seatbelt:sbpl-string in))))

(deftest-parametrize sbpl-path-renders
    ((in out)
     :ids ("directory" "root" "file" "dotfile" "quote-kept-raw" "deep")
     ((u "/w/area/") "/w/area")
     ((u "/") "/")
     ((u "/w/notes.txt") "/w/notes.txt")
     ((u "/h/.netrc") "/h/.netrc")
     ((u "/w/a\"b/") "/w/a\"b")
     ((u "/private/var/folders/xy/T/") "/private/var/folders/xy/T"))
  (ok (string= out (seatbelt:sbpl-path in))))

;;; Goldens

(deftest-parametrize profile-golden
    ((name confinement tmp)
     :ids ("read-all" "read-system" "shared-tmp-network-allow" "ports-dns-no-tmp" "escaping")
     ("read-all"
      (sc:make-confinement :writable (list (u "/w/area/"))
                           :readable (list (u "/w/ro/") (u "/w/notes.txt"))
                           :deny-read (list (u "/h/.ssh/") (u "/h/.netrc")))
      +test-tmp+)
     ("read-system"
      (sc:make-confinement :writable (list (u "/w/area/"))
                           :readable (list (u "/w/ro/") (u "/w/notes.txt"))
                           :read :system
                           :deny-read (list (u "/w/ro/secret/")))
      +test-tmp+)
     ("shared-tmp-network-allow"
      (sc:make-confinement :writable (list (u "/w/area/")) :deny-read '()
                           :tmp :shared :network :allow)
      nil)
     ("ports-dns-no-tmp"
      (sc:make-confinement :writable (list (u "/w/area/"))
                           :deny-read (list (u "/w/area/.git-credentials"))
                           :tmp :none
                           :network (policy :dns "*" 443 "*" 80 "*" 443))
      nil)
     ("escaping"
      (sc:make-confinement :writable (list (u "/w/we\"ir d\\é (x);#y/"))
                           :deny-read (list (u "/w/we\"ir d\\é (x);#y/.ssh/")))
      +test-tmp+))
  (let ((profile (golden-profile confinement tmp)))
    (ok (string= (golden-text name) profile)
        (format nil "golden ~a.sb; got:~%~a" name profile))))

;;; Properties

(defun %golden-confinements ()
  (list (sc:make-confinement :writable (list (u "/w/area/"))
                             :deny-read (list (u "/h/.ssh/") (u "/w/area/.env")))
        (sc:make-confinement :writable (list (u "/w/area/") (u "/w/scratch/"))
                             :readable (list (u "/w/ro/"))
                             :read :system
                             :deny-read (list (u "/w/area/secret/"))
                             :network :allow)
        (sc:make-confinement :writable '() :deny-read '() :tmp :shared
                             :network (policy "*" 22))))

(deftest profile-starts-with-the-base
  (dolist (c (%golden-confinements))
    (let ((lines (profile-lines (golden-profile c +test-tmp+))))
      (ok (equal seatbelt:+seatbelt-base-profile+
                 (subseq lines 0 (min (length lines) (length seatbelt:+seatbelt-base-profile+))))))))

(deftest profile-line-shape
  (dolist (c (%golden-confinements))
    (let ((profile (golden-profile c +test-tmp+)))
      (ok (char= #\Newline (char profile (1- (length profile)))) "ends with a newline")
      (ok (string= profile (golden-profile c +test-tmp+)) "deterministic")
      (ok (every (lambda (line) (and (char= #\( (char line 0))
                                     (char= #\) (char line (1- (length line))))))
                 (profile-lines profile))
          "one rule per line"))))

(deftest profile-deny-comes-after-every-file-allow
  (dolist (c (%golden-confinements))
    (let* ((lines (profile-lines (golden-profile c +test-tmp+)))
           (first-deny (position-if (lambda (l) (uiop:string-prefix-p "(deny file-" l)) lines))
           (last-allow (position-if (lambda (l) (uiop:string-prefix-p "(allow file-" l)) lines
                                    :from-end t)))
      (when (sc:confinement-deny-read c)
        (ok (and first-deny last-allow (> first-deny last-allow))
            "deny-read rules follow every file allow (last match wins: deny beats writable)")))))

(deftest profile-read-modes
  (let ((all (profile-lines (golden-profile (sc:make-confinement :writable (list (u "/w/a/")))
                                            +test-tmp+)))
        (sys (profile-lines (golden-profile (sc:make-confinement :writable (list (u "/w/a/"))
                                                                 :read :system)
                                            +test-tmp+))))
    (ok (member "(allow file-read*)" all :test #'string=))
    (ng (find-if (lambda (l) (search "file-read-metadata" l)) all) "read-all needs no metadata rules")
    (ng (member "(allow file-read*)" sys :test #'string=) "read-system never allows all reads")
    (ok (member "(allow file-read* (literal \"/\"))" sys :test #'string=))
    (ok (member "(allow file-read* (subpath \"/private/var/select\"))" sys :test #'string=))
    (ok (member "(allow file-read-metadata (literal \"/w\"))" sys :test #'string=)
        "ancestors of the writable area")
    (ng (member "(allow file-read-metadata (literal \"/\"))" sys :test #'string=)
        "the root is not an ancestor rule")))

(deftest profile-network-modes
  (flet ((net-lines (network)
           (remove-if-not (lambda (l) (search "network" l))
                          (profile-lines (golden-profile (sc:make-confinement :network network)
                                                         +test-tmp+)))))
    (ok (null (net-lines :none)) ":none adds no network rule (deny default)")
    (ok (equal "(allow network*)" (first (net-lines :allow))))
    (ok (equal '("(allow network-outbound (remote ip \"*:8080\"))")
               (net-lines (policy "*" 8080)))
        "no DNS: ports only")))

(deftest profile-user-paths-never-in-a-regex
  (let* ((weird (u "/w/a.*[x]$^/"))
         (lines (profile-lines (golden-profile (sc:make-confinement :writable (list weird)
                                                                    :readable (list (u "/w/r+?/"))
                                                                    :read :system)
                                               +test-tmp+)))
         (regex-lines (remove-if-not (lambda (l) (search "(regex" l)) lines)))
    (ok (equal '("(allow file-read* file-write* file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))")
               regex-lines)
        "only the base tty rule uses a regex")
    (ok (member "(allow file-read* file-write* (subpath \"/w/a.*[x]$^\"))" lines :test #'string=))
    (ok (member "(allow file-read* (subpath \"/w/r+?\"))" lines :test #'string=))))

(deftest profile-devices-always-writable
  (let ((lines (profile-lines (golden-profile (sc:make-confinement :writable '() :tmp :none
                                                                   :read :system :deny-read '())
                                              nil))))
    (dolist (d sc:+device-paths+)
      (ok (member (format nil "(allow file-read* file-write* file-ioctl (literal \"~a\"))" d)
                  lines :test #'string=)
          d))
    (ng (find-if (lambda (l) (search "(subpath" l) )
                 (remove-if-not (lambda (l) (search "file-write*" l)) lines))
        "no writable directory at all")))
