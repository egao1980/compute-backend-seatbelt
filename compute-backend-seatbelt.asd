(defsystem "compute-backend-seatbelt"
  :version "0.1.0"
  :description "Confining compute-protocol backend: macOS Seatbelt (sandbox-exec, generated SBPL profile)"
  :author "egao1980"
  :license "MIT"
  :depends-on ((:version "compute-protocol" "0.3.1")
               (:version "process-protocol" "0.4.1")
               (:version "process-backend-uiop" "0.3.1")
               "uiop")
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "profile")          ; pure: SBPL strings, SEATBELT-PROFILE, SEATBELT-ARGV
               (:file "backend"))         ; SEATBELT-BACKEND: features, availability, confine argv
  :in-order-to ((test-op (test-op "compute-backend-seatbelt/tests"))))

(defsystem "compute-backend-seatbelt/tests"
  :depends-on ("compute-backend-seatbelt"
               (:feature :sbcl "compute-protocol/confinement-suite")
               "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "support")
               (:file "smoke-test")
               (:file "profile-test")     ; every OS: escaping, goldens, rule order
               (:file "argv-test")        ; every OS: sandbox-exec argv, limits, size refusal
               (:file "backend-test")     ; every OS: features, availability, checks
               (:file "launch-test")      ; macOS: confine-command end to end
               (:file "tools-test" :if-feature :sbcl)  ; macOS: tools, limits, confined SBCL image
               (:file "suite-test" :if-feature :sbcl)  ; macOS: RUN-CONFINEMENT-SUITE, 21 laws
               (:module "golden"          ; the exact SEATBELT-PROFILE texts
                :components ((:static-file "read-all.sb")
                             (:static-file "read-system.sb")
                             (:static-file "shared-tmp-network-allow.sb")
                             (:static-file "ports-dns-no-tmp.sb")
                             (:static-file "escaping.sb"))))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
