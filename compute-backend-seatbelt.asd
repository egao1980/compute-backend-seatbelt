(defsystem "compute-backend-seatbelt"
  :version "0.0.1"
  :description "Confining compute-protocol backend: macOS Seatbelt (sandbox-exec, generated SBPL profile)"
  :author "egao1980"
  :license "MIT"
  :depends-on ("compute-protocol")
  :serial t
  :pathname "src"
  :components ((:file "package"))
  :in-order-to ((test-op (test-op "compute-backend-seatbelt/tests"))))

(defsystem "compute-backend-seatbelt/tests"
  :depends-on ("compute-backend-seatbelt" "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "smoke-test"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
