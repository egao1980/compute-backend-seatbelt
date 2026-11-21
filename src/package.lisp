;;;; compute-backend-seatbelt — the macOS Seatbelt confining backend (R4d-1,
;;;; cl-stack docs/capabilities/confinement.md). A CONFINEMENT becomes an SBPL
;;;; profile and a launch argv `/usr/bin/sandbox-exec -p PROFILE -- argv…`;
;;;; compute-protocol's CONFINE-COMMAND does the rest (check, resolve, private
;;;; tmp, environment scrub). Nothing here runs the command.

(defpackage #:compute-backend-seatbelt
  (:use #:cl)
  (:nicknames #:stack-compute-seatbelt)
  (:local-nicknames (#:sc #:compute-protocol) (#:pp #:process-protocol))
  (:export #:+sandbox-exec+
           #:+seatbelt-features+
           #:+seatbelt-base-profile+
           #:+seatbelt-metadata-literals+
           #:+seatbelt-extra-read-paths+
           #:+seatbelt-network-services+
           #:+profile-size-limit+
           #:+limit-shell+

           #:sbpl-string
           #:sbpl-path
           #:seatbelt-profile
           #:seatbelt-limit-argv
           #:seatbelt-argv

           #:seatbelt-backend
           #:make-seatbelt-backend
           #:seatbelt-backend-sandbox-exec
           #:use-seatbelt-backend))

(in-package #:compute-backend-seatbelt)
