;;;; Skeleton. The backend lands in milestone R4d-1 (cl-stack
;;;; docs/capabilities/confinement.md); its contract starts the team-solve run.

(defpackage #:compute-backend-seatbelt
  (:use #:cl)
  (:nicknames #:stack-compute-seatbelt)
  (:local-nicknames (#:sc #:compute-protocol)))

(in-package #:compute-backend-seatbelt)
