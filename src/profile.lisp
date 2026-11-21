(in-package #:compute-backend-seatbelt)

;;; The SBPL profile and the sandbox-exec argv: pure functions of a resolved
;;; confinement, the same on every OS (the tests run them everywhere).
;;;
;;; Given (R4d-1 contract): the constants below. Implemented in R4d-1:
;;; SBPL-STRING, SBPL-PATH, SEATBELT-PROFILE, SEATBELT-LIMIT-ARGV, SEATBELT-ARGV.
;;;
;;; Locked shape (verified with sandbox-exec on macOS 26, 2026-11-21):
;;; (deny default) + the fixed base allow list, then the read rules, the write
;;; rules, the deny-read rules (last: the last matching SBPL rule wins, so deny
;;; beats every allow), then the network rules. User paths only ever appear as
;;; (subpath "…") or (literal "…") string literals — never in a regex.

(defun %r4d1-pending (name)
  (error "R4d-1 pending: ~a" name))

;;; Constants

(defparameter +sandbox-exec+ "/usr/bin/sandbox-exec"
  "The sandbox-exec executable. Absolute: never looked up on PATH.")

(defparameter +seatbelt-base-profile+
  '("(version 1)"
    "(deny default)"
    "(allow process-exec)"
    "(allow process-fork)"
    "(allow signal (target same-sandbox))"
    "(allow process-info* (target same-sandbox))"
    "(allow sysctl-read)"
    "(allow user-preference-read)"
    "(allow ipc-posix-shm-read-data (ipc-posix-name \"apple.shm.notification_center\"))"
    "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))"
    "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.membership\"))"
    "(allow mach-lookup (global-name \"com.apple.system.notification_center\"))"
    "(allow mach-lookup (global-name \"com.apple.system.logger\"))"
    "(allow mach-lookup (global-name \"com.apple.logd\"))"
    "(allow mach-lookup (global-name \"com.apple.diagnosticd\"))"
    "(allow mach-lookup (global-name \"com.apple.cfprefsd.daemon\"))"
    "(allow mach-lookup (global-name \"com.apple.cfprefsd.agent\"))"
    "(allow pseudo-tty)"
    "(allow file-read* file-write* file-ioctl (literal \"/dev/ptmx\"))"
    "(allow file-read* file-write* file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))")
  "The first lines of every profile, in order. Deny everything, then what a shell,
coreutils, git and SBCL need: exec and fork (children inherit the sandbox),
signals and process info within the sandbox only, sysctl reads, preferences,
user/group lookups (opendirectoryd libinfo + membership: getpwuid, `id -un`),
notifyd, logging, cfprefsd, and terminals (pty allocation, /dev/ptmx, the
/dev/ttysN slaves). No network, no file access: those come from the confinement.")

(defparameter +seatbelt-metadata-literals+
  '("/etc" "/tmp" "/var")
  "macOS's root symlinks (to /private/…): under READ :SYSTEM their metadata stays
readable so a path written /tmp/… or /etc/… still resolves.")

(defparameter +seatbelt-extra-read-paths+
  '("/private/var/select/")
  "Directories READ :SYSTEM keeps readable on top of SC:SYSTEM-READ-PATHS:
/private/var/select/ holds the /bin/sh and xcode-select links (/bin/sh execs
/private/var/select/sh; without it every sh -c fails).")

(defparameter +seatbelt-network-services+
  '("com.apple.dnssd.service" "com.apple.trustd" "com.apple.trustd.agent"
    "com.apple.SecurityServer")
  "mach services NETWORK :ALLOW adds (name resolution through mDNSResponder, TLS
certificate trust). A port policy with DNS adds only the first.")

(defparameter +profile-size-limit+ 65536
  "Largest profile, in UTF-8 octets, SEATBELT-ARGV accepts. sandbox-exec refuses a
profile whose compiled form exceeds 65535 bytes (\"data object length … exceeds
maximum\") whether it comes from -p or -f; compiled profiles were always smaller
than their source in local measurements, so a source bound is a safe pre-check.")

(defparameter +limit-shell+ "/bin/bash"
  "The shell that applies resource limits inside the sandbox. Not /bin/sh: that
execs whatever /private/var/select/sh names (bash, dash or zsh), and their
`ulimit -f` units differ; Apple's /bin/bash 3.2 counts 1024-byte blocks.")

;;; SBPL

(defun sbpl-string (string)
  "STRING as an SBPL string literal: wrapped in double quotes, each \\ and \" in it
preceded by a \\. Nothing else is changed (spaces, parentheses, ;, #, non-ASCII
characters stay as they are; the profile is passed as UTF-8)."
  (declare (ignore string))
  (%r4d1-pending 'sbpl-string))

(defun sbpl-path (pathname)
  "PATHNAME's UIOP:UNIX-NAMESTRING without a trailing /, except the root, which stays
\"/\". Not quoted (SBPL-STRING does that). Same result on every OS."
  (declare (ignore pathname))
  (%r4d1-pending 'sbpl-path))

(defun seatbelt-profile (confinement tmp &key (system-read-paths (sc:system-read-paths))
                                              (shared-tmp (sc:physical-path
                                                           (uiop:ensure-directory-pathname
                                                            (uiop:temporary-directory)))))
  "The SBPL profile (a string, one rule per line, each line ended by a newline) for
CONFINEMENT, which is resolved (physical paths; this function resolves nothing),
and TMP, the launch's private temp directory or NIL. SYSTEM-READ-PATHS and
SHARED-TMP are parameters so the result is a pure function of the arguments.
P below is (SBPL-STRING (SBPL-PATH p)); \"dir\" means a pathname with no name and
no type (subpath), anything else is a file (literal). The lines, in order:

1. +SEATBELT-BASE-PROFILE+.
2. Reads. READ :ALL: (allow file-read*). READ :SYSTEM:
     (allow file-read* (literal \"/\"))
     (allow file-read-metadata (literal M))        per +SEATBELT-METADATA-LITERALS+
     (allow file-read* (subpath P)) / (literal P)  per SYSTEM-READ-PATHS, then
                                                   +SEATBELT-EXTRA-READ-PATHS+, then READABLE
     (allow file-read-metadata (literal A))        per ancestor A (see below)
   The ancestors: for each path of SYSTEM-READ-PATHS, +SEATBELT-EXTRA-READ-PATHS+,
   READABLE, WRITABLE, TMP, SHARED-TMP (when TMP is :SHARED), in that order, its
   proper ancestor directories from the root down, except / itself, each once
   (first occurrence). Path lookups and realpath(3) need them.
3. Writes: (allow file-read* file-write* (subpath P)) per WRITABLE, then TMP when
   non-NIL, then SHARED-TMP when the confinement's TMP is :SHARED; then
   (allow file-read* file-write* file-ioctl (literal D)) per SC:+DEVICE-PATHS+.
4. Deny-read (deny wins): (deny file-read* file-write* (subpath P)) per DENY-READ
   entry, file or directory alike.
5. Network. :NONE: nothing. :ALLOW: (allow network*), then
   (allow mach-lookup (global-name S)) per +SEATBELT-NETWORK-SERVICES+. A policy:
   when it has DNS, (allow mach-lookup (global-name \"com.apple.dnssd.service\"))
   and (allow network-outbound (literal \"/private/var/run/mDNSResponder\")); then
   (allow network-outbound (remote ip \"*:PORT\")) per distinct rule port, in rule
   order (every rule's host is \"*\": CHECK-CONFINEMENT refused host rules)."
  (declare (ignore confinement tmp system-read-paths shared-tmp))
  (%r4d1-pending 'seatbelt-profile))

;;; argv

(defun seatbelt-limit-argv (confinement)
  "The prefix that applies CONFINEMENT's limits inside the sandbox, or NIL when none
of CPU-LIMIT, FILE-SIZE-LIMIT, PROCESS-LIMIT is set:
  (+LIMIT-SHELL+ \"-c\" SCRIPT \"stack-compute-limits\")
SCRIPT is `ulimit -t CPU`, `ulimit -f KIB`, `ulimit -u PROCS` for the limits that are
set, in that order, joined by \" && \", then \" && exec \\\"$@\\\"\" — a refused
ulimit stops the launch (fail closed). KIB is FILE-SIZE-LIMIT bytes divided by
1024, rounded down (never a larger file than asked). MEMORY-LIMIT and WALL-CLOCK
never appear (not Seatbelt features; the wall clock is the launcher's). Note: the
process limit is RLIMIT_NPROC, which macOS counts per user, not per tree."
  (declare (ignore confinement))
  (%r4d1-pending 'seatbelt-limit-argv))

(defun seatbelt-argv (confinement profile argv &key (sandbox-exec +sandbox-exec+))
  "The argv that runs ARGV under PROFILE:
  (SANDBOX-EXEC \"-p\" PROFILE \"--\" ,@(SEATBELT-LIMIT-ARGV CONFINEMENT) ,@ARGV)
The profile goes inline (-p): a temp file (-f) has the same compiled-size limit and
macOS's ARG_MAX (1 MiB) is never the binding constraint. PROFILE longer than
+PROFILE-SIZE-LIMIT+ UTF-8 octets → SC:INVALID-CONFINEMENT with field :PROFILE and
value the octet length (nothing is run or created)."
  (declare (ignore confinement profile argv sandbox-exec))
  (%r4d1-pending 'seatbelt-argv))
