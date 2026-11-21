# compute-backend-seatbelt

Confining backend for [compute-protocol](https://github.com/egao1980/compute-protocol) 0.3.0 on macOS: a generated Seatbelt (SBPL) profile run through `/usr/bin/sandbox-exec -p PROFILE -- argv…`. One command and everything it starts can write only to the confinement's writable directories and private `TMPDIR`. It cannot read the deny-read paths (by default the credential directories under `$HOME`), it has no network unless asked, and its environment is scrubbed.

```lisp
(asdf:load-system "compute-backend-seatbelt")
(compute-protocol:run-confined (compute-backend-seatbelt:make-seatbelt-backend)
                               (compute-protocol:make-confinement :writable '("/path/to/area/"))
                               '("/bin/sh" "-c" "make test"))
```

**Status:** 0.1.0 contract (milestone **R4d-1**; decisions locked in [cl-stack confinement.md](https://github.com/egao1980/cl-stack/blob/main/docs/capabilities/confinement.md)). It implements the `confining-backend` protocol (`confinement-features`, `confinement-available-p`, `backend-confine-argv`) and must pass `compute-protocol/confinement-suite` (21 laws) on macOS.

- **Profile:** `(deny default)`, a fixed base allow list (`+seatbelt-base-profile+`: exec/fork, same-sandbox signals, sysctl reads, user lookups, logging, ptys), then reads (`:all` → `(allow file-read*)`; `:system` → the system paths, readable paths and the metadata of their ancestors), then writes, then deny-read rules last (deny wins), then network. User paths appear only as escaped `subpath` / `literal` strings, never inside a regex. `seatbelt-profile` is a pure function. The goldens in `tests/golden/` give its exact text.
- **Features (macOS):** `:filesystem :read-system :deny-read :network-none :network-allow :network-ports :cpu-limit :file-size-limit :process-limit`. There is no `:network-hosts` (that needs a proxy) and no `:memory-limit` (macOS ignores `RLIMIT_AS`). Off macOS the backend loads, has no features and reports itself unavailable ("not macOS").
- **Limits** are applied inside the sandbox by `/bin/bash -c 'ulimit … && exec "$@"'`.
- **Tests:** the profile and argv tests are pure and run on every OS. On macOS, CI also runs the launches, common tools (sh, cat, ls, mkdir, git), the limits, a confined SBCL image and the full suite. Linux and Windows record skips for those.

## License

MIT
