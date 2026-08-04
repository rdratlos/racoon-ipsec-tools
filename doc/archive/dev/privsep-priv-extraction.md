<!--
SPDX-License-Identifier: BSD-3-Clause
Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
-->

> **Archived.** Superseded by [doc/dev/v0.9.1-hardening-spec.md](../../dev/v0.9.1-hardening-spec.md)#22-extracting-privsep_priv as of 2026-08-04; retained for provenance. See also git tag `archive/pre-doc-consolidation`.


# Extracting `privsep_priv()` for automated dispatch-loop testing

Follow-up to issue #105 (`fatal-exit-path-audit.md`) and this project's
`privsep-verification-runbook.md` §7 ("Making this permanent"), which named
this exact refactor and gave the reason to do it now: Task 3 (X.509
client-identity, SAN-based device ID) is about to add new privileged
operations to `privsep.c`'s dispatch loop, and that loop was, until this
change, reachable only inside `privsep_init()`'s privilege-dropping
`fork()` — verified only by hand, on a real host, with a runbook.

---

## 1. What moved, and what did not

`privsep_init()`'s privileged parent branch used to set up (signal
disposition, the close-everything loop, `ploginit()`, the child-pid
record) and then fall directly into `while (1) { privsep_recv(); switch
(ac_cmd) { … } privsep_send(); }`, ending only via `goto fail`/`goto
out` and their `_exit(1)`/`_exit(0)`.

That `while (1)` loop — the request-serving loop itself, not the setup
that precedes it — is now a standalone function:

```c
int privsep_priv(int sock);
```

`privsep_init()`'s setup is unchanged; at the point the loop used to
start, it now reads `return privsep_priv(privsep_sock[0]);`.

**This is pure code motion.** The only edits inside the moved body are
mechanical: every `privsep_sock[0]` reference becomes the `sock`
parameter (nine call sites — `privsep_recv()`, `privsep_wait_io()` ×4,
`send_fd()`, `rec_fd()` ×2, `privsep_send()`), and
`privsep_handshake_failed()` — a small helper called from inside the
loop, for the same reason — gained a `sock` parameter for the same
substitution rather than continuing to reach for the global. Nothing
else changed: the `fail:`/`out:` labels, their log lines, and their
`_exit(1)`/`_exit(0)` are byte-for-byte what they were.

That claim is checked, not asserted. `sed` out the original `while (1)`
body (git blame range 674–1493 of the pre-extraction `privsep.c`),
mechanically substitute `privsep_sock[0]` → `sock` and
`privsep_handshake_failed(reply)` → `privsep_handshake_failed(sock,
reply)`, wrap it in `int\nprivsep_priv(sock)\n\tint sock;\n{ … }`, and
`diff` against the extracted function as it stands in this branch:

```
$ diff /tmp/orig_wrapped.txt /tmp/new_func.txt
$
```

Empty. The two are identical.

### Why the exit-status contract was deliberately not changed

The obvious "cleaner" alternative — make `privsep_priv()` *return* a
status instead of `_exit()`ing, so a test binary could call it in-process
without dying — was considered and rejected, for the same reason
`fatal-exit-path-audit.md`'s `RACOON_SCRIPT_WAIT`-via-`envp` postmortem
(`daemon-issues.md`) warns against "cleaner in theory" changes smuggled in
as refactors: it would not be pure code motion, it would be a behaviour
change wearing a refactor's clothes, and the two things this task exists
to protect — `_exit(0)` vs `_exit(1)` at exactly the points §2.3.2 of the
audit put them — are precisely what a return-based version would put at
risk of drifting from production during the next edit.

Instead, `privsep_priv()` is tested the way
`test_privsep_sigterm_forward.c` already tests
`privsep_sigterm_forward()`: a real `fork()`, the child calls
`privsep_priv(sock)` for real, and the parent — playing the unprivileged
side over a `socketpair()` instead of a real privsep connection — drives
the wire protocol and asserts on both what comes back over it and
`waitpid()`'s reported exit status. This gets the `_exit(0)` vs `_exit(1)`
distinction under test for free, with zero change to production exit
behaviour. `privsep_priv()` itself keeps ordinary external linkage
(declared in `privsep.h` now, alongside `privsep_init()`) rather than
being hidden behind an `ENABLE_UNITTEST`-only accessor the way
`send_fd()`/`rec_fd()` are — it is meant to be called directly, by
design, from both the real call site and every test in this suite.

---

## 2. New test binaries

Four, following `test/README.md`'s wrapped-static-function pattern
(`privsep_unittest_src.c`, already established by the four existing
`test_privsep_*` binaries) plus a new shared stub file,
`privsep_priv_test_stubs.c` — a real, minimal `struct localconf`; canned
`eay_get_pkcs1privkey()`/`getpsk()`; a `script_exec()` that only records
its call (no `fork()+execve()`); a real `extract_port()` (copied from
`sockmisc.c`, not linked, for the same "don't drag in most of the
daemon" reason `rsalist_test_stubs.c` gives); link-target-only stubs for
the `ENABLE_HYBRID` symbols `privsep_priv()`'s switch still references
even though no test here exercises them.

| Binary | Replaces | Covers |
| --- | --- | --- |
| `test_privsep_priv_control_cases` | — (new) | One well-formed request/reply for each of the six non-`ENABLE_HYBRID` command families, in one continuous session, ending in a clean EOF shutdown |
| `test_privsep_priv_framing` | Runbook Phase 2 | No drift across 20 mixed requests (reply's echoed `ac_cmd` must match); descriptor accounting across 8 repeated `PRIVSEP_SOCKET` calls; interleaved `SOCKET`/`BIND`/`SETSOCKOPTS` twice, each its documented descriptor order |
| `test_privsep_priv_bounded_wait` | Runbook Phase 3 | A silent peer (command sent, descriptor never sent) makes `privsep_wait_io()` give up within a compile-time-shortened bound, the reply (if any) carries `ETIMEDOUT`, and the child's `waitpid()` status is `fail:`'s exit 1, not `out:`'s exit 0 |
| `test_privsep_priv_containment` | Runbook Phase 4 / §5a / §5b / §5c | A refused hook → `EPERM`; a corrupted `ac_cmd` (`0xBEEF`) → `EINVAL`; an over-full `PRIVSEP_SCRIPT_EXEC` message with no void terminator → `E2BIG` (§5c's corrected premise — see runbook). Each case is followed by a well-formed request on the *same* connection, which is the assertion that actually proves containment, not just that the bad request failed |

`test_privsep_priv_bounded_wait` is the one binary compiled with
`-DPRIVSEP_IPC_WAIT_MAX_MS_UNITTEST_OVERRIDE=200` (its own
`test/Makefile.am` `_CPPFLAGS`; see `test/README.md`'s new section on
this seam) — 200ms rather than production's 3000ms, so the suite doesn't
spend real seconds waiting out a timeout it is deliberately triggering.
Every other binary, including the other three `test_privsep_priv_*`
binaries, gets the ordinary production constant, because each
`check_PROGRAMS` target compiles its own private copy of
`privsep_unittest_src.c` (and so of `privsep.c`) with its own flags.

Two containment rules from `fatal-exit-path-audit.md` §1 applied to how
these tests themselves had to be written, not just to what they assert:

* **Containment must not silently succeed.** `test_privsep_priv_control_cases`
  exists specifically so a regression that broke *every* request (not
  just the deliberately bad ones the containment test sends) would not
  pass unnoticed — a suite that only ever sends malformed input cannot
  tell "correctly refused" from "everything is broken."
* **Containment must not convert an exit into a hang.** Every blocking
  read in all four binaries is bounded via `poll()` with its own
  timeout (`IO_TIMEOUT_MS`, generous relative to what a healthy exchange
  needs), and every `waitpid()` is a bounded `WNOHANG` poll loop that
  falls back to `SIGKILL` — the same pattern `test_privsep_sigterm_forward.c`
  already established. A regression that reintroduces an unbounded wait
  in `privsep_priv()` fails these tests loudly; it does not hang the
  harness the same way.

---

## 3. Genuinely new coverage vs. what the suite already implied

Before this task, `privsep_priv()`'s dispatch loop itself had **zero**
unit-test coverage — not partially covered, not covered at a lower
level, simply unreachable outside a real `fork()`. Everything in the
"Covers" column above is new in that sense. Worth being more precise
about which parts are new *information* versus which parts re-exercise,
end-to-end, a mechanism a pre-existing unit test already validated in
isolation:

**Genuinely new:**
* The dispatch loop's own control flow — `privsep_recv()` → safety
  checks → `switch` → reply — has never run under `make check` before.
* The real `PRIVSEP_IPC_WAIT_MAX_MS` timeout firing *inside the loop*
  and producing the documented `fail:`/`_exit(1)` with a best-effort
  `ETIMEDOUT` reply. `privsep_wait_io()` the primitive was already
  tested directly (`test_privsep_fd_passing.c`, with an explicit
  caller-supplied bound) — but that never proved the loop's own wiring
  from a timeout to the correct exit status; only that the primitive
  itself works.
* End-to-end containment: a corrupted or refused request answered
  correctly *and* the connection still usable afterward, proven through
  the real `switch` rather than by asserting a predicate.
* §5c's E2BIG-via-corrupted-message case — not tested at all before,
  live or unit (the runbook's own §5c says "not yet run").
* `PRIVSEP_BIND`/`PRIVSEP_SETSOCKOPTS`'s server-side handling — distinct
  code from what `test_privsep_setsockopt.c` covers (that file drives
  `privsep_setsockopt()`, the *client* wrapper; the new tests drive
  `privsep_priv()`'s `PRIVSEP_SETSOCKOPTS` `case`, the *server* side of
  the same exchange).

**Automates a mechanism a unit test already implied, now proven wired
correctly end-to-end:**
* `PRIVSEP_SOCKET`'s policy gate. `privsep_socket_allowed()` itself is
  already exhaustively tested (`test_privsep_socket_policy.c`); the new
  tests only exercise the *admitted* case (`PF_INET`/`SOCK_DGRAM`)
  through the real loop, which confirms the gate is actually wired into
  the `switch` rather than duplicating the policy table.
* The no-descriptor `send_fd(-1)`/`rec_fd()` handshake itself
  (`test_privsep_fd_passing.c` already drives this directly).

**Not exercised through the loop by either the new tests or the
pre-existing ones — see §5 below.**

---

## 4. `make check` / `make check-valgrind`

Full suite, this build (`--enable-adminport --enable-natt --enable-frag
--enable-security-context=no`, `ENABLE_HYBRID` on by default,
`HAVE_LIBPAM`/`HAVE_LIBLDAP`/GSSAPI off — Ubuntu Noble):

```
# TOTAL: 49
# PASS:  49
# FAIL:  0
```

45 before this task (the count `fatal-exit-path-audit.md` last reported
plus the tests landed since), 4 new.

`make check-valgrind`: **All tests passed valgrind!** — clean across all
49 binaries, but not on the first attempt: `check-valgrind`'s
`--error-exitcode=1` surfaced a real, if minor, leak in this task's own
test infrastructure — `privsep_priv_test_lcconf_init()` (the shared stub)
overwrote `struct localconf.pathinfo[]`'s `strdup()`'d strings on each
call without freeing the previous ones. Several tests call it more than
once in the same process (once per test function, sharing one static
struct), and since each `fork()`ed `privsep_priv()` child inherits
whatever the heap looks like at that moment, the *child's own* valgrind
run flagged the now-orphaned earlier string as "definitely lost." Fixed
by freeing before reassigning (`privsep_priv_test_stubs.c`). Not a
privsep.c defect — worth recording because it is exactly the kind of
finding `fatal-exit-path-audit.md`'s prior reports flagged when
`check-valgrind` caught something inspection alone would not have.

---

## 5. Coverage: two caveats, both now fixed, then the data

### Update: both caveats below are now fixed in the shipped build

This section originally documented `make coverage` under-reporting
`privsep.c` and named a one-off, unshipped workaround for it. Follow-up
review surfaced that the workaround never made it into the actual build,
*and* that there was a second, more fundamental gap underneath it — a
plain `make coverage` run reported `privsep.c` as entirely absent, not
merely under-counted. Both are now fixed permanently in `test/Makefile.am`/
`configure.ac`, gated behind `--enable-coverage` (`ENABLE_COVERAGE`) so the
ordinary build is untouched; the original writeup is kept below for the
reasoning, updated to reflect what actually ships now.

### The `_exit()` / gcov interaction

`make coverage`'s ordinary output for `privsep.c` used to be misleading,
and the reason is `_exit()` — the same design choice §1 above explains
keeping. gcov normally flushes each process's counters to its `.gcda`
file via an `atexit()`-registered handler, run when a process exits
through `exit()`/`return` from `main()`. `_exit()` (and `_Exit()`)
deliberately bypasses every `atexit()` handler — that is what makes it
safe to call after `fork()` without double-flushing inherited stdio
buffers, and it is why `privsep_priv()` uses it at every exit point, in
production and unchanged here. The consequence: every line that only
runs *inside the forked child* — which, for these tests, means the
entire dispatch loop — never got its counters written to disk, and a
naive `lcov`/`gcov` capture reported it as 0% executed **even though it
demonstrably ran** (the child's own log lines prove it, and the parent's
assertions on the wire traffic and exit status pass).

Confirmed directly at the time: capturing coverage the ordinary way after
a full `make check` run showed `privsep.c` at 11.5% lines / 40% functions;
annotating the same `.gcda` with `gcov`'s per-line output showed
`privsep_recv()` and `privsep_priv()` themselves marked `#####`
(unexecuted) despite every one of these tests calling them and printing
proof of it.

**Fix, now shipped (`test/Makefile.am`, `configure.ac`):** under
`--enable-coverage`, the eight `check_PROGRAMS` that compile `privsep.c`
via `privsep_unittest_src.c` (the four `test_privsep_priv_*` binaries plus
the four pre-existing ones that also touch `privsep.c`) link
`test/privsep_gcov_dump_shim.c` and add `-Wl,--wrap=_exit` to their own
`_LDFLAGS`. The shim —

```c
extern void __gcov_dump(void);
extern void __real__exit(int status);

void
__wrap__exit(status)
	int status;
{
	__gcov_dump();
	__real__exit(status);
}
```

— is the same `--wrap=` linker technique `test_script_hook_leak.c` already
uses for `free()`, applied to `_exit()` instead so the forked child's gcov
counters get written before it actually exits. This changes nothing about
what runs (all binaries still pass identically with it linked in); it only
makes the *measurement* see it. `__gcov_dump()` is only available when the
binary itself is built with `-fprofile-arcs`/`-ftest-coverage`, which is
exactly what `ENABLE_COVERAGE` gates this on — the ordinary (non-coverage)
build never sees the wrap or the shim at all.

### The second gap: `make coverage` never looked in `test/` at all

Fixing the flush was not enough on its own. `test/Makefile.am`'s
`coverage:` target ran `lcov --directory "$SRC_DIR" --capture ...`, where
`$SRC_DIR` is `$(top_builddir)/src` — but `privsep_unittest_src.c` (like
every other `<module>_unittest_src.c` wrapper this suite uses — `session.c`,
`isakmp.c`, `proposal.c`, `kmpstat.c`, and others, all documented under
"Testing Static Functions" in `test/README.md`) `#include`s the real `.c`
file directly and is compiled as its own object *inside* `test/`, so its
`.gcda`/`.gcno` pair is written to `$(top_builddir)/test`, not
`$(top_builddir)/src`. `lcov`'s directory-scoped capture never looked
there, so `privsep.c` — along with every other wrapped-only module — was
completely **absent** from `make coverage`'s report, not just
under-counted. (gcov itself still attributes the coverage data to the
correct original source path, `src/racoon/privsep.c`, once its `.gcda` is
actually captured — this was purely a "which directory does `lcov` scan"
gap.)

**Fix, now shipped:** the `coverage:` target also captures
`$(top_builddir)/test` (`TEST_DIR`), and the `--remove` filter step gained
a `'*/test/*'` pattern to drop the *test driver's own* files that doing so
also picks up (`test_*.c`, `*_test_stubs.c`, `privsep_gcov_dump_shim.c`) —
matched against each entry's actual source path in the captured `.info`,
so it strips only the drivers and leaves every production source (whose
path always resolves under `src/`) exactly where it belongs.

### The numbers

With both fixes in place, a plain `make coverage` (`--enable-coverage`,
`ENABLE_HYBRID` on, `HAVE_LIBPAM` off — this project's default) now
reports `privsep.c` directly, no special rebuild required:

| Scope | Lines | Functions |
| --- | --- | --- |
| `privsep.c`, whole file | 37.4% (321/858) | 66.7% (20/30) |

The uncovered portion of `privsep_priv()` is concentrated in two places,
both deliberate, not accidental:

1. **`ENABLE_HYBRID`'s `PRIVSEP_ACCOUNTING_SYSTEM`/`PRIVSEP_XAUTH_LOGIN_SYSTEM`
   cases** (this environment has `ENABLE_HYBRID` on, `HAVE_LIBPAM` off,
   so the PAM-gated cases are not even compiled) — outside the runbook's
   own six-command Phase 1 table this task replaces, and outside this
   task's scope; `privsep_priv_test_stubs.c` stubs their dependencies
   only so the `switch` still links.
2. **Allocation-failure paths** — `racoon_malloc()` failing for the
   reply buffer itself, `racoon_realloc()` failing to grow the
   `EAY_GET_PKCS1PRIVKEY`/`GETPSK` reply. Both are channel-scoped fatal
   paths per `fatal-exit-path-audit.md` §2.3 and both are real, but this
   suite has no allocation-failure injection (a `--wrap=malloc`/`realloc`
   shim, same technique as above, would reach them — not built here to
   keep this task to what it was scoped for).

A full `lcov`/`genhtml` HTML report (built from the wrapped capture
above) and the raw `lcov --list` summary are provided alongside this
report as the input the next coverage analysis pass needs, per that
pass's own request for "data, not just a pass/fail summary."

---

## 6. What could not be verified here

* **Runbook Phase 1** (the real happy path — real kernel, real peer, real
  certificate load) still needs `PF_KEY`/XFRM and a real privilege drop,
  neither of which this sandbox has. Not a gap this task introduces —
  §4 of the task brief this document was written against says so
  explicitly, and the runbook (updated alongside this document) keeps
  Phase 1 as the one thing still requiring a real host.
* **A refused `PRIVSEP_SOCKET` request, driven through the real dispatch
  loop.** `test_privsep_priv_control_cases`/`test_privsep_priv_framing`
  only exercise the *admitted* `PF_INET`/`SOCK_DGRAM` case end-to-end;
  the refusal path is proven correct at the predicate level
  (`test_privsep_socket_policy.c`, pre-existing) but not through the
  loop's own `send_fd(-1)` handling of it. A small, identified gap, not
  a silent one.
* **Allocation-failure channel-scoped exits** (§5, item 2 above) —
  identified, not exercised.
* **The coverage percentage without the `--wrap=_exit` workaround** — not
  wrong, exactly, but not informative either; §5 explains why and gives
  the number that is.

---

## 7. Files changed

| File | Change |
| --- | --- |
| `src/racoon/privsep.c` | `privsep_priv(int sock)` extracted from `privsep_init()`'s `while (1)` loop (pure code motion — see §1's diff); `privsep_handshake_failed()` takes `sock` as a parameter instead of reaching for the global; `PRIVSEP_IPC_WAIT_MAX_MS` gains a compile-time-only test override seam |
| `src/racoon/privsep.h` | `privsep_priv()` prototype |
| `test/test_privsep_priv_control_cases.c` | New: one well-formed request per command family |
| `test/test_privsep_priv_framing.c` | New: handshake framing (runbook Phase 2) |
| `test/test_privsep_priv_bounded_wait.c` | New: the bounded mid-request wait (runbook Phase 3) |
| `test/test_privsep_priv_containment.c` | New: containment (runbook Phase 4/§5a/§5b/§5c) |
| `test/privsep_priv_test_stubs.c` | New: shared stub layer for the four binaries above |
| `test/Makefile.am` | Four new `check_PROGRAMS` entries |
| `test/README.md` | New section: the wrapped-static-function pattern generalised, and the compile-time constant-override seam |
| `doc/dev/privsep-verification-runbook.md` | Phases 2–4 marked superseded (with the binaries that replace them); §7 marked done |
| `doc/dev/privsep-priv-extraction.md` | This report |
