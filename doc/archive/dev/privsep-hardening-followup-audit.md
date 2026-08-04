> **Archived.** Superseded by [doc/dev/v0.9.1-hardening-spec.md](../../dev/v0.9.1-hardening-spec.md)#24-the-follow-up-audit-and-pr-108-review-response as of 2026-08-04; retained for provenance. See also git tag `archive/pre-doc-consolidation`.

# Audit: privsep test-hardening follow-up (issue #107 / PR #108)

## 0. Scope and how to read this document

`doc/dev/privsep-priv-extraction.md` covers the original task: extracting
`privsep_priv()` (privsep.c's privileged dispatch loop) out of
`privsep_init()` as pure code motion, so it could be driven directly by a
test over a plain `socketpair()` instead of only inside a real
`privsep_init()` fork on a live host. That document's own §5/§6 named two
things explicitly out of scope at the time: an accurate coverage number
for `privsep.c`, and the client-side half of the wire protocol
(`privsep_socket()`, `privsep_bind()`, `privsep_script_exec()`, and
friends — the functions the *unprivileged* process calls, as opposed to
`privsep_priv()`, the loop the *privileged* process runs).

This document covers everything done since: closing both of those gaps,
extending the same testing approach to `privsep_init()` itself (the one
entry point the original task still bypassed), and — the reason a
maintainer doing a security-focused cross-review should read this one
closely — **real defects this work found and fixed**: two confirmed bugs
in `privsep.c` itself (§2.1, §2.2), one latent-but-not-currently-live
fragility flagged for the reviewer's judgment rather than fixed outright
(§2.3), and four bugs in the test infrastructure that was supposed to be
verifying it all (§3.1–§3.4). None were known before this task. Every one
of the seven was found by actually exercising a code path (or, for §3.1,
a build configuration) no earlier test — in this project's history,
including the KAME/NetBSD lineage this file descends from — had ever
reached at all.

Read `doc/dev/privsep-priv-extraction.md` first for the extraction itself
and `doc/dev/fatal-exit-path-audit.md` for the containment work that
motivated it (issue #105) — this document assumes both as background and
does not repeat their content. `doc/dev/privsep-verification-runbook.md`
is the manual, real-host procedure that Runbook Phase 1 (the real
`PF_KEY`/XFRM happy path) still requires; nothing in this document
replaces it.

**Summary for the impatient reviewer:**

| | Count |
| --- | --- |
| Production defects found and fixed in `privsep.c` | 2 confirmed + 1 latent-fragility finding (closed with a real fix in the review follow-up, §9.1) |
| Test-infrastructure defects found and fixed | 4 |
| New `check_PROGRAMS` test binaries added | 4 + 2 (review follow-up: `test_monitor_fd_cold_start`, `test_privsep_do_exit` — §9.1/§9.2) = 6 |
| New tests added to the pre-existing 4 `test_privsep_priv_*` binaries | 0 (unchanged; new coverage went into the new binaries) |
| `make check` totals | 45 → 53 → 55 (root; review follow-up added 2); 53 pass + 2 skip (unprivileged, by design — §4.4) |
| `check-valgrind` | clean throughout; **caught §2.1 directly** |
| `privsep.c` line/function coverage | effectively unmeasurable → 72.9% / 97.1% (§5) |
| Sanitizer-build coverage of privsep-related tests | 0/16 → 11/16 (review follow-up spike, §9.4); the other 5 stay excluded for a documented `session.c`-dependency reason |

---

## 1. Timeline

All work below happened on `claude/racoon-privsep-hardening-lkkogg`, as a
follow-up on top of the extraction commit, in this order:

| Commit | What |
| --- | --- |
| `222e9df` | (Base) `privsep_priv()` extraction — see `privsep-priv-extraction.md` |
| `b0d991f` | Fix: missing PAM stubs broke the build on any host with `libpam-dev` (§3.1) |
| `aa5c312` | Fix: a new test false-failed under an unprivileged `make check` (§3.2) |
| `617f3a9` | Fix: `privsep.c` (and every wrapped-static-function module) was invisible to `make coverage` (§3.3) |
| `76067fa` | Add: client-side wrapper tests + `privsep_init()` tests (§4) |
| `f06cf27` | Fix: those new tests needed to skip, not fail, without root (§4.4) |
| `2a5575d` | **Fix: uninitialized stack padding sent over `privsep_sock`** (§2.1) |
| `5146d4a` | Add: `privsep_init()` fork()/chroot() failure-path tests; **fix: fd leak on fork() failure** (§2.2) |
| `d725113` | Fix: a false-positive fd-leak report in the new fork()-failure test itself (§3.4) |

Each is expanded below, findings first (§2–3), then what was added and
why (§4), then numbers and open items (§5–7). §9 covers a later round of
commits, also on this branch: the maintainer review follow-up on this
document itself, closing out items from §2.3, §2.1, and §6.

---

## 2. Production code defects found and fixed

These are changes to `privsep.c` itself — the code a security reviewer
should focus on.

### 2.1 Uninitialized stack padding transmitted over `privsep_sock`

**Severity: low-to-moderate. Confirmed by Valgrind, not theoretical.**

`privsep_bind()` and `privsep_setsockopt()` (both client-side wrappers,
called by the unprivileged process) each build a small local struct
field-by-field, then `memcpy()` the *whole struct* into the outgoing wire
message:

```c
struct bind_args {
	int s;
	const struct sockaddr *addr;
	socklen_t addrlen;
};
```

On this project's primary target (x86-64 Linux), the compiler inserts 4
bytes of padding between `s` (offset 0, 4 bytes) and `addr` (offset 8, a
pointer needing 8-byte alignment) so the struct's total size is 24 bytes,
not the 16 its three fields would need unpadded. `bind_args.s = -1;
bind_args.addr = NULL; bind_args.addrlen = addrlen;` sets all three
*fields* but never touches those 4 padding bytes — they are whatever the
stack slot last held. The `memcpy(data, &bind_args, sizeof(bind_args))`
that follows copies all 24 bytes, padding included, and the message goes
out over `sendto()` a few lines later.

`struct sockopt_args` has the identical problem in two places (4 bytes
after `optname`, before the `optval` pointer; 4 more trailing bytes after
`optlen` to round the struct to 8-byte alignment).

**How it was found:** not by inspection — by Valgrind, running the new
`test_bind_wire()` test (§4.2), which was the first test in this
project's history (including upstream KAME/NetBSD history) to ever drive
`privsep_bind()`'s escalation branch (a real `bind()`-to-a-privileged-port
call as a non-root process, which then falls through to the wire
protocol) at all:

```
Syscall param socketcall.sendto(msg) points to uninitialised byte(s)
   at 0x... sendto
   by 0x... privsep_send
   by 0x... privsep_bind
Uninitialised value was created by a stack allocation
   at 0x... privsep_bind
```

**Fix:** `bzero(&bind_args, sizeof(bind_args));` /
`bzero(&sockopt_args, sizeof(sockopt_args));` immediately before the field
assignments, in both functions (`src/racoon/privsep.c`). This is the same
pattern already used a few lines above for the message buffer itself
(`bzero(msg, len);`) — the bug was that it was applied to the *outer*
message buffer but not to the *local struct copied into it*.

**Why this matters for a security review, and why it's rated
low-to-moderate rather than higher:** what leaked is 4–8 bytes of this
process's own recent stack contents, sent over `privsep_sock`. That socket
is a `socketpair()` — created fresh by `privsep_init()`, inherited only by
the two processes `fork()` created it between, with no name in the
filesystem or an abstract namespace for a third process to ever attach to.
Under this project's stated threat model (`fatal-exit-path-audit.md`
§2.5), the only entity that can read the leaked bytes is the *privileged*
process — i.e., the process on the *more* trusted side of this boundary,
receiving stack bytes from the *less* trusted one. That is the opposite
direction of what would matter for a sandbox-escape or information
disclosure to an external attacker: an attacker who has already
compromised the unprivileged process to the point of reading its own
stack layout has not gained anything from this specific leak that they
did not already have (they are inside the process the stack belongs to).
It is a real bug — uninitialized memory should never cross a process
boundary, full stop, and a future refactor of `bind_args`/`sockopt_args`
could easily reintroduce a variant that leaks something more
interesting — but it was not, in its current form, a privilege-escalation
or confidentiality bypass across the privsep trust boundary as designed.
**A reviewer should confirm this threat-model reasoning independently**;
it is the basis for not treating this as a release-blocker on its own,
and it is exactly the kind of judgment call an independent pass should
sanity-check.

**Audit completeness:** every local struct in `privsep.c` that gets
`memcpy()`'d into an outgoing message was checked, not just the two that
were broken. `struct socket_args` (three `int` fields, no alignment gaps)
is clean and needed no change. Every other outgoing `memcpy()` in the file
copies either a bare scalar (no padding possible) or a caller-supplied
buffer (`addr`, `optval`, `raddr`, `usr`, `pwd` — owned by whatever called
the wrapper, not a `privsep.c`-local variable, and so out of this file's
control to zero).

**Reply direction, checked separately (review follow-up, PR #108, §9.3):**
the sweep above only covers the request direction (unprivileged →
privileged: `bind_args`, `sockopt_args`, `socket_args`). The reply
direction — every `memcpy()` `privsep_priv()` itself performs while
building `reply`/`newreply` before sending back to the unprivileged
process, the direction that actually matters for confidentiality since the
privileged process is the one holding the more sensitive state — was
audited in the same follow-up and found clean: no reply-side struct is
field-assigned and then whole-struct-`memcpy()`'d without an intervening
`bzero()`/equivalent the way `bind_args`/`sockopt_args` were. See §9.3 for
the specifics.

### 2.2 `privsep_sock[]` descriptor leak on `fork()` failure

**Severity: low.** `privsep_init()`'s `socketpair()` call happens *before*
its `fork()` call:

```c
if (socketpair(PF_LOCAL, SOCK_STREAM, 0, privsep_sock) != 0) { ... return -1; }

switch (child_pid = fork()) {
case -1:
	plog(LLV_ERROR, LOCATION, NULL, "Cannot fork privsep: %s\n", strerror(errno));
	return -1;   /* privsep_sock[0]/[1] never closed */
```

A failing `fork()` used to return `-1` having leaked both `privsep_sock[]`
descriptors, with nothing left in the function to close them. `fork()`
failing at all is already a sign of a resource-constrained process (out
of PIDs, memory, or hitting `RLIMIT_NPROC`); leaking two more descriptors
on that exact path compounds an already-bad situation, though on its own
it is a two-fd leak on a rare, already-degraded path, not a
routinely-triggered one.

**How it was found:** while designing a test specifically for this branch
(§4.5) — not by an existing test catching a live regression, since no
prior test had ever exercised this branch (`fork()` essentially never
fails in ordinary testing).

**Fix:** `close(privsep_sock[0]); close(privsep_sock[1]);` plus resetting
both to `-1`, with `errno` saved/restored around the cleanup so a caller
inspecting `errno` after `privsep_init()` returns `-1` still sees `fork()`'s
own `EAGAIN`/`ENOMEM`, not whatever `close()` happened to leave behind.

### 2.3 `monitor_fd()` / `fd_monitor_tree[]` initialization-order dependency (latent, not a live bug)

**Severity: informational — flagged for the reviewer's judgment, not
fixed as a "bug" in this pass.** `privsep_init()`'s privilege-dropping
child branch calls `monitor_fd(privsep_sock[1], privsep_do_exit, NULL, 0)`
(session.c). `monitor_fd()` inserts into `fd_monitor_tree[]`, a
`static TAILQ_HEAD(...) fd_monitor_tree[NUM_PRIORITIES]` array that is
safe to insert into only *after* `TAILQ_INIT()` has run on it — otherwise
its `tqh_last` pointer is `NULL` (the array's all-zero static default,
not the "points at `tqh_first`" state `TAILQ_INIT()` establishes), and
`TAILQ_INSERT_TAIL()` dereferences that `NULL` immediately.

In production this is never reachable: `session()`'s own startup
(`session_init_before_cfparse()`, session.c) always calls
`TAILQ_INIT(&fd_monitor_tree[i])` long before `privsep_init()` is ever
called, so the real privileged-drop child always inherits already-
initialized state via `fork()`'s copy of the parent's memory. This was
discovered only because the new `test_privsep_init.c` (§4.3) calls
`privsep_init()` directly, with none of that surrounding `session()`
startup — and the real forked child **segfaulted immediately** until the
test was changed to call session.c's own `init_fd_monitor_unittest()`
accessor first.

**Why this is worth a reviewer's attention despite not being a live bug:**
the safety of `monitor_fd()` depends on a precondition (`fd_monitor_tree[]`
already `TAILQ_INIT()`-ed) that is enforced entirely by call-order
convention, not by anything in `monitor_fd()`'s own signature, a comment
on it, or a comment on `privsep_init()` warning that it must be called
after `session()`'s own init. That is exactly the kind of implicit
invariant that a future refactor — a different startup order, a
standalone re-exec path, a new entry point that calls `privsep_init()`
earlier — could violate silently, with the same segfault this task hit by
accident. Two options worth the maintainer's consideration, neither acted
on here since both are behavior changes beyond this task's scope:

1. Document the precondition explicitly on both `monitor_fd()` and
   `privsep_init()` (cheapest, no behavior change).
2. Make `fd_monitor_tree[]`'s initialization idempotent/lazy (e.g., a
   one-time-init guard inside `monitor_fd()` itself) so the invariant
   cannot be violated by call order at all (a real code change, needs its
   own review).

**Resolution (review follow-up, PR #108, §9.1): option 2, implemented.**
A comment was judged insufficient — it is exactly the kind of protection
that already failed here once, since the precondition was always implicit
in `privsep_init()`'s one call site, not enforced by anything a future
caller would be forced to read. `monitor_fd()` (session.c) now guards
`fd_monitor_tree[]`'s initialization itself: before inserting, it checks
each `fd_monitor_tree[i].tqh_last == NULL` — the array's true, otherwise
unreachable all-zero static-default state — and calls `TAILQ_INIT()` on
any priority still in it. This was confirmed, not assumed, against both
`sys/queue.h`s this project actually compiles against (the Linux compat
header under `src/include-glibc`, and NetBSD's own upstream header,
fetched live for comparison): both define `TAILQ_HEAD`'s `tqh_last` field
and have `TAILQ_INIT()` set it to `&head->tqh_first`, never `NULL`, so the
guard is a reliable one on both of this project's target platforms.
`session_init_before_cfparse()`'s own `TAILQ_INIT()` call is unchanged —
this is defense in depth, not a replacement for the normal startup path.

A new regression test, `test_monitor_fd_cold_start.c`, calls `monitor_fd()`
as the very first thing a fresh process does, with none of `session()`'s
surrounding startup anywhere in its call history — the same shape of call
that segfaulted by accident when `test_privsep_init.c` was first written
(described above). Reverting the guard and re-running that test reproduces
the exact segfault; with the guard in place it passes, including under
Valgrind. This is the test that should have caught the original
`test_privsep_init.c` segfault before a human had to.

---

## 3. Test-infrastructure defects found and fixed

None of these are bugs in `privsep.c`. They are listed because each one,
left unfixed, would have undermined confidence in "the tests pass" —
either by blocking the build outright, by failing for reasons unrelated
to what was actually being tested, or by silently under-reporting what
had and had not been verified. A reviewer relying on this test suite's
green status should know what it took to make that status trustworthy.

### 3.1 Missing PAM stubs broke the build wherever `libpam-dev` is installed

`privsep_priv_test_stubs.c` (shared by the four `test_privsep_priv_*.c`
binaries) stubbed the `ENABLE_HYBRID`-only link targets
(`isakmp_cfg_accounting_system()`, `xauth_login_system()`) but not their
`HAVE_LIBPAM`-nested siblings
(`isakmp_cfg_resize_pool()`/`isakmp_cfg_accounting_pam()`/
`xauth_login_pam()`/`cleanup_pam()`), because the environment the original
extraction task was written in had no `libpam-dev` installed, so
`HAVE_LIBPAM` was never defined there and the gap never surfaced. Any
build where `./configure`'s `--with-libpam=auto` autodetects a real PAM
installation (the reviewer's own machine, in fact — this is how it was
reported and reproduced) hit unresolved symbols at link time. Fixed by
adding the four missing stubs, gated the same way `privsep.c` itself
gates the call sites (`#ifdef HAVE_LIBPAM` inside `#ifdef ENABLE_HYBRID`).
Verified by forcing `-DHAVE_LIBPAM` with a minimal local
`<security/pam_appl.h>` shim in the sandbox that lacks the real library.

### 3.2 A new test conflated the privsep policy gate's `EPERM` with the kernel's own

The new `test_privsep_priv_control_cases.c` SETSOCKOPTS sub-test treated
any `EPERM` reply as proof `privsep_setsockopt()`'s policy gate wrongly
refused an authorized option. But Linux's xfrm stack itself returns
`EPERM` for `setsockopt(IP_IPSEC_POLICY)` on a process without
`CAP_NET_ADMIN`, *independent of what the gate decided* — the exact
ambiguity issue #105 already documented for `privsep_setsockopt()`
(`test_privsep_setsockopt.c`). The test false-failed under any
unprivileged `make check` run (a normal thing for a human reviewer to do
locally, even though this project's containers/CI run as root). Fixed by
only treating `EPERM` as a gate failure when `geteuid() == 0`, where the
kernel's own privilege check is out of the picture. Reproduced and
confirmed with `setpriv --reuid=nobody`.

### 3.3 `privsep.c` was invisible to `make coverage` — two separate bugs

1. `privsep_priv()` exits every path via `_exit()`, which bypasses gcov's
   `atexit()`-registered counter flush, so a forked test child's coverage
   data never reached disk. Fixed by linking every `check_PROGRAMS` target
   that compiles `privsep.c` with `-Wl,--wrap=_exit` plus a small shim
   (`privsep_gcov_dump_shim.c`) that calls `__gcov_dump()` before the real
   `_exit()`, gated behind a new `ENABLE_COVERAGE` automake conditional so
   the ordinary build is unaffected.
2. **The bigger one:** even with (1) fixed, `test/Makefile.am`'s
   `coverage:` target ran `lcov --directory $(top_builddir)/src`, which
   never looks in `$(top_builddir)/test` — but `privsep.c` (via
   `privsep_unittest_src.c`, like every other
   `<module>_unittest_src.c`-wrapped module this suite uses: `session.c`,
   `isakmp.c`, `proposal.c`, `kmpstat.c`, and others) is compiled as its
   own object *inside* `test/`, so that is where its `.gcda`/`.gcno` pair
   lives. `privsep.c` — and every other wrapped-only module — was
   therefore **entirely absent** from `make coverage`'s report, not just
   under-counted. Fixed by also capturing `test/`, with a `'*/test/*'`
   `--remove` filter to drop the test drivers' own files that doing so
   also picks up while keeping every production source (whose path always
   resolves under `src/`).

Verified with a real `--enable-coverage` build: `privsep.c` went from
absent to reported, and `session.c`/`isakmp.c`/`proposal.c`/`kmpstat.c`/
`racoonctl.c`/`nattraversal.c`/`grabmyaddr.c`/`vendorid.c`/`ipsec_doi.c`/
`oakley.c` — all previously silently missing for the identical reason —
started appearing too.

### 3.4 A false-positive "leak" in the new fork()-failure test itself

Reported after this task's own work was believed complete: the new
`test_privsep_init_fork_failure` (§4.5) failed on a reviewer's Arch Linux
machine with the exact message the *real* fd leak (§2.2) would have
produced, even though that leak was already fixed. Root cause:
`privsep_init()`'s `case -1:` branch logs via `plog(LLV_ERROR, ...)`,
which — with no logfile configured and not running in the foreground,
this test binary's own untouched defaults — reaches `vsyslog()`.
`vsyslog()`'s *first* call in any process opens a socket to the system
log and never closes it (standard glibc behavior); since that first call
was happening *inside* the exact window the test measured (between two
`/proc/self/fd` counts, "before" and "after" calling `privsep_init()`), a
reachable `/dev/log` — true on a typical desktop/server Linux running
`systemd-journald`, not necessarily true in the minimal container this
task was originally developed in — turned "leaked nothing" into an
apparent `+1` fd that had nothing to do with `privsep_sock[]`.

Fixed by calling the identical `plog(LLV_ERROR, ...)` once as a
deliberate warmup *before* taking the "before" count, so `privsep_init()`'s
own later call reuses the already-open (or, on a host with no syslog at
all, still-absent) fd instead of changing the count itself. Verified by
binding a throwaway `AF_UNIX SOCK_DGRAM` listener at `/dev/log` in the
original sandbox (which has none by default) to reproduce the reviewer's
exact environment, confirming the failure reproduced without the fix and
was resolved with it, in both the with-syslog and without-syslog case.

**Note for the reviewer:** this is a general hazard for any test that
tries to detect resource leaks via a raw fd-count delta around a call
that also happens to be the first one in the process to touch some
lazily-initialized subsystem (syslog here; `malloc()` arena setup,
NSS/`getpwnam()` module loading, and DNS resolver library init are the
same category of risk elsewhere). Worth keeping in mind if this pattern
is reused for future fd-leak tests in this codebase.

---

## 4. New automated coverage added

### 4.1 New `privsep.c` `ENABLE_UNITTEST` accessors

Every client-side wrapper (`privsep_script_exec()`, `privsep_socket()`,
etc.) reads the *static* `privsep_sock[]` pair, normally written only by
a real `privsep_init()`. To drive them over a test `socketpair()` instead:

- `privsep_set_sock_unittest(int, int)` / `privsep_get_sock_unittest(int)`
  — point `privsep_sock[]` at a test socketpair, and read it back.
- `privsep_reset_state_unittest(void)` — clears `privsep_sock[]` and
  `privsep_child_pid` between scenarios in the same process.
- `port_check_unittest(int)` — exposes the static, `ENABLE_HYBRID`-only
  `port_check()` predicate directly.

### 4.2 `test_privsep_client_wrappers.c` / `test_privsep_hybrid_client_wrappers.c`

Cover `privsep_eay_get_pkcs1privkey()`, `privsep_getpsk()`,
`privsep_script_exec()`, `privsep_socket()`, `privsep_bind()` (always
built) and `port_check()`, `privsep_xauth_login_system()`,
`privsep_accounting_system()`, `privsep_accounting_pam()`,
`privsep_xauth_login_pam()`, `privsep_cleanup_pam()` (`ENABLE_HYBRID`/
`HAVE_LIBPAM`-gated at the C level, so the binary still builds and runs
with fewer cases on a build without those features).

Every function gets two cases: **"passthrough"** (called as this test
binary's own root, taking the wrapper's own
`if (geteuid() == 0) return <real syscall/function>(...)` branch
directly) and **"wire protocol"** (this process's effective uid dropped
to `nobody`, so the same call instead builds and sends the real wire
message, against a forked child running the *real* `privsep_priv()` —
real production code on both ends of the real protocol, the mirror image
of what `test_privsep_priv_*.c` already covers by hand-crafting the wire
messages itself). The shared driver, `privsep_wire_roundtrip.c`, is what
found the bug in §2.1: it is what first made `privsep_bind()`'s
escalation branch — a real `bind()` to a privileged port as a real
non-root process — reachable by any test at all, let alone under
Valgrind.

`privsep_socket()`/`privsep_bind()` were flagged at the start of this
task as "if possible, socket functions have shown to be not easily unit
tested." They turned out tractable precisely because the real dispatch
loop this driver forks into performs the real `socket()`/`bind()`
syscalls itself, identically to production — there is no socket-behavior
simulation to get wrong, only the `SCM_RIGHTS` handoff and the two policy
gates (`privsep_socket_allowed()`, the ISAKMP-port check in
`PRIVSEP_BIND`), both already-real code.

### 4.3 `test_privsep_init.c`

Drives `privsep_init()` itself — the one `privsep.c` entry point every
other test in this suite deliberately bypasses. Four scenarios:

1. `lcconf->uid == 0`: must return `0` having done nothing else. No fork
   needed, safe to call directly.
2. Missing cert/script path: must return `-1` before ever reaching
   `socketpair()`/`fork()`. Also safe to call directly.
3. `lcconf->chroot` pointed at a path that does not exist: the real
   forked child's `chdir()` must fail, returning `-1` before ever
   reaching `setgid()`/`setuid()`/`monitor_fd()`.
4. The real `fork()`+privilege-drop+`privsep_priv()` happy path, entirely
   inside a disposable forked child (see the file's own header comment
   for the full three-process breakdown: the test binary forks an "outer
   child," whose own call to `privsep_init()` forks a further
   "grandchild" that actually drops privilege and makes one real
   `ENABLE_HYBRID` client-wrapper call over the genuine production
   `privsep_sock` — no test accessor involved at that point at all).
   This is the one scenario in the whole suite that reaches
   `privsep_priv()`'s `ENABLE_HYBRID` dispatch cases through the real
   production entry point, rather than a synthetic direct
   `privsep_priv(sock)` call.

Scenarios 3 and 4 share their fork/pipe/reap plumbing via one
`run_forked_privsep_init()` helper, parameterized by a per-scenario
callback for what the innermost forked child does with `privsep_init()`'s
return value.

**Explicitly out of scope, documented as a gap, not fixed here:** a real,
*successful* `chroot()` (as opposed to scenario 3's deliberate failure)
is never exercised — a real, populated jail directory is orthogonal to
what this file tests, and getting it wrong risks the test host itself,
not just a failing test. Also out of scope: `setgid()`/`setegid()`/
`setuid()`/`seteuid()` failure. These were assessed as **not practically
testable**: a real root test process can set its [ug]id to almost any
value, and there is no portable, deterministic way to make a root
process's own privilege-drop syscalls fail without something exotic (a
`--wrap=`-level interposition making them lie, which would test the
interposition, not `privsep_init()`).

### 4.4 Root-privilege requirements and `SKIP` semantics

`test_privsep_client_wrappers`/`test_privsep_hybrid_client_wrappers` need
real root for *every* case (`seteuid()` to a different account needs
`CAP_SETUID`, which only a process that started as root has) and detect
that up front, reporting `SKIP` (exit code 77, automake's own convention)
instead of failing when run unprivileged. `test_privsep_init` is more
granular: its two privilege-free scenarios always run; only its two
real-fork scenarios check root and soft-skip just themselves. See
`CONTRIBUTING.md`'s "Running the Test Suite" section for the full
reasoning, including why `fakeroot` is not a substitute (it fakes
file-ownership library calls for packaging, not the real uid/`CAP_SETUID`
these tests need).

### 4.5 `test_privsep_init_fork_failure.c`

A separate binary — linked with `-Wl,--wrap=fork`, which redirects
*every* `fork()` call in whatever it is linked into, so it cannot share a
binary with `test_privsep_init.c`'s own real-fork scenarios. `__wrap_fork()`
always fails with `EAGAIN`, deterministically, without touching any real
system resource (no `RLIMIT_NPROC` manipulation, which would risk
affecting other processes under the same uid on a shared CI host).
Asserts `privsep_init()` returns `-1` and, via the `/proc/self/fd` count
described in §3.4, that it leaks nothing — this is the test that both
found and now pins the fix in §2.2. Needs no real privilege at all
(`fork()` never actually runs, wrapped or not), so unlike its siblings it
always runs in full regardless of who invokes `make check`.

---

## 5. Coverage numbers

Measured with `./configure --enable-coverage` (plus this project's usual
`--enable-adminport --enable-natt --enable-frag`), `make -C test
coverage`, `ENABLE_HYBRID` on and `HAVE_LIBPAM` off (this project's
default when `libpam-dev` is absent):

| Point in this task | `privsep.c` lines | `privsep.c` functions |
| --- | --- | --- |
| Before this task (extraction task's own one-off measurement, `--wrap=_exit` applied by hand, not shipped) | 35.5% (290/817) | 66.7% (20/30) |
| Before this task, via a *plain* `make coverage` (the bug in §3.3) | *entirely absent from the report* | *entirely absent* |
| After §3.3's fix alone | 37.4% (321/858) | 66.7% (20/30) |
| After §4's new tests (client wrappers + `privsep_init()` happy path) | 71.8% (625/871) | 97.1% (33/34) |
| After §4.5/§4.3's fork()/chroot()-failure scenarios (final) | **72.9% (641/879)** | **97.1% (33/34)** |

The remaining ~27% of uncovered lines is concentrated in: allocation-
failure paths (`racoon_malloc()`/`racoon_realloc()` failing —
identified, not exercised, per `privsep-priv-extraction.md` §6); the
`setgid`/`setuid`/`seteuid` failure lines just discussed (§4.3); a
refused `PRIVSEP_SOCKET` request driven through the real loop specifically
(the refusal predicate itself is covered — `test_privsep_socket_policy.c`
— but not through `privsep_priv()`'s own `send_fd(-1)` handling of it,
per `privsep-priv-extraction.md` §6); and `privsep_setsockopt()`'s own
escalation branch, which — unlike `privsep_bind()`'s, now exercised by
`test_bind_wire()` — still has no test driving it through the real wire
protocol at all (only its pre-existing, geteuid()==0-only return-contract
test, `test_privsep_setsockopt.c`). **That last one is worth flagging
specifically:** `sockopt_args`' padding bug (§2.1) was found and fixed by
inspection/analogy with `bind_args`, not by a test actually exercising it
under Valgrind the way `test_bind_wire()` did for `bind_args` — a
follow-up `test_setsockopt_wire()` in the same shape as `test_bind_wire()`
would close that verification gap and is the most direct, actionable
next step this document recommends.

---

## 6. Test suite state (final)

- `make check`: **55/55** as root (was 45 before this task; the
  extraction task's own commit brought it to 49, this task's work to 53,
  the review follow-up's two new binaries — `test_monitor_fd_cold_start`,
  `test_privsep_do_exit`, §9.1/§9.2 — to 55).
- `make check` as an unprivileged user: 53 pass, 2 skip, 0 fail (by
  design — §4.4).
- `make check-valgrind`: clean across all 55 binaries — and, over the
  course of this task, Valgrind is specifically what caught §2.1 (an
  ordinary `make check` run, without Valgrind, sees `privsep_bind()`
  return the correct value either way and would not have noticed the
  uninitialized bytes on the wire). §3.4, by contrast, was *not* a
  Valgrind finding — it surfaced as an ordinary `make check` failure on a
  reviewer's own (non-container) Linux machine, precisely because that
  machine's `/dev/log` behaves differently than this task's own
  development sandbox; see §3.4 for why.
- Sanitizer builds (`--enable-sanitizer` or equivalent, wherever this
  project's CI configures one): **resolved for 11 of the 16 privsep-related
  binaries in the review follow-up (§9.4).** The 11 `privsep.c`-only
  targets (`test_privsep_sigterm_forward`, `test_privsep_fd_passing`,
  `test_privsep_socket_policy`, `test_privsep_setsockopt`,
  `test_privsep_priv_control_cases`, `test_privsep_priv_framing`,
  `test_privsep_priv_containment`, `test_privsep_priv_bounded_wait`,
  `test_privsep_client_wrappers`, `test_privsep_hybrid_client_wrappers`,
  `test_privsep_do_exit`) now build and pass under a real
  `-fsanitize=address,undefined` configure, genuinely instrumented
  (confirmed via `nm`/`ldd`), by dropping `-ffunction-sections`/
  `--gc-sections` for a `SANITIZER_BUILD`-conditional variant and
  supplying a minimal link-only `monitor_fd()` stub
  (`privsep_sanitizer_monitor_fd_stub.c`) for the one symbol
  `privsep_init()` (unreached at runtime by any of these tests, but still
  part of the linked translation unit once `--gc-sections` is gone) still
  references. **The remaining 5 — `test_monitor_fd_range`,
  `test_prune_stale_monitored_fds`, `test_monitor_fd_cold_start`,
  `test_privsep_init`, `test_privsep_init_fork_failure` — stay excluded**,
  for a documented, harder reason than the original blanket one:
  `session.c`'s own dependency closure (`isakmp_init()`, `pfkey_init()`,
  `admin_init()`, `cfparse()`, and effectively most of the daemon) is not
  practical to stub just to link one test binary, and doing so would
  defeat the point of those specific tests anyway. See §9.4 for the full
  spike writeup, including the exact reproducible link errors this ruled
  out.

---

## 7. Recommendations for the reviewer

In rough priority order. Items 3 and 4 were review follow-up items on PR
#108 and are now closed (or closed-as-investigated); their original text
is kept below, struck through, with the resolution appended — see §9 for
the full writeup of everything closed in that follow-up, including two
items (the reply-direction padding audit and a standalone
`privsep_do_exit()` unit test, §9.2/§9.3) that were not separate numbered
recommendations here but are part of the same closure.

1. **Confirm the threat-model reasoning in §2.1 independently.** The
   severity judgment there (leaked stack bytes flow toward the more-
   trusted process, not away from it, under a `socketpair()`-based,
   unnamed, two-endpoint-only channel) is load-bearing for treating that
   finding as "fixed and done" rather than "fixed, but reassess whether
   anything else reads privileged-process memory this way." A second set
   of eyes on that specific reasoning is the single highest-value thing
   this document is asking for. Still open.
2. **Consider a `test_setsockopt_wire()`** (§5) — `sockopt_args`' bug was
   found by inspection, not by a Valgrind-driven test the way
   `bind_args`' was; closing that asymmetry would remove the one
   remaining "we believe this is fixed but nothing actually proves it
   under Valgrind" case among the three structs audited in §2.1. Still
   open — out of scope for the PR #108 review follow-up (§9's own
   non-goals).
3. ~~**Decide on §2.3's `monitor_fd()`/`fd_monitor_tree[]` ordering
   dependency** — document the precondition, make it self-enforcing, or
   explicitly accept the current call-order-only guarantee as sufficient
   given `privsep_init()` has exactly one call site today.~~ **Closed
   (review follow-up, PR #108, §9.1):** implemented as a self-enforcing
   guard inside `monitor_fd()` itself (option 2 of §2.3's original list),
   verified against both this project's actual `sys/queue.h` headers and
   pinned by a new regression test that reproduces the original segfault
   when reverted. `session_init_before_cfparse()`'s own `TAILQ_INIT()`
   call is retained as defense in depth.
4. ~~**Weigh whether the sanitizer-build gap in §6 is acceptable** for a
   feature this task's own framing calls "new to production" — Valgrind
   coverage is real and already found a genuine bug, but it is not a
   substitute for ASan/UBSan on the same code if this project's CI
   otherwise relies on those for its memory-safety signal elsewhere.~~
   **Closed-as-investigated (review follow-up, PR #108, §9.4):** the gap
   is now real ASan/UBSan coverage for 11 of the 16 previously-excluded
   binaries — every `privsep.c`-only target. The remaining 5
   (`session.c`-dependent) targets stay excluded, but for a documented,
   harder reason than the original blanket one, not a restatement of it.
   See §9.4 for the reproducible spike results either way.
5. **Runbook Phase 1 remains required, unchanged by any of this work.**
   Nothing in this task or the original extraction touches the real
   `PF_KEY`/XFRM code path; that is still the one thing that needs a real
   host per `doc/dev/privsep-verification-runbook.md`, and should be run
   explicitly before any production rollout of privsep as this project's
   default operating mode.

---

## 8. Files changed

Production code:
- `src/racoon/privsep.c` — §2.1 (`bind_args`/`sockopt_args` zeroing),
  §2.2 (fork-failure fd leak), §4.1 (new `ENABLE_UNITTEST` accessors)

Build system:
- `configure.ac` — new `ENABLE_COVERAGE` conditional (§3.3)
- `test/Makefile.am` — new `check_PROGRAMS` targets and their
  `ENABLE_COVERAGE`/`-Wl,--wrap=` stanzas (§3.3, §4.2, §4.3, §4.5)

New test sources:
- `test/privsep_wire_roundtrip.c` — shared client-wrapper wire-protocol
  driver (§4.2)
- `test/test_privsep_client_wrappers.c`, `test/test_privsep_hybrid_client_wrappers.c` (§4.2)
- `test/test_privsep_init.c` (§4.3)
- `test/test_privsep_init_fork_failure.c` (§4.5)
- `test/privsep_gcov_dump_shim.c` (§3.3)

Modified test sources:
- `test/privsep_priv_test_stubs.c` — §3.1
- `test/test_privsep_priv_control_cases.c` — §3.2

Documentation:
- `CONTRIBUTING.md` — new "Running the Test Suite" section (§4.4)
- `test/README.md` — new sections describing all of the above
- `doc/dev/privsep-priv-extraction.md` — §5 rewritten to describe the
  shipped coverage fix (§3.3) instead of the one-off workaround it
  originally documented
- This document.

**Review follow-up (PR #108, §9) additionally changed:**

Production code:
- `src/racoon/session.c` — §9.1 (`monitor_fd()` self-enforcing
  `fd_monitor_tree[]` init guard)
- `src/racoon/privsep.c` — §9.2 (`privsep_do_exit_unittest()`
  `ENABLE_UNITTEST` accessor; no other change — §2.1's reply-direction
  audit, §9.3, found nothing to fix)

Build system:
- `test/Makefile.am` — new `test_monitor_fd_cold_start`/
  `test_privsep_do_exit` targets (§9.1/§9.2); `SANITIZER_BUILD`-conditional
  variants for the 11 `privsep.c`-only targets (§9.4)

New test sources:
- `test/test_monitor_fd_cold_start.c` (§9.1)
- `test/test_privsep_do_exit.c` (§9.2)
- `test/privsep_sanitizer_monitor_fd_stub.c` — shared link-only
  `monitor_fd()` stand-in for the `SANITIZER_BUILD` variants (§9.4)

Documentation:
- This document — §9 and the closure notes threaded through §2.1, §2.3,
  §6, and §7.

---

## 9. Review follow-up (PR #108)

A maintainer review of this document's own §2.3 and §6 findings asked for
four things: fix (not just decide on) the `monitor_fd()` ordering
fragility from §2.3; give `privsep_do_exit()` its own standalone unit
test, decoupled from `monitor_fd()`'s dispatch machinery; confirm the
reply-direction half of §2.1's padding audit was actually checked; and
spike whether §6's blanket sanitizer-build exclusion could be scoped more
narrowly than "every privsep test, no exceptions." All four are closed
below. Explicitly out of scope for this follow-up, per the review's own
framing: any change to `privsep.c` beyond what closing these four items
required (none turned out to be required beyond §9.2's one new accessor),
and folding in unrelated work items or issues — this section closes out
review feedback on PR #108 specifically, nothing broader.

### 9.1 `monitor_fd()` / `fd_monitor_tree[]`: self-enforcing initialization

Closes §2.3, option 2 of the two the original finding left to the
maintainer's judgment. A comment-only fix (option 1) was rejected: a
comment is exactly the kind of protection that already failed here once
— the precondition was always implicit in `privsep_init()`'s one call
site, never enforced by anything a future caller would be forced to read
before violating it.

**The mechanism**, verified rather than assumed: `TAILQ_INIT(head)` sets
`head->tqh_last = &head->tqh_first` — never `NULL` — while
`fd_monitor_tree[]`'s all-zero static default (before any `TAILQ_INIT()`
call has ever touched it) has `tqh_last == NULL`. That makes
`tqh_last == NULL` a reliable one-time-init guard, provided it holds for
every `sys/queue.h` this project actually compiles against. Checked
directly, not assumed to be true "because BSD":

- This project's own Linux compat header (`src/include-glibc/sys/queue.h`)
  — a project-shipped file, not the system's own — defines `TAILQ_HEAD`
  with a `tqh_last` field and `TAILQ_INIT()` sets it to `&(head)->tqh_first`.
- NetBSD's own upstream `sys/queue.h` (fetched live for comparison, since
  NetBSD is this project's other target platform and its *system* header
  is what would be used there, not the Linux compat one) defines the same
  field and the same `TAILQ_INIT()` behavior.

Both platforms agree, so the guard added to `monitor_fd()` (session.c)
holds on both:

```c
for (i = 0; i < NUM_PRIORITIES; i++) {
	if (fd_monitor_tree[i].tqh_last == NULL)
		TAILQ_INIT(&fd_monitor_tree[i]);
}
```

placed at the top of `monitor_fd()`, before the existing `FD_SET()`/
`TAILQ_INSERT_TAIL()` logic. `session_init_before_cfparse()`'s own
`TAILQ_INIT()` call is unchanged — this is defense in depth on top of the
normal startup path, not a replacement for it; the normal path still runs
first in every real invocation and the guard above is then a same-state
no-op for it.

**Regression test:** `test_monitor_fd_cold_start.c` is a dedicated
single-purpose binary whose entire `main()` calls `monitor_fd()` as the
first thing in a fresh process — no `init_fd_monitor_unittest()`, no
`session()` startup, nothing — proving the guard works from a genuinely
uninitialized state, which is exactly the shape of call that segfaulted by
accident when `test_privsep_init.c` was first written (§2.3, above). This
is the test that should have caught that original segfault before a human
hit it. Verified three ways: (1) it passes against the fixed
`monitor_fd()`; (2) reverting the guard and re-running it reproduces the
exact segfault, confirming the test and the fix are actually linked, not
coincidentally both present; (3) clean under Valgrind (`--leak-check=full`)
with the fix in place.

### 9.2 `privsep_do_exit()`: standalone unit test

Closes the review's ask for `privsep_do_exit()` to be directly testable on
its own, not merely verified as a side effect of §9.1's `monitor_fd()`
fix — a test that only ever drove it through `monitor_fd()`'s full
dispatch path could not distinguish "the callback's own logic is wrong"
from "the dispatch machinery around it is wrong."

**From source, not assumed** (the review brief's own instruction, and
worth stating because the brief itself guessed wrong about which file the
function lives in — it assumed `session.c`; `privsep_do_exit()` is
actually defined in `privsep.c`, `static`):

```c
static int
privsep_do_exit(void *ctx, int fd)
{
	kill(getpid(), SIGTERM);
	return 0;
}
```

It ignores both arguments and does exactly one thing: signal its own
calling process with `SIGTERM`, then return `0`. `monitor_fd()` dispatches
to it in production only when `privsep_sock[1]` shows readable/EOF in the
unprivileged child's own select loop, so it is otherwise unreachable
directly.

**Accessor:** `privsep_do_exit()` being `static` needed the same
`ENABLE_UNITTEST`-only accessor pattern already used elsewhere in this
file (§4.1) — `privsep_do_exit_unittest(void *ctx, int fd)`, defined
immediately after `privsep_socket_allowed_unittest()`, just calls through.

**Test:** `test_privsep_do_exit.c`, following the fork+real-signal+
`waitpid()` pattern `test_privsep_sigterm_forward.c` already established
in this suite rather than inventing a new one. Two cases, each in its own
disposable forked child so a signal that *does* terminate the process
takes down only that child:

1. **Terminates via `SIGTERM`** — default disposition. Fork, have the
   child call `privsep_do_exit_unittest()` directly (a function call, not
   through `monitor_fd()`), assert via `waitpid()` that
   `WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM`.
2. **Returns `0` when the signal is caught, not fatal** — the shape a real
   unprivileged child is normally already in by the time this callback
   could ever fire (`session.c`'s own signal setup runs well before
   `privsep_sock[1]` could show EOF). Installs a handler, calls the
   accessor, and confirms both that the handler actually fired (proving
   the signal was delivered, not merely that the process survived by
   coincidence) and that the function's own return value was `0` —
   communicated back through the child's exit code, the only channel
   available across `fork()`.

Both pass; verified stable across repeated runs and clean under Valgrind
(`--trace-children=yes`). Explicitly narrower in scope than an end-to-end
`monitor_fd()`-dispatch test driving `privsep_do_exit()` through the real
dispatch path — that is a separate, still-valid test to consider adding
later, not something this one replaces.

### 9.3 `privsep_priv()` reply-direction padding audit

Closes the review's ask to confirm §2.1's padding sweep covered the reply
direction (privileged → unprivileged), not just the request direction it
explicitly described. It did not say either way, so this follow-up
checked directly: every `memcpy()` `privsep_priv()` performs while
building `reply`/`newreply` before sending it back over `privsep_sock`,
cross-checked against `vchar_t`'s definition
(`struct _vchar_t_ { size_t l; caddr_t v; }` — a length and a heap
pointer, no fixed-layout struct with alignment gaps to leak in the first
place) and every reply-side local variable's own layout.

**Result: no issue found.** Unlike `bind_args`/`sockopt_args` (request
direction, §2.1), nothing on the reply side is field-assigned and then
whole-struct-`memcpy()`'d the way those two were. This sentence, together
with the one added directly to §2.1 above, is the audit-completeness
statement the review asked for: the reply direction was checked, and is
clean. No code change was needed or made.

### 9.4 Sanitizer-build exclusion: scoping spike

Closes the review's ask to investigate — explicitly framed as a spike, not
a guaranteed fix — whether §6's blanket `if !SANITIZER_BUILD` exclusion of
every privsep test binary could be scoped more narrowly than "all of
them, unconditionally."

**Hypothesis:** the conflict blamed in §6 is between
`-ffunction-sections`/`-fdata-sections` + `-Wl,--gc-sections` (needed under
the *ordinary* build to keep these binaries' dependency closures small —
`privsep_unittest_src.c` `#include`s the whole of `privsep.c`, which
statically references far more of the daemon than any one test actually
calls) and ASan/UBSan instrumentation. Confirmed, precisely: on this
project's GCC 13.3.0/Ubuntu 24.04 toolchain, combining
`-fsanitize=address,undefined` with `--gc-sections` reliably drops
`main()`'s own section, producing `undefined reference to 'main'` from
`Scrt1.o` — reproduced and isolated by toggling `--gc-sections` and
`-ffunction-sections` independently under a real
`-fsanitize=address,undefined` configure. Removing just `--gc-sections`
(and its precondition, `-ffunction-sections`/`-fdata-sections`) for a
`SANITIZER_BUILD`-conditional variant resolves that specific error, which
answered the review's actual question: the conflict is about
`--gc-sections` specifically, not some broader, unnamed incompatibility
between the two flag families.

**What dropping `--gc-sections` costs:** without it, the linker requires
every symbol the *whole* `privsep.c` translation unit references, not just
what a given test calls — the same set `privsep_priv_test_stubs.c` already
supplies for `test_privsep_priv_*.c` (`eay_get_pkcs1privkey()`, `getpsk()`,
`script_exec()`, the `ENABLE_HYBRID`/`HAVE_LIBPAM` link targets), now
needed by every privsep target uniformly rather than just the four that
happened to need it already under `--gc-sections`. It also needs one more
symbol none of the ordinary-build variants do: `monitor_fd()`, referenced
by `privsep_init()` (itself unreached at runtime by any of these tests,
which all drive `privsep_priv()` or the client wrappers directly, but
still part of the linked object once `--gc-sections` can no longer prune
it away). The real `monitor_fd()` lives in `session.c`, whose own
dependency closure — `isakmp_init()`, `pfkey_init()`, `admin_init()`,
`cfparse()`, `sched_init()`, `myaddr_*`, `sainfo_*`, `rmconf_*`, and more,
confirmed by attempting exactly this and capturing the resulting cascade
of further undefined references — is not practical to pull into a
privsep-only test binary just to satisfy one link-time reference nothing
in these tests ever calls at runtime. `privsep_sanitizer_monitor_fd_stub.c`
supplies a minimal, link-only stand-in instead (`return 0`, ignoring all
four arguments); see that file's own header comment for the same reasoning
in place.

**Applied to 11 targets** — every `privsep.c`-only binary in this suite:
`test_privsep_sigterm_forward`, `test_privsep_fd_passing`,
`test_privsep_socket_policy`, `test_privsep_setsockopt`,
`test_privsep_priv_control_cases`, `test_privsep_priv_framing`,
`test_privsep_priv_containment`, `test_privsep_priv_bounded_wait`,
`test_privsep_client_wrappers`, `test_privsep_hybrid_client_wrappers`,
`test_privsep_do_exit`. Each got a `SANITIZER_BUILD`-conditional variant
in `test/Makefile.am` (dropping `-ffunction-sections`/`--gc-sections`,
adding `privsep_priv_test_stubs.c` and
`privsep_sanitizer_monitor_fd_stub.c` where the ordinary build did not
already need them) alongside its unchanged ordinary-build variant,
replacing the `if !SANITIZER_BUILD` exclusion. All 11 were verified, under
a real `./configure ... CFLAGS="-fsanitize=address,undefined -g -O0"
LDFLAGS=-fsanitize=address,undefined` build: link cleanly, are genuinely
instrumented (confirmed via `nm | grep '__asan_\|__ubsan_'` — 33-plus
matches each — and `ldd | grep asan` showing real `libasan.so.8` linkage,
not just the flag having been passed), and pass. The full sanitizer-build
`make check` (all 41 binaries that exist under that configure) is clean:
41/41.

**Does not work, and was not forced, for 5 targets** —
`test_monitor_fd_range`, `test_prune_stale_monitored_fds`,
`test_monitor_fd_cold_start`, `test_privsep_init`,
`test_privsep_init_fork_failure`. These need `session.c`'s *real*
`monitor_fd()` (the first three) or a real `privsep_init()` fork/privilege
drop that itself calls into `session.c` (the last two) — the stub above is
by design not a substitute, and would defeat the point of these specific
tests if it were. Pulling in the real `session.c` instead (attempted, to
be thorough rather than assume) produces the dependency cascade described
above; not pursued further; these 5 remain excluded from sanitizer builds
under the unchanged `if !SANITIZER_BUILD` conditional. This is a genuinely
different, harder problem than the one this spike closed, not a
restatement of it — see the file comment in
`privsep_sanitizer_monitor_fd_stub.c` for the same distinction made in
the code itself.

**Full regression, both configurations:** the sanitizer-configured
`make check` (41/41, including the 11 newly-instrumented targets) and,
after a clean rebuild under the project's ordinary (non-sanitizer)
configure, the full `make check` (55/55) and `make check-valgrind` for the
two new §9.1/§9.2 binaries specifically (clean, 0 errors, no leaks) both
pass — the same verification discipline used throughout this task,
confirming the sanitizer-build changes did not regress the ordinary build
this project's CI actually runs day to day.
