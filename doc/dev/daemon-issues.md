# racoon daemon-side issues found during split-DNS hook testing

Filed per brief 3 §G (Issues 1-3) and the Task F ACQUIRE-provenance
investigation (Issue 4, `doc/dev/teardown-investigation.md`). These were
**not fixed when filed** — that work package was explicitly scoped to
*filing* what live testing on a Xubuntu Bionic 32-bit roadwarrior (racoon
0.9.1, OpenSSL 1.1.1, systemd 237) and, for Issue 4, a wider set of live
hosts (Bionic, Noble, Arch) surfaced in `src/racoon`'s own C code, each
traced to a concrete source location and given a reproducer, so a future
change to the daemon itself could be scoped correctly. No file under
`src/racoon/` was touched by the commit that added this document.

That constraint has since been lifted; each issue below is now fixed on
its own branch/PR and marked **Status: resolved** with a link to its
fixing commit as the work lands. Issues without a Status line are still
open.

Each issue below cites the exact function/line the finding traces to in
*this* tree (not upstream ipsec-tools, which may already read differently),
confirmed by reading the source, not inferred from behavior alone where a
source-level explanation was available.

---

## Issue 1 (F2): `SIGTERM`/`SIGINT` shutdown does not reliably run `phase1-down` hooks

**Severity:** high — this is the direct cause of the split-DNS hooks
leaving routes/DNS/SPD state configured after a `systemctl stop racoon` or
`kill <racoon-pid>`, forcing a manual `phase1-down.sh` invocation or reboot
to clean up.

**Root cause.** `close_session()` (`src/racoon/session.c:343-358`), the
handler for `SIGTERM`/`SIGINT` (`src/racoon/session.c:479-484`), calls
`flushph1()` (`src/racoon/handler.c:494-509`), which calls `delph1()`
(`src/racoon/handler.c:377-464`) for every live Phase 1 handle. `delph1()`
*does* call `script_hook(iph1, SCRIPT_PHASE1_DOWN)`
(`src/racoon/handler.c:385`) — so the hook is invoked, at the C level, on
every code path that tears down a Phase 1 SA, including this one. The bug
is not a missing call; it is a race the call loses.

`script_hook()` → `privsep_script_exec()` → (when running as root, the
common case — `src/racoon/privsep.c:956-957`) `script_exec()`
(`src/racoon/isakmp.c:3231-3261`), which does:

```c
switch (fork()) {
case 0:
	execve(argv[0], argv, envp);
	...
	_exit(1);
	break;
...
}
return 0;
```

This is fire-and-forget: the parent (racoon's main process) never
`waitpid()`s on the forked hook process, and returns immediately.
`close_session()` proceeds straight through `flushph2()`, `flushrmconf()`,
`flushsainfo()`, `close_sockets()`, `backupsa_clean()`, one `plog()` call,
and `exit(0)` (`src/racoon/session.c:346-357`) — all of which happens in
well under a millisecond after the `fork()`, while `phase1-down.sh` has
barely started (it still has to resolve `SCRIPT_DIR`, source
`racoon-hook-lib.sh`, and run `rhook_state_oldest_unconsumed()` before it
touches anything).

The shipped `debian/racoon.service` unit runs racoon as
`Type=simple` with `ExecStart=-/usr/sbin/racoon -F $RACOON_ARGS` and no
explicit `KillMode=` — which defaults to `KillMode=control-group`
(systemd's documented default per `systemd.kill(5)`). Under that default,
once systemd observes the `Type=simple` main process exit, it treats the
unit as stopped and kills every remaining process left in the unit's
control group — including the orphaned `phase1-down.sh` (and everything it
may have already spawned: `ip`, `resolvectl`/`nmcli`, `setkey`) — which is
still in that same cgroup, since `fork()` does not move a child to a new
one. The hook process loses the race between "finish tearing down the
tunnel" and "get reaped by the cgroup cleanup systemd performs immediately
after the main process it was tracking disappears."

This mechanism is inferred from source plus systemd's documented
`KillMode` semantics, not confirmed live (no systemd host was available in
this session) — see the reproducer below for how to confirm it directly.

**Reproducer (on a systemd host running the shipped unit or equivalent):**

```sh
# Terminal 1: watch the cgroup racoon actually runs in
systemctl show racoon.service -p ControlGroup
watch -n 0.2 "systemd-cgls \$(systemctl show racoon.service -p ControlGroup --value)"

# Terminal 2: bring a tunnel up, confirm phase1-up.sh ran and left state
systemctl status racoon
ls /run/racoon/hook-state.*

# Terminal 3: stop the daemon and see whether phase1-down.sh's own log
# line (RACOON_HOOK_DEBUG=2+, /run/racoon/hook.trace) ever appears, and
# whether /run/racoon/hook-state.* survives the stop
systemctl stop racoon
cat /run/racoon/hook.trace 2>/dev/null | tail -20
ls /run/racoon/hook-state.* 2>/dev/null   # a survivor here confirms the race was lost
```

A more direct confirmation, bypassing systemd's cgroup cleanup entirely to
isolate the fork/exit race from the cgroup-kill mechanism specifically:

```sh
# Run racoon directly (not under systemd), so no cgroup kill can interfere
sudo /usr/sbin/racoon -F -f /etc/racoon/racoon.conf &
RACOON_PID=$!
# ... bring a tunnel up ...
sudo kill -TERM "$RACOON_PID"
# If phase1-down.sh's state-file cleanup still doesn't complete here, the
# race is inherent to the fork-without-wait in script_exec() itself, not
# specific to systemd's cgroup kill -- narrows the fix to isakmp.c.
```

**Status: resolved** — fixed in `src/racoon/isakmp.c` (`script_exec()`,
`script_hook()`), `src/racoon/session.c`/`session.h`
(`racoon_shutting_down`), and `src/racoon/privsep.c`
(`privsep_sigterm_forward()`).

**Decision.** Of the two directions this document originally scoped, a
bounded `waitpid()` in `script_exec()` was chosen over
`KillMode=mixed`/`TimeoutStopSec` at the systemd-unit level, for two
reasons found while implementing it:

1. **Portability.** This project targets NetBSD as well as Linux, and
   NetBSD has no systemd. A C-level fix protects both `systemctl stop`
   and a bare `kill <pid>` (or NetBSD's `rc.d` equivalent) identically,
   with no per-init-system unit-file logic and no NetBSD-specific gap to
   document.
2. **It is not actually a choice between exactly the two original
   options.** Tracing every call site into daemon shutdown (per this
   document's own standing instruction) surfaced that `privsep` changes
   *which fix is needed*, not just *which process runs the hook*: see
   the privsep finding below. `KillMode=mixed` alone would not have
   addressed it, since the underlying problem there is the privileged
   process's own signal disposition, not process-group cleanup timing.

**The fix, and why it is scoped the way it is.**

`script_exec()` now does a bounded, `WNOHANG`-polling `waitpid()` (3000ms,
polled every 50ms) on the hook it just forked, but *only* when asked to
via a new internal-only `RACOON_SCRIPT_WAIT` entry in the `envp` it
receives — not unconditionally for every `SCRIPT_PHASE1_DOWN`/
`SCRIPT_PHASE1_DEAD` invocation as this document's own two proposed
directions originally implied. Tracing `delph1()`'s callers
(`src/racoon/handler.c`, `isakmp.c`, `isakmp_inf.c`, `isakmp_xauth.c`,
`isakmp_cfg.c`) showed `SCRIPT_PHASE1_DOWN` also fires from ordinary,
frequent, *non-shutdown* events: peer-initiated deletes, negotiation
errors, xauth failures. Likewise, all three `SCRIPT_PHASE1_DEAD` call
sites (`isakmp_ph1resend()`'s retry-exhaustion path, `isakmp_ph1delete()`'s
SA-expiry path, and DPD timeout in `isakmp_inf.c`) fire during normal
operation, on a scheduler callback, never from `close_session()`.
Blocking the single-threaded main loop for up to 3s on *every* such event
— not just at shutdown — would have traded a shutdown-only bug for a
standing, adversary-triggerable latency/DoS-adjacent regression affecting
every other concurrent negotiation each time a peer disconnects, times
out, or fails DPD. That would have been a worse fix than the bug it
closes, per this project's own standing rule for this kind of change.

So: `close_session()` (`session.c`) sets a new flag, `racoon_shutting_down`
(`session.h`), before it calls `flushph1()` — the *only* place this
document's own root-cause tracing found that genuinely means "the daemon
is exiting." `script_hook()` (`isakmp.c`) only asks `script_exec()` to
wait when `racoon_shutting_down` is set **and** the script is
`SCRIPT_PHASE1_DOWN` (not `SCRIPT_PHASE1_DEAD`, which per the above never
fires from shutdown at all in the current tree). `SCRIPT_PHASE1_UP` was
never a candidate, per this document's own original note: blocking the
main loop on it mid-negotiation is not acceptable, and remains
fire-and-forget.

The `RACOON_SCRIPT_WAIT` decision travels through the *existing*, already
variable-length, already-marshaled `envp` channel — including across
`privsep`'s IPC when privsep is active — rather than through
`privsep_com_msg`'s fixed-size, manually-counted wire struct. Threading a
new field through that struct's hand-counted `PRIVSEP_NBUF_MAX` buffer
indices was judged a materially riskier change to a security boundary
(privilege-separation IPC) than the shutdown race it would help fix more
"cleanly," so it was deliberately avoided; see the comments on
`RACOON_SCRIPT_WAIT_ENV` and in `script_exec()` (`isakmp.c`) for the
detailed reasoning. `script_exec()` strips the entry before `execve()`,
so it is never visible to the hook script's own environment.

**The privsep finding.** This document's own standing instruction —
confirm privsep's effect on each issue rather than assuming it is
irrelevant — surfaced a second, more severe bug than the one originally
filed. Under `privsep`, `privsep_init()` (`privsep.c`) forks before the
main loop starts; the *parent* (which keeps the original pid, and is
therefore the pid systemd's `Type=simple` unit tracks as `$MAINPID`)
becomes the privileged process, and only it can ever actually
`fork()`+`execve()` a hook — `script_exec()` in the unprivileged child's
own address space is never reached; the child instead sends a
`PRIVSEP_SCRIPT_EXEC` IPC request and blocks for a reply. Before this
fix, the privileged process left `SIGTERM`/`SIGINT` at their default
disposition (`signal(SIGTERM, SIG_DFL)` — immediate termination, no
handler). A `systemctl stop racoon` (or any `kill <pid>` naming
`$MAINPID`) therefore killed the privileged process **on the spot**,
before the child's request for `SCRIPT_PHASE1_DOWN` could ever arrive
over `privsep_sock`. Under privsep, the down hook was not merely raced by
a fast `exit(0)` as originally filed — it was **never attempted at all**.

The fix: `privsep_init()` now installs `privsep_sigterm_forward()` for
`SIGINT`/`SIGTERM` in the privileged process instead of `SIG_DFL`. The
handler forwards the signal to the recorded child pid via `kill()`
(async-signal-safe per POSIX.1-2008 §2.4.3) and returns; the privileged
process's existing `privsep_recv()` loop is untouched and keeps running
exactly as before (it already tolerates `EINTR`), now naturally servicing
the child's now-bounded-wait `SCRIPT_EXEC` request before the child exits
and the parent's own pre-existing `EOF → _exit(0)` path takes over. Also
changed: `PRIVSEP_SCRIPT_EXEC`'s handler in `privsep.c`'s dispatch loop
now calls the same `script_exec()` (unchanged from the non-privsep case)
so the wait applies identically whether or not privsep is active.
`SIGHUP`/`SIGUSR1`/`SIGUSR2` are deliberately left at `SIG_DFL` in the
privileged process — config reload is a separate, unfiled concern (this
process has no config to reload) and touching it was out of scope here.

**`/* UNVERIFIED: */`.** None left as unverified reasoning — every claim
above about `fork()`/`waitpid()`/signal semantics is either cited against
POSIX directly (see the code comments on `script_wait_down()` and
`privsep_sigterm_forward()`) or confirmed by the live tests below. What
*is* an accepted, documented limitation rather than something unverified:
serial shutdown latency. `flushph1()` iterates every live Phase 1 SA and
calls `delph1()` for each; with several concurrent SAs at shutdown, each
one's down hook is waited on serially, so worst-case shutdown time scales
with the SA count (bounded per-hook at 3s). This stays comfortably under
systemd's default 90s `TimeoutStopSec` for any realistic SA count, but
was not re-engineered to wait in parallel — that would be a larger,
separately-riskier change than this issue warrants.

**Verification performed.**

- `test/test_script_exec_wait.c` (new `check_PROGRAMS` unit test):
  drives `script_exec()` directly with real `fork()`+`execve()` of small
  throwaway shell scripts (not mocked) and asserts, with real wall-clock
  timing: (1) no `RACOON_SCRIPT_WAIT` ⇒ returns immediately, unchanged
  fire-and-forget behavior; (2) `RACOON_SCRIPT_WAIT=1` ⇒ blocks until the
  script actually finishes; (3) the sentinel never reaches the script's
  own `execve()` environment; (4) a script that outlives the 3000ms bound
  does not hang `script_exec()` forever — it gives up on schedule, and
  the test itself reaps the still-running script afterward so it does
  not leak past the test.
- `test/test_privsep_sigterm_forward.c` (new `check_PROGRAMS` unit
  test): drives the actual, compiled `privsep_sigterm_forward()` against
  a real forked child and a real kernel-delivered `SIGTERM` (not
  simulated), confirming the child receives it and confirming the
  function is a safe no-op with no child pid recorded.
- Both new tests were confirmed to **fail** with their respective fix
  reverted (temporarily, for verification only) and **pass** with it
  restored, confirming they exercise the fixed code paths rather than
  trivially passing.
- `make check`: 37/37 pass (up from 35 — the two new tests), no
  regressions in the existing suite, including `test_script_hook_leak`
  (which also compiles `script_hook()` and needed a
  `racoon_shutting_down` stub, added to its existing stub file).
- Full build (`autoreconf -fi`; `./configure --enable-security-context=no`
  to work around an unrelated, pre-existing deprecated-`security_context_t`
  build break from this environment's newer libselinux) succeeds,
  including the real `racoon` and `racoonctl` binaries with `privsep.o`
  linked in.
- **Not performed, and why:** live reproduction of the original F2
  observation (`systemctl stop racoon` against a real established
  tunnel, checking for leftover interface/routes/SPD) as this document's
  own verification section calls for. This session's container has no
  `systemd`, and more fundamentally lacks a `PF_KEY`/XFRM-capable
  kernel (`/proc/net/pfkey` does not exist, and no `modprobe` is
  available to load `af_key`); `racoon`'s own `pfkey_init()`
  (`session.c`) — which runs before `privsep_init()` — fails immediately
  on this host, so `racoon` cannot be started far enough to reach a live
  Phase 1 SA at all, with or without this fix. The two new unit tests
  above exercise the actual fixed functions with real `fork()`/`execve()`/
  signal delivery, which is the closest live verification achievable in
  this environment; the originally-filed F2 reproducer
  (`doc/dev/daemon-issues.md`'s own "Reproducer" section above) remains
  the right next step on a host with a working `PF_KEY`/XFRM stack and,
  ideally, systemd, and should be run before this fix is considered fully
  closed out operationally.

The hooks themselves still also treat any residual delay defensively:
state left over from an interrupted teardown is retried by the next
`phase1-up.sh`/`phase1-down.sh` invocation rather than lost (brief 3
§D's generation scheme) — see `doc/admin/split-dns.html` §6. That
safety net is unchanged by this fix and remains in place as defense in
depth, not as a substitute for it.

---

## Issue 2 (F5): foreground log output is unreliable under systemd (buffering, not stderr)

**Severity:** medium — does not affect the hooks' own correctness (they
have their own independent trace file, `/run/racoon/hook.trace`, precisely
because racoon's own logging could not be relied on during this
engagement's live testing), but makes diagnosing racoon's *own* behavior
(SA negotiation, the Issue 1 race above) unreliable via `journalctl -u
racoon`.

**Correction to the original finding.** Brief 3 described this as "stderr
block-buffered, duplicated, torn." Reading `src/racoon/plog.c` shows the
affected stream is actually **stdout**, not stderr — `plogv()`
(`src/racoon/plog.c:174-201`) writes every log line via
`vprintf(newfmt, ap)` (`src/racoon/plog.c:189`) when `f_foreground` is set
(the `-F` flag, `src/racoon/main.c:199`, and exactly what
`debian/racoon.service`'s `ExecStart=-/usr/sbin/racoon -F ...` passes).
`vprintf` targets `stdout` by definition. Under systemd, a unit's stdout
and stderr are both captured into the journal by default and appear
interleaved in `journalctl` output regardless of which fd they came from,
which is almost certainly why the practical, live-observed symptom reads
as "stderr is unreliable" even though the actual call site is stdout. The
underlying mechanism (buffering, below) applies to stdout either way, so
the *symptom* the brief described is accurate; only the specific fd
attribution needed correcting here, per this engagement's standing
requirement to flag anything that proved wrong against reality.

**Root cause.** Nowhere in `src/racoon/plog.c`, `src/racoon/main.c`, or
`src/racoon/session.c` is `setvbuf()`/`setbuf()` ever called on `stdout`.
glibc's default stdio buffering is line-buffered only when the target fd
is a TTY; for anything else — a pipe, which is exactly what a systemd
unit's stdout is connected to (systemd reads it via a pipe/socket into the
journal, never a TTY) — the default is **fully block-buffered** (typically
a 4 KiB buffer). That means log lines do not reach the journal until the
buffer fills or the process calls `fflush()`/exits cleanly through
`exit()` (which flushes open `FILE*` streams via its registered
`atexit`-style stdio cleanup) — `_exit()` (used by the failed-`execve()`
path in `script_exec()`, and by any code path that bypasses `exit()`)
skips that flush entirely. Combined with Issue 1's fork/exit race, a
`plog()` call made in the last few lines of `close_session()` before
`exit(0)` is not guaranteed to have left the block buffer before the
process (or, under privsep, cooperating processes sharing descriptors
across a `fork()`) disappears — explaining reports of missing, torn, or
oddly-ordered lines right around shutdown specifically, while calls
earlier in a long-running session eventually flush once the buffer fills
and look normal.

**Reproducer:**

```sh
# Run racoon in the foreground exactly as the unit does, but pipe stdout
# through `cat` instead of a TTY, to reproduce the non-TTY buffering mode
# systemd triggers, without needing systemd at all:
sudo /usr/sbin/racoon -F -f /etc/racoon/racoon.conf | cat
# Compare against a real TTY (no pipe):
sudo /usr/sbin/racoon -F -f /etc/racoon/racoon.conf
# Bring a tunnel up/down in both cases and compare how promptly each
# INFO/WARNING line appears relative to the actual negotiation event.
```

```sh
# Confirm the non-TTY block-buffering directly with strace, no VPN traffic
# needed -- count write(1, ...) syscalls against stdout while idle vs.
# under load; block buffering shows far fewer, larger writes than the
# number of plog() calls actually made:
sudo strace -f -e trace=write -p "$(pgrep -o racoon)" 2>&1 | grep 'fd=1\|"1<'
```

**Why not fixed here.** The fix (`setvbuf(stdout, NULL, _IOLBF, 0)` early
in `main()`, or switching foreground logging to `stderr` with the same
treatment, or writing directly via `write(2, ...)`/`syslog()` unconditionally
instead of `vprintf()`) is a behavior change to `src/racoon/plog.c` and
`main.c`, out of scope for §G. Workaround already in place: the hooks
maintain their own independent, explicitly-flushed trace/report/state
files under `/run/racoon/` (`doc/admin/split-dns.html` §6) rather than
depending on racoon's own log stream for anything the hooks themselves
need to reason about.

---

## Issue 3 (F8): "authtype mismatched" `WARNING` on every Phase 2 negotiation is expected noise, not a real problem

**Severity:** low — cosmetic/diagnostic-quality issue only; does not
affect negotiation outcome. Filed because it was flagged during live
testing as looking like a fault ("`authtype mismatched: my:hmac-sha256
peer:hmac-sha512`" on every Phase 2), and an operator unfamiliar with the
matching algorithm below could reasonably mistake it for a misconfiguration
or a downgrade attempt.

**Root cause.** `cmpsatrns()` (`src/racoon/proposal.c:579-630`) is the
per-transform comparator called from `get_ph2approval()`'s matching loop
(`src/racoon/proposal.c:475-479`):

```c
for (tr1 = pr1->head; tr1; tr1 = tr1->next) {
	for (tr2 = pr2->head; tr2; tr2 = tr2->next) {
		if (cmpsatrns(pr1->proto_id, tr1, tr2, ph1->rmconf->pcheck_level) == 0)
			goto found;
	}
}
```

This is a brute-force search over every `(peer transform, my configured
transform)` pair, `goto found` on the first pair that matches on every
field `cmpsatrns()` checks (transform ID first, then, at
`src/racoon/proposal.c:594-601`, `authtype`). When a peer proposes more
than one transform per proposal (e.g. offering both `hmac-sha256` and
`hmac-sha512` as alternatives, a normal and RFC-legal way to offer a
preference-ordered choice) and racoon's own `sainfo` is configured to
accept more than one, `cmpsatrns()` is called once per candidate pair
tried before the search lands on a pair that actually matches — and it
logs at `LLV_WARNING` (`src/racoon/proposal.c:594-599`) on *every* pair it
rejects along the way, not just on a genuine, search-exhausted failure.
The warning text is therefore an artifact of the search order, emitted
even on a completely successful negotiation that simply didn't match on
its first-tried transform pair.

**Reproducer:**

```sh
# Peer-side (or a second racoon instance acting as responder) sainfo
# offering two authtypes, most-preferred first:
sainfo anonymous
{
    ...
    proposal_check obey;   # or claim/strict -- reproduces regardless
    ...
}
# In the *responder's* remote{} sainfo, list both, e.g.:
#   authentication_algorithm hmac_sha256, hmac_sha512;
# Bring up a tunnel and grep the log for every "authtype mismatched" line
# per single successful Phase 2:
grep 'authtype mismatched' /var/log/racoon.log   # or journalctl -u racoon
# Expect one WARNING line per non-matching (tr1, tr2) pair the nested loop
# tried before landing on the pair that succeeded -- present even though
# the SA came up correctly, confirmed by a following "IPsec-SA established"
# line for the same negotiation.
```

**Why not fixed here.** Silencing or relocating this diagnostic (e.g.
logging the *search outcome* once, at `LLV_INFO`, instead of every
rejected candidate pair at `LLV_WARNING`) is a behavior change to
`src/racoon/proposal.c`'s logging, out of scope for §G. Noted here mainly
so an operator (or a future reader of racoon's logs while debugging Issue
1/Issue 2 above) does not mistake this expected search noise for an actual
negotiation fault.

---

## Issue 4: `racoonctl vpn-disconnect` (and any admin-socket event wait) can exit non-zero with zero output

**Severity:** low — does not affect the underlying teardown, which
proceeds and succeeds independently; purely a diagnostic/scripting
concern. Filed because it produced a misleading "did not return cleanly"
signal in **every one of 8 live Task F test runs** (`doc/dev/
teardown-investigation.md`) across three distros, well under the
configured timeout each time — a 100% reproduction rate makes this worth
documenting precisely rather than shrugging off as a one-off race.

**Root cause.** `f_vpnd()` (`src/racoon/racoonctl.c:708-733`) sets
`evt_quit_event = EVT_PHASE1_DOWN` and delegates to
`f_deleteallsadst()`; the shared `f_vc()` request loop
(`src/racoon/racoonctl.c:296-327`) then blocks in `com_recv()`
(`src/racoon/kmpstat.c:136-189`) waiting for that event to arrive over the
admin `AF_UNIX` socket. `com_recv()` has two distinct failure paths that
both `goto bad1` with **no `perror()` or any other diagnostic call**:

```c
/* receive by PEEK */
if ((len = recv(so, &h, sizeof(h), MSG_PEEK)) == -1)
	goto bad1;

/* sanity check */
if (len < sizeof(h))
	goto bad1;
```

(`src/racoon/kmpstat.c:149-154`). If the admin socket EOFs or resets
before the expected event arrives on that specific connection — for
whatever reason on racoon's side, not otherwise diagnosed here — either
branch fires silently, `com_recv()` returns `-1`, and `f_vc()`'s caller
falls through to:

```c
bad:
	close(so);
	if (errno == EEXIST)
		exit(0);
	exit(1);
```

(`racoonctl.c:322-326`). `errno` at this point is whatever a clean EOF
happened to leave behind, essentially never `EEXIST`, so this is a
silent `exit(1)`: no stdout, no stderr, non-zero exit, and — critically —
this happens fast (well under any reasonable timeout), not after a hang.
Meanwhile racoon's own teardown (`isakmp_ph1delete()`, `delph1()`, the
`SCRIPT_PHASE1_DOWN` hook) proceeds via its own internal path, independent
of whether `racoonctl`'s specific connection saw the event, and reliably
completes a moment later — confirmed in all 8 Task F runs, where
`phase1-down.sh`'s own completion summary always appeared in syslog
shortly after `vpn-disconnect` had already exited non-zero.

**Reproducer:**

```sh
# Bring a tunnel up, then disconnect while capturing both the exit code
# and all output -- expect an empty capture with a non-zero exit on a
# meaningful fraction of runs, well under any timeout:
racoonctl vpn-connect <gateway>
racoonctl vpn-disconnect <gateway>; echo "exit=$?"
# Compare against syslog: phase1-down.sh's own "result: OK|PARTIAL"
# summary (tag racoon-phase1-down) still appears a moment later,
# independent of the exit code above.
journalctl -t racoon-phase1-down --no-pager | tail -5
```

**Status: resolved** — fixed in `src/racoon/kmpstat.c`'s `com_recv()` by
commit `735f2ff` ("racoonctl: report why com_recv() failed on a
short/EOF admin reply (#4)").

One of the two `goto bad1` paths this issue originally described (the
`MSG_PEEK`-failure branch, `recv() == -1`) had already picked up a
`warn()` call in a since-merged, unrelated fix for issue #89 (commit
`69d1129`, "racoonctl: replace confusing 'send: Bad file descriptor' with
a real diagnostic"). The remaining silent path — the "sanity check"
branch (`len < sizeof(h)`), which is what every one of the 8 live Task F
runs actually hit, since a clean connection close arrives as a `recv()`
return of `0`, not `-1` — stayed silent until this fix. It now
distinguishes a clean EOF (`len == 0`: "racoon closed the admin
connection before sending a reply header (EOF)") from a genuine
truncated-header short read (`0 < len < sizeof(h)`: "short read from
racoon: got N of M expected header bytes"), using `warnx()` rather than
`warn()` since `errno` is not meaningfully set by either condition (the
`recv()` call itself succeeded).

`racoonctl.c`'s `main()` calls `com_recv()` directly (not through a
separate `f_vc()` helper — that name in this document's original
Root-cause section reflects an earlier revision of the tree; the current
`do { ... } while (evt_quit_event != 0)` loop and its `bad:`/`exit(1)`
path are the same code, just inlined in `main()`). `warnx()` writes to
`stderr`, which glibc leaves unbuffered by default, so the message is
flushed well before `main()`'s `bad:` label reaches `exit(1)` — confirmed
live (see below), not just by reading the code.

Verified with two mock-admin-socket reproductions standing in for a live
racoon (an `AF_UNIX` listener that accepts the connection and then either
closes immediately or writes a 2-of-8-byte truncated header before
closing), run against `src/racoon/racoonctl` built from this fix:

```
$ racoonctl -s /tmp/mock_admin.sock vpn-disconnect 203.0.113.1; echo "EXIT=$?"
racoonctl: racoon closed the admin connection before sending a reply header (EOF)
EXIT=1

$ racoonctl -s /tmp/mock_admin2.sock vpn-disconnect 203.0.113.1; echo "EXIT=$?"
racoonctl: short read from racoon: got 2 of 8 expected header bytes
EXIT=1
```

Before the fix, both runs printed nothing and exited 1 — exactly the
originally-filed symptom.

Also added `test/test_kmpstat_com_recv.c`, a `check_PROGRAMS` unit test
following this project's established unit-test-a-static-function pattern
(`kmpstat_unittest_src.c` wraps `kmpstat.c`, `com_set_fd_unittest()` is a
new `-DENABLE_UNITTEST`-only accessor for `com_recv()`'s private socket
fd). It drives `com_recv()` against a `socketpair()` for the EOF case,
the truncated-header case, and a well-formed-reply regression guard
(asserting `com_recv()` stays silent and succeeds on a normal exchange).
Confirmed the two failure-path tests fail without this fix (temporarily
reverted the diagnostic, kept the test accessor) and pass with it,
verifying the tests actually exercise the fixed code path rather than
trivially passing.

`/* UNVERIFIED: */` — none remaining for this issue. The fix is a pure
diagnostic addition (no control-flow change beyond what
`if (len < sizeof(h))` already did), so no syscall/signal semantics
needed re-verification here.
