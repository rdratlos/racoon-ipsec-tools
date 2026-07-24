# racoon daemon-side issues found during split-DNS hook testing

Filed per brief 3 §G (Issues 1-3) and the Task F ACQUIRE-provenance
investigation (Issue 4, `doc/dev/teardown-investigation.md`). These are
**not fixed here** — this work package is explicitly scoped to *filing*
what live testing on a Xubuntu Bionic 32-bit roadwarrior (racoon 0.9.1,
OpenSSL 1.1.1, systemd 237) and, for Issue 4, a wider set of live hosts
(Bionic, Noble, Arch) surfaced in `src/racoon`'s own C code, each traced
to a concrete source location and given a reproducer, so a future change
to the daemon itself can be scoped correctly. No file under `src/racoon/`
is touched by this document or by the commit that adds it.

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

**Why not fixed here.** Any real fix (e.g. a bounded `waitpid()` with
timeout in `script_exec()` for the `SCRIPT_PHASE1_DOWN`/`SCRIPT_PHASE1_DEAD`
cases specifically, not the fire-and-forget `SCRIPT_PHASE1_UP` case where
blocking the daemon's main loop is not acceptable; or shipping
`KillMode=mixed` plus a `TimeoutStopSec` generous enough for the hook to
finish in the unit file) is a behavior change to the daemon's shutdown path
or its packaging, both out of scope for brief 3 §G, which is filing-only.
The hooks themselves already treat this defensively: state left over from
an interrupted teardown is retried by the next `phase1-up.sh`/
`phase1-down.sh` invocation rather than lost (brief 3 §D's generation
scheme), so this issue causes stale-but-recoverable state, not silent data
loss — see `doc/admin/split-dns.html` §6.

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

**Why not fixed here.** A real fix (adding `perror()`/an explicit error
message on both `goto bad1` paths in `com_recv()`, or having `f_vc()`
distinguish "clean EOF after the request was accepted" from "not
delivered at all" before deciding its own exit code) is a behavior change
to `src/racoon/kmpstat.c` and/or `racoonctl.c`, out of scope for this
filing-only pass. Workaround already in place in
`task-f-acquire-investigation.sh`: it never treats `vpn-disconnect`'s own
exit code as authoritative, and instead waits for `phase1-down.sh`'s own
always-emitted syslog summary before drawing any conclusion — any script
or operator relying on `racoonctl vpn-disconnect`'s exit code alone should
do the same.
