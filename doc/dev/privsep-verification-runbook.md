<!--
SPDX-License-Identifier: BSD-3-Clause
Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
-->

# Manual verification: privsep dispatch loop (issue #105)

The one thing `make check` cannot reach. The privileged dispatch loop only
runs inside `privsep_init()`'s privilege-dropping `fork()`, which needs a
real PF_KEY/XFRM kernel and a real unprivileged peer — so it has to be
driven on a real host. This runbook does that on a roadwarrior client.

Companion to `fatal-exit-path-audit.md`; section references (§2.2, §2.3.1,
…) point into that report.

**Run this on a test machine.** Phase 3 deliberately takes the daemon down,
and Phase 4 deliberately corrupts its IPC.

---

## 0. What each phase is actually for

| Phase | Verifies | Destructive |
| --- | --- | --- |
| 1 | The happy path still works — the regression risk the changes carry | no |
| 2 | The descriptor handshake goes over the wire in the new order (§2.2) | no |
| 3 | The bounded wait fires and exits cleanly instead of hanging (§2.3.1) | yes |
| 4 | One bad request no longer kills the daemon (§2.1) | yes |

Phase 1 is the one that must not be skipped. The audit's containment
changes are mostly on paths a healthy daemon never takes; what they *did*
touch on the healthy path is the descriptor-passing order, and if that were
wrong racoon would fail to bind or to negotiate at all. Phases 3 and 4 are
the interesting ones, but Phase 1 is the one that catches a mistake.

### Control run (recommended)

Phases 3 and 4 are before/after tests, and their "before" is worth seeing:
on `develop` the daemon does not exit — it stops responding while looking
perfectly healthy. Doing a control run first makes the difference concrete,
and takes ten minutes:

```bash
git checkout develop && make && sudo make install     # control
# ... run phase 3 and/or 4, observe the hang / the daemon dying ...
git checkout claude/audit-process-exit-paths-0o4m7u && make && sudo make install
```

---

## 1. Setup

### Build

```bash
git clone https://github.com/rdratlos/racoon-ipsec-tools
cd racoon-ipsec-tools
git checkout claude/audit-process-exit-paths-0o4m7u
./bootstrap
./configure --prefix=/usr --sbindir=/usr/bin --sysconfdir=/etc/racoon \
            --libdir=/usr/lib/ipsec-tools --localstatedir=/var/run \
            --with-environmentdir=/etc/conf.d
make && make check
sudo make install
```

Those are `packaging/arch/PKGBUILD`'s own flags, so the result matches what
the Arch package would install. Everything else this branch needs
(adminport, NAT-T, fragmentation) is on by default.

Do **not** strip the binary — Phase 3 wants symbols. `make install` does not
strip; `makepkg` does, so build directly rather than through the PKGBUILD if
you plan to run Phase 3.

Build dependencies beyond the usual toolchain: `flex`, `bison`, `openssl`.

### racoon.conf

Privsep only engages when `user` resolves to a non-root uid, and
`privsep_init()` refuses to start without **both** path directives — it is a
hard requirement, not a suggestion, because they are what makes the
privileged side's path checks meaningful:

```
path certificate "/etc/racoon/certs";
path script      "/etc/racoon/scripts";

privsep {
        user  "racoon";
        group "racoon";
}

log debug;
```

The Arch package already creates the `racoon` system user
(`packaging/arch/ipsec-tools.sysusers`). `log debug;` is what surfaces the
privileged side's per-command lines used below; drop it again afterwards.

**Expect every log line twice.** `plogv()` (plog.c) writes to stdout when
running in the foreground *and* to syslog, and the shipped unit runs
`racoon -F`, so systemd captures both copies into the journal under the
same `racoon[PID]` identifier. It is pre-existing and cosmetic, but worth
knowing before reading any of the phases below: a message appearing twice
is one message, not a repeated code path. `journalctl -o verbose` tells
them apart by `_TRANSPORT` (`stdout` vs `syslog`), or add
`StandardOutput=null` to a drop-in to suppress the stdout copy for the
duration of the testing.

### Identify the two processes

```bash
sudo journalctl -u racoon | grep -E 'privileged|unprivileged'
# racoon privileged process running with PID 1234
# racoon unprivileged process running with PID 1235

PRIV=1234   # runs as root, is the parent, serves the dispatch loop
CHILD=1235  # runs as racoon, is the daemon proper
```

`ps -o pid,user,cmd -p $PRIV,$CHILD` should show exactly that split. If both
run as root, privsep did not engage — recheck `user`/`group` above.
(`setproctitle("[priv]")` is BSD-only, so on Linux the two are told apart by
uid, not by name.)

---

## 2. Phase 1 — the happy path

A single connect/disconnect cycle exercises nearly the whole dispatch loop,
because the unprivileged side cannot do any of this for itself:

| Step | Commands reached |
| --- | --- |
| Resolving a local address for the peer (`getlocaladdr()`, sockmisc.c) | `PRIVSEP_SOCKET`, `PRIVSEP_SETSOCKOPTS` ×2 (in/out bypass) |
| Dumping the SADB (`pfkey_dump_sadb()`, pfkey.c — `vd`, `show-sa esp`, DPD) | `PRIVSEP_SOCKET` (PF_KEY) |
| Opening/binding an ISAKMP socket (`isakmp_open()`) | `PRIVSEP_SOCKET`, `PRIVSEP_SETSOCKOPTS`, `PRIVSEP_BIND` |
| Authentication | `PRIVSEP_EAY_GET_PKCS1PRIVKEY` (X.509) or `PRIVSEP_GETPSK` (PSK) |
| `phase1-up` / `phase1-down` hooks | `PRIVSEP_SCRIPT_EXEC` |
| `systemctl stop` | `PRIVSEP_SCRIPT_EXEC` with the wait flag (Issue 1/F2) |

```bash
sudo systemctl start racoon
sudo racoonctl vc -u <user> <gateway>      # or: ping <remote-subnet-host>
racoonctl show-sa isakmp
racoonctl show-sa esp
# pass real traffic through the tunnel here
sudo racoonctl vd <gateway>
sudo systemctl stop racoon
```

Expected in the log, attributable to `$PRIV` by PID:

```
eay_get_pkcs1privkey("/etc/racoon/certs/...")   # or: getpsk("...", 32)
script_exec("/etc/racoon/scripts/phase1-up.sh", 0, 0x...)
script_exec("/etc/racoon/scripts/phase1-down.sh", 1, 0x...)
racoon privileged process 1234 terminated      # only at shutdown
```

**Pass:** Phase 1 and Phase 2 SAs establish, traffic flows, both hooks run,
`racoonctl vd` tears down, and the shutdown is clean.

**Fail — and what it would mean:** a failure to bind, or a negotiation that
never gets a local address, points straight at the descriptor-handshake
reordering in §2.2. `privsep: timed out …` appearing here (nobody is
interfering) would mean the reordering left the two sides out of step —
which is the specific thing §2.2 had to get right.

### Already found here

The first run of this phase found a real bug — a **pre-existing** one,
predating the audit (§2.4.1):

```
racoon[PRIV]:  ERROR: privsep_socket: unauthorized domain (15)
racoon[CHILD]: ERROR: libipsec failed pfkey open: Success
```

Domain 15 is `AF_KEY`. `pfkey_dump_sadb()` needs a PF_KEY socket of its
own, and `PRIVSEP_SOCKET`'s policy gate admitted only the two INET
families — so under privsep, `racoonctl vd`, `racoonctl show-sa
esp|ah|ipsec`, and `purge_remote()`'s fallback path (hence DPD and
peer-initiated teardown) could not dump the SADB at all. On `develop` that
refusal ran into the dispatch loop's `_exit()`, so each of them took the
whole daemon down; the containment work is what turned it into the two
legible log lines above. Fixed by admitting PF_KEY in
`pfkey_open()`'s exact shape.

If you see those lines, you are running a build from before that fix —
`git pull` and rebuild. The trailing `: Success` is `ipsec_strerror()`
reporting on an `errno` libipsec never set, not a second fault.

The re-run then found a second pre-existing bug (§2.4.2), visible as a
stray error next to sockets that opened anyway:

```
racoon[CHILD]: ERROR: privsep_setsockopt (Operation not permitted)
racoon[CHILD]: INFO:  fe80::...%racoon0[500] used as isakmp port (fd=17)
```

`privsep_setsockopt()` escalated only on `EACCES` — KAME's errno for this
— while Linux returns `EPERM`, so the privileged process was never asked
and `setsockopt_bypass()`'s in/out bypass policies were never applied
under privsep on Linux. An operator-precedence bug in the same statement
returned that failure to the caller as success, which is why it showed up
as a log line rather than a malfunction. Both fixed.

**Watch for one consequence** on the re-run: with the return value
corrected, a bypass `setsockopt()` that genuinely fails now stops
`isakmp_open()` from opening that socket, instead of opening it
unprotected. Expected result is that the errors simply disappear (the
privileged process can set the policy). If instead you see the
`used as isakmp port` lines *disappear* for some address, that is this
change turning a previously silent failure into a hard one — report it,
because it would mean the bypass has never worked on that host, not that
the fix is wrong.

Note that `privsep_setsockopt()` and `privsep_bind()` only escalate to the
privileged process when the direct call fails with a privilege errno
(`EACCES` or, on Linux, `EPERM` — see §2.4.2). If the unit grants the
daemon `CAP_NET_ADMIN`/`CAP_NET_BIND_SERVICE`, they succeed directly and
those commands are never sent. Phase 2 tells you which happened.

---

## 3. Phase 2 — watch the handshake

```bash
sudo strace -tt -p $PRIV \
     -e trace=socket,bind,setsockopt,recvmsg,sendmsg,sendto,recvfrom
```

**Do not add `-f` here.** Under privsep the privileged process is the one
that forks hooks, so following forks drags in the entire `phase1-up` tree —
every `ip`, `setkey` and `resolvectl` it runs. The first capture of this
phase came to 3041 lines, of which 2601 were `+++ exited with 0 +++` and
`SIGCHLD` from those children and 50 were the privileged process itself.
Without `-f` you get just the 50. If you do want to watch the hook fork,
add `-f -e signal=none --quiet=attach,exit` so the child bookkeeping stays
quiet.

### Reading it

Every request is a peek of the 8-byte `admin_com` header, a read of the
whole message, and one reply. The command is the third and fourth bytes,
little-endian (`privsep.h`):

| bytes | command |
| --- | --- |
| `\1\10` | `PRIVSEP_EAY_GET_PKCS1PRIVKEY` (0x0801) |
| `\3\10` | `PRIVSEP_SCRIPT_EXEC` (0x0803) |
| `\4\10` | `PRIVSEP_GETPSK` (0x0804) |
| `\n\10` | `PRIVSEP_SETSOCKOPTS` (0x080A) |
| `\v\10` | `PRIVSEP_BIND` (0x080B) |
| `\f\10` | `PRIVSEP_SOCKET` (0x080C) |

A bare reply is 200 bytes (`sizeof(struct privsep_com_msg)`); anything
larger is carrying data back.

The ordering is the whole point of §2.2. For `BIND`/`SETSOCKOPTS` the
descriptor is received **immediately after the command, before any
validation**:

```
recvfrom(18, "\370\0\n\10...", 8, MSG_PEEK)      <- SETSOCKOPTS header
recvfrom(18, "\370\0\n\10...", 248, 0)           <- the command
recvmsg(18, {... SCM_RIGHTS ...})              <- the descriptor
setsockopt(3, SOL_IPV6, IPV6_IPSEC_POLICY, ...) = 0
sendto(18, "\310\0\n\10...", 200, 0)             <- the reply
```

and `SOCKET` sends exactly one descriptor message per request, on success
and failure alike:

```
recvfrom(18, "\324\0\f\10...", 8, MSG_PEEK)
recvfrom(18, "\324\0\f\10...", 212, 0)
socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP) = 3
sendmsg(18, {... SCM_RIGHTS [3] ...})
sendto(18, "\310\0\f\10...", 200, 0)
```

**Pass criteria**, all four checkable by counting:

1. peeks == body reads == replies. Drift by one is the desync §2.2 exists
   to prevent.
2. `recvmsg` count == number of `BIND` + `SETSOCKOPTS` commands; `sendmsg`
   count == number of `SOCKET` commands. Exactly one descriptor message
   each way per request.
3. The `socket()` return value does not climb across requests — the
   privileged process closes each descriptor after passing it. A rising
   fd number is a leak.
4. No `privsep: timed out` in the log, and no gap between a command and
   its reply (a stalled request would show as `<unfinished ...>` on
   something other than the idle header peek).

### Result of the first run

Pass, and it confirmed more than the ordering:

* **10 commands, 10 body reads, 10 replies.** No drift.
* **5 `recvmsg` for 4 `SETSOCKOPTS` + 1 `BIND`; 2 `sendmsg` for 2
  `SOCKET`.** Descriptor accounting exact in both directions.
* **`socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP) = 3` twice** — the same
  descriptor number reused, so the privileged process is releasing each
  one after handing it over.
* **`setsockopt(3, SOL_IPV6, IPV6_IPSEC_POLICY, ...) = 0`, four times** —
  two sockets × inbound/outbound (the policy blobs differ only in their
  direction byte, `\4\0\1\0` vs `\4\0\2\0`). This is the §2.4.2 fix
  working end to end: before it, the unprivileged process never escalated
  these at all on Linux, so this is the first time racoon's own bypass
  policies have actually been installed under privsep on this platform.
  It also means `PRIVSEP_SETSOCKOPTS`' escalation path — the reordering of
  §2.2 and the bounded wait of §2.3.1 — has now executed for real.
* **A 1392-byte reply to `EAY_GET_PKCS1PRIVKEY`** (1192 bytes of key past
  the 200-byte header), which is the `racoon_realloc()` grow path rewritten
  in §2.1 doing its job.
* No timeouts, no `EPERM`, no `EACCES`, no desync.

The one line worth a second look is not a fault: a `PRIVSEP_GETPSK`
(224-byte request, 208-byte reply — so 8 bytes of key came back) between
the private-key load and the hook. Whether a PSK lookup belongs in an
X.509 negotiation is a question about the remote's configuration, not
about privsep.

---

## 4. Phase 3 — the bounded wait (§2.3.1)

This is the fix that has no unit-test equivalent, because the failure it
prevents is *silence*: a child that stops talking mid-request, with no EOF
and no error for the privileged process to notice.

Reproduce it by freezing the child between its command and its descriptor —
exactly the window `privsep_wait_io()` now bounds. Prefer the scripted
form, which frees the child again on a timer rather than on your reflexes:

```bash
sudo gdb -p $CHILD -batch \
    -ex 'break send_fd' -ex 'continue' \
    -ex 'shell sleep 6' -ex 'detach' &
sleep 1
sudo racoonctl vc -u <user> <gateway>     # or ping across the tunnel
```

The child stops at `send_fd`, having sent `PRIVSEP_SETSOCKOPTS` (or
`PRIVSEP_BIND`) and never the descriptor. Six seconds is comfortably past
the 3 s bound; `detach` then lets it run again with any pending signals
delivered.

Interactively (`sudo gdb -p $CHILD`, `break send_fd`, `continue`) works
too, but **detach as soon as you have seen the log lines** — see "the
90-second SIGKILL" below for what happens if you sit at the prompt.

**Expected on this branch, within ~3 seconds of the freeze:**

```
privsep: timed out after 3000 ms waiting for privsep_setsockopt's descriptor
privsep: unprivileged process did not complete its request; privsep_sock cannot be resynchronised, terminating
racoon privileged process 1234 terminating: privsep_sock is no longer usable
```

Each line twice, per the note in §1 — the privileged process logs this
once and exits; it does not loop.

`$PRIV` is then gone, with exit status 1 (§2.3.2 — faults and clean
shutdowns no longer report the same status). Check with
`systemctl show racoon -p ExecMainStatus`; the clean-shutdown path reports
0 and says `racoon privileged process N terminated` instead.

**Expected on `develop` (control):** nothing. No log line, both processes
still listed by `ps`, `systemctl status` still green — and:

```bash
sudo cat /proc/$PRIV/wchan; echo        # blocked in a socket read
sudo strace -p $PRIV                    # no syscalls at all, forever
```

That is the failure mode this fix removes: a daemon that looks alive,
serves nobody, and needs a human to notice. Confirming that on `develop`
first is what makes the "after" meaningful.

**Also worth checking:** the child's own log should carry `ETIMEDOUT` for
the failed operation before shutdown — that is
`privsep_handshake_failed()`'s best-effort reply arriving at a client that
is broken rather than gone.

### The 90-second SIGKILL

If the child is still held by gdb when the privileged process exits, the
run ends like this:

```
systemd[1]: racoon.service: State 'stop-sigterm' timed out. Killing.
systemd[1]: racoon.service: Killing process 35474 (racoon) with signal SIGKILL.
systemd[1]: racoon.service: Failed with result 'timeout'.
```

That is the test procedure, not the daemon. The privileged process is the
unit's `MAINPID` (privsep's `fork()` leaves the original pid in the
parent), so when it exits systemd stops the unit and SIGTERMs whatever
remains in the cgroup — here, the child. A ptrace-stopped process cannot
act on that signal, and gdb holds it undelivered while you sit at the
prompt, so systemd waits out `TimeoutStopSec` (90 s by default) and
SIGKILLs.

Detach promptly and the child instead takes its ordinary path: whichever
`privsep_recv()`/`rec_fd()` it was blocked in returns EOF, the call fails,
control returns to the main loop, `privsep_do_exit()` fires on the
now-EOF'd `privsep_sock` and raises SIGTERM on itself, and
`close_session()` runs. Seconds, not ninety.

Note that the same 90 s applies in production to a child that is genuinely
wedged — which is the case this whole bound exists for. That is systemd
doing its job on a process that cannot answer, and it is still bounded,
unlike the state before the fix.

---

## 5. Phase 4 — containment: one bad request (§2.1)

The headline claim: a single malformed or refused request fails *itself*
and the daemon keeps running. On `develop`, each of these ends the process.

### 5a. Refused hook — config only, zero tooling

Point a hook at a script outside `path script`:

```
remote <gateway> {
        script "/tmp/not-under-path-script.sh" phase1_up;
}
```

Expected (both branches): the daemon survives; the privileged side logs

```
privsep_script_exec: unsafe script "/tmp/not-under-path-script.sh"
```

The difference is on the **child** side. Before, the refusal was answered
with an empty success reply and the child believed the hook had run (§2.4);
now it gets `EPERM` and says so. That asymmetry — a hook silently not
running — is worth confirming is gone, since it is the kind of thing that
only ever shows up as "why did my routes not get installed".

### 5b. Corrupted request — fault injection

The corrupted-message paths cannot be reached by a conformant child, so
this needs a shim. It mangles one command's `ac_cmd` on its way out of the
unprivileged process, which lands in the dispatch loop's `default:` case:

```c
/* privsep-fault.c: cc -shared -fPIC -o privsep-fault.so privsep-fault.c */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

ssize_t
sendto(int fd, const void *buf, size_t len, int flags,
       const struct sockaddr *to, socklen_t tolen)
{
	static ssize_t (*real)(int, const void *, size_t, int,
	    const struct sockaddr *, socklen_t);
	static int fired = 0;
	int domain = 0;
	socklen_t dlen = sizeof(domain);

	if (!real)
		real = dlsym(RTLD_NEXT, "sendto");

	/*
	 * Only in the unprivileged process, only on an AF_UNIX socket,
	 * only for a buffer whose first u_int16_t is its own length --
	 * i.e. a privsep_com_msg on privsep_sock -- and only once.
	 */
	if (!fired && geteuid() != 0 && len >= 8 &&
	    getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &dlen) == 0 &&
	    domain == AF_LOCAL && *(const uint16_t *)buf == len) {
		uint8_t copy[4096];
		if (len <= sizeof(copy)) {
			memcpy(copy, buf, len);
			*(uint16_t *)(copy + 2) = 0xbeef;  /* ac_cmd */
			fired = 1;
			return real(fd, copy, len, flags, to, tolen);
		}
	}

	return real(fd, buf, len, flags, to, tolen);
}
```

```bash
sudo mkdir -p /etc/systemd/system/racoon.service.d
printf '[Service]\nEnvironment=LD_PRELOAD=/path/to/privsep-fault.so\n' | \
    sudo tee /etc/systemd/system/racoon.service.d/fault.conf
sudo systemctl daemon-reload && sudo systemctl restart racoon
sudo racoonctl vc -u <user> <gateway>
```

**Expected on this branch:**

```
unexpected privsep command 48879
```

— the one operation that request belonged to fails, and **the daemon keeps
running**. Any already-established SA stays up; a second `racoonctl vc`
succeeds (the shim fires once).

**Expected on `develop`:** the same log line, immediately followed by
`racoon privileged process N terminated` and a dead daemon, taking every
other live SA with it.

Remove the drop-in afterwards:

```bash
sudo rm -r /etc/systemd/system/racoon.service.d/fault.conf
sudo systemctl daemon-reload && sudo systemctl restart racoon
```

### Result of the first run

**5a: pass.** Both halves of the exchange showed up, which is the point —
the refusal on one side and the caller learning about it on the other:

```
racoon[PRIV]:  ERROR: privsep_script_exec: unsafe script "/tmp/phase1-up.sh"
racoon[CHILD]: ERROR: Script phase1_up execution failed
```

That second line is `script_hook()` (isakmp.c) reacting to `EPERM` in the
reply. Before §2.4 the refusal was answered with `ac_errno == 0`, so
`privsep_script_exec()` returned success and that line never printed: the
hook silently did not run. The daemon then carried on normally — a later
`racoonctl vd` purged the SA and ran `phase1-down` — and `phase1-down`'s
own "no live state generation matches this session's IKE_COOKIE" warning
is the expected consequence of a `phase1-up` that never ran, not a second
fault.

**5b: pass, and this is the audit's headline claim confirmed on real
hardware.**

```
racoon[PRIV]:  ERROR: unexpected privsep command 48879
racoon[CHILD]: ERROR: failed to get private key.
racoon[CHILD]: [10.77.254.7] ERROR: failed to process ph1 packet (side: 0, status: 6).
racoon[CHILD]: [10.77.254.7] ERROR: phase1 negotiation failed.
```

48879 is `0xBEEF`, the shim's mangled `ac_cmd`; it landed on the
`EAY_GET_PKCS1PRIVKEY` request. The privileged process refused it with
`EINVAL`, `privsep_eay_get_pkcs1privkey()` returned NULL, and
`oakley_ph1sign()` (oakley.c) failed *that negotiation* — nothing else.

The decisive evidence that the daemon survived is in the next line of the
log, and it is worth knowing to look for: a `racoon-phase1-down[...]`
process ran *after* the fault. Under privsep only the privileged process
can `fork()+execve()` a hook, so a hook running after the corrupted
command is direct proof that process was still alive and still serving
requests. On `develop` that same command reaches the dispatch loop's
`default:` case and `_exit()`s, so there is nothing left to fork it.

For a second, independent check: the shim fires once, so a repeat
`racoonctl vc` should simply succeed.

**5c: not yet run.**

### 5c. The wire budget at its ceiling

**Correction.** An earlier draft of this runbook said a gateway pushing a
large mode-config attribute set could fill `PRIVSEP_NBUF_MAX`'s 24 slots
and trigger the `E2BIG` path of §2.1. That is wrong, and the code says so
in three independent places:

* **Every list-shaped attribute is joined into one string** before it is
  handed to `script_env_append()` — `SPLIT_INCLUDE`,
  `INTERNAL_SPLITDNS_DOMAINS`, `INTERNAL_DNS4_LIST` and the rest. A
  gateway with ten split-DNS domains and eleven split networks makes those
  *values* longer; it does not add entries. No `script_env_append()` call
  in either file sits inside a loop.
* **The env count is fixed-shape**: 6 from `script_hook()` (isakmp.c) plus
  at most 15 from `isakmp_cfg_setenv()` (isakmp_cfg.c) — and the split-DNS
  pair at isakmp_cfg.c:2127/2134 is an if/else, so it contributes one
  either way. 21 maximum, plus script, name and terminator: exactly 24.
* **It is a compile-time assertion**, not a runtime condition:
  `typedef char privsep_script_exec_max_envc_fits_wire_budget[(3 +
  PRIVSEP_SCRIPT_EXEC_MAX_ENVC <= PRIVSEP_NBUF_MAX) ? 1 : -1]` (isakmp.c).
  Exceeding the budget fails the build.

And if it somehow were exceeded, `privsep_script_exec()`'s own guard
(privsep.c) refuses **before anything reaches the wire**:

```
Unexpected error: privsep_script_exec count > PRIVSEP_NBUF_MAX
```

so the privileged side's `E2BIG` is not reachable from a conformant client
at all. It guards a corrupted or hostile message, which is 5b's territory,
not a configuration.

**What is worth running instead.** A mode-config gateway pushing the full
attribute set is the *ceiling* case — all 21 env vars, all 24 slots used,
which is precisely the landmine PR #94 hit when it added a 22nd entry. A
config like

```
default_domain "example.org";
split_dns      "a.example.org b.example.org ... j.example.org";   # 10 domains
split_network  include 10.66.0.0/24, 192.168.66.0/24, ... ;       # 11 networks
```

with XAuth in play (so `XAUTH_USER` is present too) packs the budget
exactly full. Connect with it and confirm:

1. **Neither guard fires.** Nothing in the log saying
   `privsep_script_exec count > PRIVSEP_NBUF_MAX` (client side) or
   `privsep_script_exec: too many args` (privileged side).
2. **The hook runs and receives everything.** `phase1-up` should see
   `SPLIT_INCLUDE`, `INTERNAL_SPLITDNS_DOMAINS`, `DEFAULT_DOMAIN` and the
   rest populated — a truncated or missing variable would mean the joining
   is losing data even though the slot count is fine.

That validates the accounting where it actually matters, which the
unreachable `E2BIG` path never could.

## 6. What to report back

Per phase: pass/fail, plus

```bash
sudo journalctl -u racoon --since "-15min" --output=short-precise \
     --output-fields=MESSAGE,_PID > racoon-phaseN.log
```

The `_PID` field is what attributes each line to the privileged or the
unprivileged process; without it the two are indistinguishable in the
journal, and for this change that distinction is most of the information.

Phase 3 and 5b are the two worth capturing on **both** branches — the delta
is the result, not the log itself.

---

## 7. Making this permanent

This runbook exists because the dispatch loop is not reachable from a test
binary: it is inline in `privsep_init()`, after the `fork()`. Extracting it
into its own `privsep_priv(void)` — a pure code motion, no behaviour change
— would let a test drive the real loop over a `socketpair()` with a scripted
adversarial client, and would cover in CI everything Phases 3 and 5b here do
by hand: silence mid-request, corrupted headers, unknown commands, refused
arguments, descriptor messages that never arrive.

Worth doing before the X.509 client-identity work adds new commands to this
loop. Filed as a follow-up rather than done here, because it is a
refactor-plus-harness change and this branch is a behaviour fix.
