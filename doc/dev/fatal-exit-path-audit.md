<!--
SPDX-License-Identifier: BSD-3-Clause
Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
-->

# Audit: single-request failures that fatally exit the whole daemon

Issue [#105]. Follow-up to [#102], which fixed two instances of one bug
class — a fault scoped to a single request or connection ending the
*entire* racoon process, and with it every unrelated live Phase 1/2 SA.

This report is the sweep that issue asked for: every `exit()`, `_exit()`,
`errx()` and process-ending `return` in the daemon's own sources,
classified as **genuinely fatal** or **containable**, with the containable
ones fixed on the same principle #102 established.

---

## 1. The classification used

A failure is **containable** when, after refusing the request that caused
it, the process still holds consistent state and can serve the next one.
That is a question about *state and protocol*, not about how alarming the
fault looks:

* An unauthorized argument, a corrupted message, a failed allocation for
  one reply, an unknown command — all leave everything else intact. The
  request fails; the daemon runs on.
* A lost IPC framing, an unreadable event socket, a half-rebuilt global
  configuration tree — these leave no defined next request to serve.

A failure is **genuinely fatal** when the process cannot continue in a
defined state, or when it happens during startup, where "refuse and
continue" has no meaning: there is no service yet to preserve, and the
operator gets a clear diagnostic instead of a daemon running in a
half-configured state.

Two supporting rules follow from #102's own trace, and both turned out to
matter more than the classification itself:

1. **Containment must not silently succeed.** A rejected request must be
   answered with an error, not with an empty all-clear reply. Several
   privsep paths did the latter (see §2.4).
2. **Containment must not desynchronise a protocol.** Where a request's
   wire exchange is more than one message, refusing it early can leave the
   other side one message out of step — which is worse than exiting. This
   is why privsep's descriptor-passing commands needed real work rather
   than a `goto` swap (§2.2).
3. **Containment must not convert an exit into a hang.** A process blocked
   forever mid-request is worse than one that exits: it still looks alive,
   serves nobody, and needs a human to notice. Every wait the privileged
   process performs between receiving a request and answering it therefore
   has to be bounded (§2.3.1).

---

## 2. `privsep.c` — the privileged dispatch loop

The case issue #105 named, and by far the largest one.

`privsep_init()`'s parent branch runs `while (1) { privsep_recv(); switch
(ac_cmd) { ... } privsep_send(); }`. Roughly thirty failure paths inside
that loop reached a single `out:` label whose body is
`plog(...); _exit(0);`.

Why that is fatal to the *whole* daemon and not just to the privileged
process: the unprivileged child monitors `privsep_sock[1]` with
`privsep_do_exit()`, which raises `SIGTERM` on itself the moment that
socket reports EOF. So the privileged process exiting is, by construction,
a full daemon shutdown — and under privsep it is also the only process
that can `fork()+execve()` a hook (see the `privsep_sigterm_forward()`
comment block added in Issue 1/F2).

### 2.1 Faults now contained (answered with an errno, loop continues)

| Fault | Command(s) | Reply |
| --- | --- | --- |
| Message too short to hold its own buffer-length array | any | `EINVAL` |
| Buffer lengths claiming more bytes than the message carries | any | `EINVAL` |
| `safety_check()` rejection (void buffer / index out of range) | all 11 commands using it | `EINVAL` |
| Fixed-size argument with the wrong length ("corrupted message") | `GETPSK`, `SCRIPT_EXEC`, `SOCKET`, `BIND`, `SETSOCKOPTS` | `EINVAL` |
| More `SCRIPT_EXEC` arguments than `PRIVSEP_NBUF_MAX` slots | `SCRIPT_EXEC` | `E2BIG` |
| `racoon_malloc()` failure for the `envp` array | `SCRIPT_EXEC` | `ENOMEM` |
| `racoon_realloc()` failure growing the reply to carry a key/PSK | `EAY_GET_PKCS1PRIVKEY`, `GETPSK` | `ENOMEM` |
| Unauthorized socket domain / bind port / socket option | `SOCKET`, `BIND`, `SETSOCKOPTS` | `EPERM` |
| Unrecognised `ac_cmd` | `default:` | `EINVAL` |

Each of these now fails exactly one operation in the unprivileged process —
one certificate load, one PSK lookup, one hook, one socket — which every
one of those call sites already handles, because the same functions already
had to cope with the corresponding "real" errno.

The two `racoon_realloc()` cases also fixed a latent leak: the result was
assigned straight back over `reply`, so a failure lost the pointer to the
still-valid original buffer. They now go through a temporary.

### 2.2 Descriptor passing: why this needed protocol work

`PRIVSEP_SOCKET`, `PRIVSEP_BIND` and `PRIVSEP_SETSOCKOPTS` do not exchange
one message per request. They exchange two, and the split is asymmetric:

* `privsep_socket()` (client) sends the command, then blocks in `rec_fd()`,
  **then** reads the reply.
* `privsep_bind()` / `privsep_setsockopt()` (client) send the command and
  then immediately `send_fd()` the descriptor, unconditionally.

That is precisely why these checks could not previously "just reply an
error": on `PRIVSEP_SOCKET` a reply sent without a preceding descriptor
message would be eaten one byte at a time by the client's `rec_fd()`, and
on `BIND`/`SETSOCKOPTS` an early bail-out would leave the client's
descriptor message queued, to be misread as the next request. Exiting was
the only thing left. Three changes remove that constraint:

* **`send_fd(s, -1)`** now sends the message with no `SCM_RIGHTS` attached
  instead of failing. `PRIVSEP_SOCKET`'s failure paths use it, so exactly
  one descriptor message goes out per request either way.
* **`rec_fd()`** returns -1 for a message that carries no descriptor (and
  validates `cmsg_level`/`cmsg_type`/`cmsg_len` before use). This also
  fixes a real latent crash: the old code ran `CMSG_DATA(cmsg)` and
  dereferenced the result without checking `CMSG_FIRSTHDR()` for `NULL`,
  so any truncated or EOF'd read faulted rather than failing.
* **`PRIVSEP_BIND` / `PRIVSEP_SETSOCKOPTS`** call `rec_fd()` first, before
  validating anything, and `close()` the descriptor on every refusal path.

`privsep_socket()` (client) matches: it no longer returns early when no
descriptor arrives, but reads the reply that follows and reports the errno
it carries.

Both halves of this handshake live in the same binary, in a parent and a
child of the same `fork()`, so there is no mixed-version concern.

### 2.3 Faults that remain fatal — and why

To be precise about what "fatal" means here, since §2 already established
it: there is exactly **one** privileged process, serving exactly **one**
child, over exactly **one** socket. Ending that socket's service *is*
ending the daemon — the child SIGTERMs itself on EOF. So none of the rows
below are "scoped" to anything in the sense the containable faults are;
what they have in common is that no answer can be given and no next
request can be trusted, so a clean shutdown is the best outcome available.
Where the text below says a fault is *channel-scoped*, it means only that
the fault is a property of the socket rather than of the request — not
that the blast radius is smaller than the whole daemon. It never is.

| Fault | Why it stays fatal |
| --- | --- |
| `privsep_recv()` failure (EOF, `ECONNRESET`, short/corrupt framing) | The socket itself is gone or the stream boundary is lost. Nothing to answer, nothing to resynchronise on. |
| `racoon_malloc()` failure for the reply buffer itself | With no reply buffer there is no way to answer at all, and the client blocks in `privsep_recv()` forever. A hang is strictly worse than an exit. |
| `send_fd()` failure (`PRIVSEP_SOCKET`) | The client is already blocked in `rec_fd()` with nothing coming. |
| `rec_fd()` failure (`BIND`, `SETSOCKOPTS`) | The descriptor the client sent is unaccounted for; stream position is no longer known. |
| `privsep_send()` failure | The reply could not be delivered; same blocked-client argument. |
| Mid-request wait timeout (§2.3.1) | Same "stream position is no longer known" rule as the `rec_fd()` row, reached by silence instead of by error. |

#### 2.3.1 Bounding the mid-request waits

§1's third rule was initially applied only to the cases where a *failed*
call left the client blocked. It missed the mirror image, which is the
more dangerous one: a client that does not fail but simply **stops
talking**.

Three waits in the dispatch loop were unbounded:

* `rec_fd()` for `PRIVSEP_BIND` / `PRIVSEP_SETSOCKOPTS` — reading the
  descriptor the client's command announced. A child that sends the
  command and never the descriptor blocks here forever. No EOF, no error,
  no timeout: the socket is simply idle and the peer is still alive, so
  none of the fatal rows above ever fire.
* `send_fd()` for `PRIVSEP_SOCKET`, and `privsep_send()` for every reply —
  a child that queues requests and never drains the replies fills the
  socket buffer and blocks the send.

The consequence is worse than any exit in this report, and it is exactly
the failure mode that third rule exists to prevent: no certificate loads,
no PSK lookups, no hooks, **for every peer**, with the daemon still
apparently alive and its process still running, until an operator notices
and restarts it by hand.

`privsep_wait_io()` now bounds all three, polling for readability or
writability in 50 ms slices up to `PRIVSEP_IPC_WAIT_MAX_MS` (3 s). The
bound matches `script_exec()`'s existing `SCRIPT_DOWN_WAIT_MAX_MS` and its
reasoning: far above anything the real exchange needs — the client's
`send_fd()` is the statement immediately after its `privsep_send()`, with
nothing that can block in between — and far below systemd's default 90 s
`TimeoutStopSec`. Slice-polling also makes the wait EINTR-safe without a
clock. It uses `poll()` rather than `select()` deliberately: privsep_sock's
descriptor number is not ours to bound, and an `fd_set` overrun here would
be the exact failure mode §3.1 was fixed for.

**Why a timeout still ends the process rather than failing just that
request.** This is the one place in this audit where the containment rule
is deliberately not applied, and it is worth being explicit that it is a
framing constraint, not a severity judgement. Nothing has been read when
the wait expires, so the stream is left at an offset only the client knows.
Resuming the loop would meet the announced descriptor message — one data
byte plus ancillary data — whenever it eventually lands, and read it as the
head of the next command: a garbled `admin_com` whose attacker-chosen
`ac_len` then drives the next allocation and the next blocking read. That
re-creates the very unbounded block the wait exists to remove, one
iteration later and considerably harder to diagnose. `rec_fd()` failure is
already fatal for exactly this reason; a timeout is only how that failure
looks when the peer goes silent instead of loud.

What the bound buys is therefore not survival of the request but the
difference between two failure modes: an unbounded, silent, unrecoverable
hang becomes a prompt, logged exit that the child's `privsep_do_exit()`
turns into an ordinary SIGTERM shutdown. The reply is still sent first,
best effort, so a merely-broken client gets `ETIMEDOUT` named in its own
log (`privsep_handshake_failed()`).

#### 2.3.2 Exit status: telling a fault from a shutdown

Writing §2.3.1 exposed a smaller problem that made "an exit a service
manager can act on" untrue as written. *Every* path out of the dispatch
loop — clean EOF and every fault alike — shared one `out:` label ending in
`_exit(0)`. A privileged process that had just lost its IPC, failed to
allocate a reply, or timed out mid-handshake reported the same success
status as one whose child had finished and gone away. Under the shipped
unit's `Restart=on-failure` that is precisely the difference between
coming back and staying down, and it always resolved the wrong way.

Split in two. `privsep_recv()` now returns 1 rather than -1 for "the peer
closed" (EOF or `ECONNRESET`), which every caller's `!= 0` test already
handles, so the loop can distinguish the two cases: `out:`/`_exit(0)` is
now reached only by the child closing its end, and every fault goes to
`fail:`/`_exit(1)` with its own log line.

One packaging caveat this does **not** fix, flagged rather than changed
because it is a deliberate-looking choice in the unit rather than a bug in
this code: `systemd/racoon.service.in` uses `ExecStart=-@RACOON_SBINDIR@/racoon`,
and the `-` prefix tells systemd to treat any exit status as success. With
it, `Restart=on-failure` will not restart a faulted daemon no matter what
status this code exits with. Dropping the `-`, or moving to
`Restart=always`, is what would make the new status actually reach the
service manager — a packaging decision, noted here for whoever owns it.

Removing the exit entirely would mean removing the two-message exchange —
carrying the descriptor on the command message itself, so there is no
second message to wait for. That is a real option and probably the right
end state, but it needs `privsep_recv()` restructured away from its
`MSG_PEEK` header read (peeking `SCM_RIGHTS` installs the descriptor on
Linux, once per peek), which is a protocol change of a different size than
this audit. Noted as a follow-up, not attempted here.

### 2.4 Rejections that used to report success

Independent of the exit paths, several refusals `break`'d out of the switch
with `ac_errno` left at 0 — an all-clear reply for an operation that never
happened. Fixed as part of making containment meaningful:

* every `safety_check()` rejection (11 commands),
* `port_check()` rejections (4 sites) → `ERANGE`,
* `isakmp_cfg_resize_pool()` failures (3 sites) → `ENOMEM`,
* `PRIVSEP_SCRIPT_EXEC`'s "unsafe script" refusal → `EPERM`. The
  unprivileged side's `script_hook()` log line is the only place this
  shows up in the child's log, and it never fired.

### 2.4.1 Found by live testing: PF_KEY refused under privsep

The first live `racoonctl vd` on a privsep host (Phase 1 of
`privsep-verification-runbook.md`) turned up a **pre-existing** bug that
this audit's containment work changed the symptom of, and that is worth
recording precisely because of how it presented.

`pfkey_dump_sadb()` (pfkey.c) opens a PF_KEY socket of its own via
`privsep_socket()`. `PRIVSEP_SOCKET`'s policy gate allowed `PF_INET` and
`PF_INET6` only, so it refused. The gate and the call site have coexisted
unchanged since the project's import.

What that costs is not one obscure command. `pfkey_dump_sadb()` is reached
from `racoonctl vd` and `racoonctl show-sa esp|ah|ipsec`, and from
`purge_remote()`'s fallback path (isakmp_inf.c) — which is also how DPD
expiry and peer-initiated teardown reach the SADB.

* **Before this audit:** the refusal did `goto out` → `_exit(0)`, so *any*
  of those took the whole daemon down. On a privsep host, `racoonctl vd`
  could not do anything else.
* **After §2.1, before this fix:** the refusal was contained. The daemon
  survived and logged `privsep_socket: unauthorized domain (15)` — `AF_KEY`
  — and `libipsec failed pfkey open`, and `vd` simply did not flush.
* **Now:** `privsep_socket_allowed()` admits PF_KEY in exactly libipsec
  `pfkey_open()`'s shape (`SOCK_RAW`/`PF_KEY_V2`) and no other.

Allowing it grants the unprivileged process nothing it does not already
hold: `pfkey_init()` (session.c) opens `lcconf->sock_pfkey` while still
root, well before `privsep_init()` forks, and the child inherits that
descriptor for its whole life.

Two things are worth drawing out of this. First, it is a live reproduction
of exactly the class #105 is about — a single request's policy refusal
ending the entire daemon — found by the containment fix turning a silent
death into a legible error message. Second, it is a reminder of what the
`_exit()` was costing: the same wrong decision has been in this gate the
whole time, and the exit is what made it undiagnosable.

The gate is now a separate predicate, `privsep_socket_allowed()`, covered
by `test/test_privsep_socket_policy.c` — see §5. Writing that test also
surfaced a second, unrelated looseness: the INET families are admitted for
*any* type and protocol, so a compromised child can request a raw socket
it would need `CAP_NET_RAW` to open itself. Every caller in the tree asks
for `SOCK_DGRAM`/0, so narrowing it would cost nothing — but that is a
privilege change unrelated to this bug, so §7 records it rather than this
commit making it.

One further observation from the same reading, recorded rather than fixed:
`PRIVSEP_BUFLEN_MAX` (privsep.h, 4096) is defined and referenced nowhere
in the tree. It implies a per-buffer cap that does not exist. Worth either
enforcing or deleting, so that nobody later reads it as a guarantee — the
mode-config values that reach `PRIVSEP_SCRIPT_EXEC` (joined split-include
and split-DNS lists) are the ones that could plausibly approach it.

### 2.4.2 Found by live testing: privsep never escalated setsockopt on Linux

The second live finding, from the same Phase 1 run once `racoonctl vd`
worked. Also **pre-existing**, also not an exit path — but it is the same
"silently succeeds" failure §1's first rule is about, and it had kept a
real defect quiet for as long as the code has existed.

The log showed, repeatedly, next to sockets that then carried on normally:

```
ERROR: privsep_setsockopt (Operation not permitted)
INFO:  fe80::...%racoon0[500] used as isakmp port (fd=17)
```

Two defects, one hiding the other:

1. **The escalation condition tested `EACCES` alone.** That is what the
   KAME stack returns for `IP_IPSEC_POLICY` on an unprivileged socket;
   Linux's xfrm returns `EPERM`. So on Linux the privileged process was
   *never asked* — meaning `setsockopt_bypass()`'s "in bypass"/"out bypass"
   policies (sockmisc.c) have never been applied to racoon's own sockets
   under privsep on this platform.

2. **`if ((err = setsockopt(...) == 0) || …)`** assigns the *comparison*,
   not the call's result. `err` was 1 on success and 0 on failure, and
   every caller tests `< 0` — so every failure this function did not
   escalate was handed back as success. That is why defect 1 produced only
   a stray log line rather than a visible malfunction:
   `setsockopt_bypass()` was told it had worked.

Both fixed: `EPERM` now counts as a privilege refusal alongside `EACCES`,
and `err` holds what `setsockopt()` actually returned.

**This changes behaviour beyond the log noise, deliberately.** With the
return value corrected, a bypass `setsockopt()` that genuinely fails now
propagates: `setsockopt_bypass()` returns -1 and `isakmp_open()` takes its
`goto err` — refusing to open that socket rather than opening one without
the bypass policy. That is what the surrounding code was always written to
do; the precedence bug is what stopped it. On a host where the privileged
process can set the policy (root, `CONFIG_XFRM`), the escalation now
succeeds and nothing is refused. On one where even root cannot, sockets
that used to open silently unprotected will now fail to open — loudly,
which is the right way round, but worth knowing before it is seen.

Worth noting what this means for the audit's own subject: the escalation
path for `PRIVSEP_SETSOCKOPTS` — the descriptor-first reordering of §2.2,
the bounded wait of §2.3.1 — had, on Linux, never executed at all before
this fix. It does now.

### 2.5 Note on the privsep threat model

The privileged process treats messages from the unprivileged one as
untrusted. Refusing an unauthorized operation is what that requires;
*exiting* was never part of it, and refusing is strictly more informative.
Nothing in §2.1–§2.2 grants the child an operation it could not already
request, and every refusal now names itself in the log.

The one thing containment did have to be checked against is the hang in
§2.3.1, and an earlier draft of this report got it wrong. It argued that a
child claiming `PRIVSEP_BIND` and sending no descriptor was harmless
because "if it exits, the socketpair EOFs and the privileged process takes
its channel-scoped exit". That reasoning only covers the child that
*exits*. A child that stays alive and goes silent produces no EOF and no
error — the socket is simply idle — so the privileged process blocked in
`rec_fd()` indefinitely. And since there is one privileged process serving
one child, not one per connection, that is not a stalled connection among
many but the end of privileged service for every peer, silently, until a
human intervenes. That is precisely the "a hang is worse than an exit"
case §2.3 invokes to justify its own fatal rows; it was simply not
recognised as an instance of it. §2.3.1 is the fix, and the wait is now
bounded on both the read and the write side.

Two things remain true after that fix. A compromised child can still end
the daemon trivially — by exiting, which is not a capability containment
ever took away. And it can still trip the bounded wait deliberately; the
result is now a 3-second delay and a clean, logged, restartable shutdown
rather than an indefinite one.

---

## 3. Other containable paths found and fixed

### 3.1 `session.c` — `monitor_fd()` / `unmonitor_fd()` (`exit(1)`)

Both exited when handed a descriptor outside the `fd_set` range. That
descriptor is not a fixed daemon-wide resource: besides the
pfkey/routing/admin-listener sockets opened once at startup, `monitor_fd()`
is called for **every accepted admin connection that asks for events**
(`evt_subscribe()`, `evt.c`) and for **every ISAKMP socket opened for an
address that appears while running** (`isakmp_open()`, `isakmp.c`, driven by
routing-socket/netlink updates). Whether such a descriptor lands past
`FD_SETSIZE` depends only on how many descriptors the process happens to
hold at that moment — so "this one `racoonctl` connection cannot be
watched" meant "every live SA dies".

`monitor_fd()` now returns 0/-1 (prototype in `session.h` changed to
match); `unmonitor_fd()` logs and returns, since nothing was ever
registered for such a descriptor. Callers:

| Caller | On failure |
| --- | --- |
| `evt_subscribe()` (`evt.c`) — per admin connection | Undo the listener registration, return `EMFILE`; `admin_process()`/`admin_handler()` close that one connection, as with any non-`-2` return |
| `isakmp_open()` (`isakmp.c`) — per address, at runtime | `goto err` — closes the socket, fails just that address, exactly like the `bind`/`setsockopt` failures above it |
| `admin_init()`, `pfkey_init()`, `myaddr_init()`, `privsep_init()` — startup | Close the socket and return -1; the caller in `session()` still treats it as fatal, which at startup it is |

### 3.2 `sockmisc.c` — `mask_sockaddr()` (`exit(1)` ×2)

Exited on an unsupported address family or a prefix length longer than the
family's addresses. Its callers are *matching* functions —
`cmpspidxwild()` (`policy.c`, per policy lookup, over addresses arriving in
PF_KEY messages) and `naddr_score()` (per negotiation, over configured
`netaddr`s). A comparison that cannot be made is one failed match, which
both callers already have a way to express. Now returns 0/-1 (prototype in
`sockmisc.h`); all five call sites treat a failure as "does not match".

### 3.3 `policy.c` — `cmpspidxwild()` destination check (`exit(1)`)

The `#ifndef __linux__` sanity check on `dst.ss_len` exited, while the
*identical* check on `src.ss_len` twenty lines above already returned 1
("no match"). Made consistent with its own sibling, and given the same
diagnostic detail.

### 3.4 `isakmp_xauth.c` — `PAM_conv()` (`exit(1)` ×2)

A `strdup()` failure while building a PAM response ended the process. This
is the PAM conversation callback for one XAuth login, and under privsep it
runs *in the privileged process* (`PRIVSEP_XAUTH_LOGIN_PAM`) — so one
client's login attempt could end the daemon for every peer. Now releases
the responses built so far (libpam only takes ownership on `PAM_SUCCESS`)
and returns `PAM_CONV_ERR`, which `xauth_login_pam()` and its caller
already handle — the same thing the function's own `default:` branch
already did.

### 3.5 `cfparse.y` — `cfparse()`'s "yyerrorcount but no error" (`exit(1)`)

Every other parse failure in this function returns -1, which `reload_conf()`
(`session.c`) handles by keeping the daemon running on the old
configuration. This one inconsistent branch exited instead, so a `SIGHUP`
reload hitting it dropped every live SA over a reload that could simply
have been refused. Now returns -1 like its siblings; at startup the callers
(`session()`, and `main.c`'s `-C` config test) still treat it as fatal.

---

## 4. Paths reviewed and deliberately left fatal

Full inventory of the remaining `exit()`/`_exit()`/`errx()` calls in the
daemon's own sources (`racoon_SOURCES` + `EXTRA_racoon_SOURCES`):

### 4.1 Startup and shutdown — correct as they are

`main.c` (usage, `-C` config test, `must be root`, `daemon()` failure),
`session.c`'s `errx()` block (`pfkey_init`, `isakmp_init`,
`isakmp_cfg_init`, `cfparse`, `admin_init`, `myaddr_init`, radius/ldap
init), `session.c`'s pid-file and `privsep_init()` failures,
`init_signal()`, `localconf.c`'s `initlcconf()`, `plog.c`'s `ploginit()`,
`crypto_openssl.c`'s `eay_init()`, `vendorid.c`'s `compute_vendorids()`
(called only from `main()`). All run before the daemon serves anything;
failing loudly is the right behaviour. `session.c`'s `close_session()`
`exit(0)` is the intended shutdown.

### 4.2 The contrast case named in the issue

`isakmp.c`'s `script_exec()` child branch `_exit(1)`s after a failed
`execve()`. Correct and required: it is inside the forked child, not the
parent event loop. Unchanged.

### 4.3 Test-only `main()`s

`logger.c`, `schedule.c`, `backupsa.c` and `getcertsbyname.c` each carry a
standalone `main()` behind `#ifdef`, never compiled into the daemon. Out of
scope.

### 4.4 Config-tree duplication OOM — containable in principle, not fixed here

`remoteconf.c`'s `duprmconf_finish()` (2 sites) and `cfparse.y`'s
`dupspspec_list()` exit on `racoon_malloc()`/`dupspspec()` failure while
deep-copying a `remoteconf`. These are reachable at runtime through a
`SIGHUP` reload, not only at startup.

Left as-is deliberately, and this is the one place where the report
recommends further work rather than delivering it. Both are `void`
functions several levels inside a duplication chain (`duprmconf()` →
`duprmconf_finish()` → `dupspspec_list()` → `dupspspec()`), invoked from
yacc actions; propagating a failure means changing that whole chain's
signatures and giving `cfparse()`'s grammar actions a way to abort a
half-built tree. Unlike everything fixed above, the state at the point of
failure genuinely *is* half-rebuilt, which is the "corrupted shared state"
case issue #105 explicitly allows. `reload_conf()` already documents itself
as `XXX possible mem leaks and no way to go back`; this belongs with that
work, not ahead of it.

### 4.5 `STRDUP_FATAL` — a distinct sub-class, not fixed here

`misc.h`'s `STRDUP_FATAL(x)` macro is `if (x == NULL) { plog(...); exit(1); }`,
used at ~30 sites in daemon runtime code (`isakmp.c` ×16, `remoteconf.c`
×10, `admin.c` ×4, `isakmp_inf.c` ×2). Almost all follow one idiom:

```c
a = racoon_strdup(saddr2str(iph1->local));
STRDUP_FATAL(a);
plog(LLV_INFO, LOCATION, NULL, "... %s ...", a, ...);
racoon_free(a);
```

— a ~46-byte copy made only because `saddr2str()` returns a rotating static
buffer and the log line needs two addresses at once. So a transient
allocation failure *while formatting a diagnostic* ends the daemon. That is
the least defensible reason in this whole audit for a process to exit, and
it is per-packet code.

It is nonetheless left alone, for reasons worth stating rather than
hiding:

* The trigger is genuine allocation failure of a few dozen bytes, not
  anything a peer or an operator can provoke on its own — unlike the
  privsep and `monitor_fd()` cases, which ordinary operational conditions
  reach.
* There is no single-point fix. Making the macro non-fatal leaves the
  variable `NULL` and hands it to `%s`: glibc and the BSD libcs print
  `(null)`, musl does not — a crash traded for a crash, in code that is
  by definition rarely exercised. Every one of the ~30 sites would have to
  be edited to guard its own `plog()` arguments, in per-packet paths, for a
  failure mode that only occurs when the process is already out of memory.
* The real fix is upstream of the macro: give `saddr2str()` callers a
  caller-supplied buffer so the `strdup()` disappears. That removes the
  exits *and* ~30 allocations per busy negotiation.

Recommended as its own follow-up issue, scoped to the `saddr2str()`
buffer idiom rather than to the macro.

---

## 5. Tests

Four new regression tests, following this project's established
wrapped-static-function pattern (see `test/README.md` and
`test_prune_stale_monitored_fds.c`), plus the existing suite:

* **`test/test_monitor_fd_range.c`** — `monitor_fd()` refuses an
  out-of-range or negative descriptor by *returning* -1, `unmonitor_fd()`
  tolerates one, and an already-monitored descriptor is unaffected by
  either. A regression that restores the `exit(1)` kills the test binary,
  which the harness records as a failure.
* **`test/test_privsep_fd_passing.c`** — over a real `socketpair()` with
  real `SCM_RIGHTS` messages: a real descriptor still round-trips and is
  usable; `send_fd(-1)` is received as -1 rather than dereferencing
  `CMSG_DATA(NULL)`; and the reply following a no-descriptor message is
  still the next thing read, which is what makes answering-instead-of-
  exiting legal for `PRIVSEP_SOCKET`. Three further cases drive
  `privsep_wait_io()` (§2.3.1) against a real silent peer: it returns
  promptly when the peer has spoken, gives up within its budget when the
  peer sends nothing, and works in the reply-send direction too. Note the
  failure signature of a regression here: an unbounded wait does not fail
  that test, it hangs the harness — which is the production symptom.
* **`test/test_privsep_setsockopt.c`** — `privsep_setsockopt()`'s return
  contract (§2.4.2): a failure must look like a failure. Verified against
  the pre-fix code, where both its cases fail. Needs no privsep host and
  behaves identically as root or not.
* **`test/test_privsep_socket_policy.c`** — the `PRIVSEP_SOCKET` policy
  gate (§2.4.1), asserted in both directions: the three sockets racoon
  legitimately asks for are admitted, PF_KEY only in `pfkey_open()`'s exact
  shape, and no other family at all. Written after a live `racoonctl vd`
  found the PF_KEY omission the hard way; the gate is now a separate
  predicate so that policy is checkable without a privsep host.

Full suite: **44/44 pass** (40 before, plus these four), release build,
`--enable-adminport --enable-hybrid --enable-natt --enable-frag`.
`privsep.c` and `isakmp_xauth.c` additionally syntax-checked with
`-DHAVE_LIBPAM` (`-Wall -Werror`), since the PAM cases are not compiled in
the default configuration.

### Live verification

The dispatch loop only runs inside `privsep_init()`'s privilege-dropping
`fork()`, so no test binary reaches it — the same constraint noted
throughout `daemon-issues.md` and in `test_privsep_sigterm_forward.c`.
`privsep-verification-runbook.md` drives it on a real host instead. Status
on a real Arch roadwarrior:

* **Phase 1 (happy path): pass**, after the two pre-existing bugs it found
  (§2.4.1, §2.4.2) were fixed. One connect/disconnect cycle covers a
  certificate load, a PF_KEY dump, socket/bind/setsockopt escalation and
  both hooks.
* **Phase 2 (handshake order): pass.** 10 commands, 10 body reads, 10
  replies — no drift. One descriptor message per request in each
  direction: 5 `recvmsg` for 4 `SETSOCKOPTS` + 1 `BIND`, 2 `sendmsg` for
  2 `SOCKET`. The passed descriptor number does not climb across requests,
  so none are leaked. `setsockopt(SOL_IPV6, IPV6_IPSEC_POLICY) = 0`
  executes in the privileged process — §2.4.2's fix working end to end,
  and the first time `PRIVSEP_SETSOCKOPTS`' escalation path (hence §2.2's
  reordering and §2.3.1's bounded wait) has run on Linux at all. A
  1392-byte `EAY_GET_PKCS1PRIVKEY` reply exercised §2.1's rewritten
  `racoon_realloc()` grow path. No timeouts, no desync.
* **Phase 3 (bounded wait): the timeout mechanism passes.** Freezing the
  child between its command and its descriptor produced, within the 3 s
  bound, exactly the three lines `privsep_wait_io()` /
  `privsep_handshake_failed()` / the `fail:` label emit, and the privileged
  process exited. The run also produced two effects worth recording,
  neither a code fault:
  * Every line appeared twice. `plogv()` (plog.c) writes to stdout when
    running in the foreground *and* to syslog, and the unit runs
    `racoon -F`, so systemd journals both copies. Pre-existing and
    cosmetic — but it matters here, because a doubled "terminating" line
    would otherwise read as `_exit(1)` failing to take effect.
  * systemd SIGKILLed the child after `TimeoutStopSec`. That is the gdb
    freeze, not the daemon: the privileged process is the unit's
    `MAINPID`, so its exit makes systemd SIGTERM the rest of the cgroup,
    and a ptrace-stopped child cannot act on that until gdb detaches. With
    a prompt detach the child takes its ordinary EOF →
    `privsep_do_exit()` → `close_session()` path. The runbook now uses a
    scripted `gdb -batch … detach` so the window does not depend on
    operator timing.
* **Phase 4 (containment under fault injection): 5a and 5b pass.**
  * *5a, refused hook:* the privileged side logged its refusal and the
    child logged `Script phase1_up execution failed` — §2.4's fix, which
    is what makes a refusal visible to the caller at all. Before it the
    reply carried `ac_errno == 0` and the hook silently did not run. The
    daemon carried on; a later `racoonctl vd` purged normally.
  * *5b, corrupted `ac_cmd`:* the privileged process logged
    `unexpected privsep command 48879` (`0xBEEF`) and answered `EINVAL`;
    the child failed **that negotiation only** (`failed to get private
    key` → `phase1 negotiation failed`). The daemon stayed up — proven
    independently by a `phase1-down` hook running after the fault, since
    under privsep only the privileged process can fork one. On `develop`
    that command reaches the `default:` case and `_exit()`s, taking the
    daemon and every live SA with it.
  * *5c: withdrawn as originally written.* It assumed a gateway pushing a
    large mode-config attribute set could fill `PRIVSEP_NBUF_MAX` and
    trigger `E2BIG`. It cannot: every list-shaped attribute is joined into
    a single `script_env_append()` value (so a peer lengthens entries, never
    adds them), the env count is fixed-shape at 21, and
    `PRIVSEP_SCRIPT_EXEC_MAX_ENVC_FITS_WIRE_BUDGET` (isakmp.c) asserts
    `3 + 21 <= 24` at compile time. `privsep_script_exec()`'s own
    client-side guard would also refuse before anything reached the wire.
    So the `E2BIG` row in §2.1 guards a corrupted or hostile message —
    5b's territory — not a configuration. The runbook now uses that config
    for what it is genuinely good for: the *ceiling* case, all 21 env vars
    and all 24 slots in use, which is exactly the boundary PR #94's extra
    entry once crossed.

### What could not be verified here
* **`policy.c`'s `#ifndef __linux__` branch**, which is not compiled on
  this project's primary platform. It is exercised by the NetBSD CI
  workflow; the change mirrors the sibling check immediately above it,
  including its types and format specifiers.

---

## 6. Files changed

| File | Change |
| --- | --- |
| `src/racoon/privsep.c` | Dispatch-loop containment; `send_fd(-1)`/`rec_fd()` no-descriptor handshake; descriptor-first ordering for `BIND`/`SETSOCKOPTS`; `privsep_socket()` client fix; errno on silent-success rejections; `privsep_wait_io()` bounding every mid-request wait (§2.3.1); three `ENABLE_UNITTEST` accessors |
| `src/racoon/session.c`, `session.h` | `monitor_fd()` returns 0/-1; `unmonitor_fd()` no longer exits |
| `src/racoon/evt.c` | `evt_subscribe()` drops just the connection when it cannot be watched |
| `src/racoon/isakmp.c` | `isakmp_open()` fails just that address |
| `src/racoon/admin.c`, `pfkey.c`, `grabmyaddr.c` | Startup callers check `monitor_fd()` and clean up |
| `src/racoon/sockmisc.c`, `sockmisc.h` | `mask_sockaddr()` returns 0/-1 |
| `src/racoon/policy.c` | `cmpspidxwild()` dst check returns "no match"; masking failures likewise |
| `src/racoon/isakmp_xauth.c` | `PAM_conv()` returns `PAM_CONV_ERR` instead of exiting |
| `src/racoon/cfparse.y` | `cfparse()` returns -1 instead of exiting on the `yyerrorcount` branch |
| `test/test_monitor_fd_range.c`, `test/test_privsep_fd_passing.c`, `test/test_privsep_socket_policy.c`, `test/test_privsep_setsockopt.c`, `test/Makefile.am` | New regression tests |

---

## 7. Follow-ups this audit recommends but does not deliver

In priority order, with the reason each is separate rather than folded in:

1. **Narrow the two privsep policy gates** (§2.4.1, §2.4.2). `PRIVSEP_SOCKET`
   admits the INET families for any type/protocol, though every caller asks
   for `SOCK_DGRAM`/0 — so a compromised child can obtain a raw socket it
   would need `CAP_NET_RAW` for. `PRIVSEP_SETSOCKOPTS` picks its expected
   option with `level == IPPROTO_IP ? IP_IPSEC_POLICY : IPV6_IPSEC_POLICY`,
   so any level that is neither is checked against the IPv6 constant rather
   than rejected. Both are a few lines, plus flipping two already-marked
   rows in `test_privsep_socket_policy.c`'s table. Held back only because
   tightening privileges mid-verification would muddy the signal from the
   runbook's phases.
2. **Carry the descriptor on the command message** (§2.3.1). Would remove
   the two-message exchange for `BIND`/`SETSOCKOPTS`/`SOCKET` outright, and
   with it the last place where a timeout has to end the process instead of
   just failing a request. Needs `privsep_recv()` restructured off its
   `MSG_PEEK` header read, since peeking `SCM_RIGHTS` installs the
   descriptor on Linux. A protocol change, not a hardening change.
3. **Remove the `saddr2str()` `strdup` idiom** (§4.5). Deletes ~30
   `STRDUP_FATAL` exits *and* ~30 allocations per busy negotiation. Should
   be scoped to the buffer idiom, not to the macro — changing the macro
   alone trades a controlled exit for an uncontrolled `%s`-of-`NULL`.
4. **Error propagation through the config-duplication chain** (§4.4).
   Belongs with `reload_conf()`'s own documented "no way to go back"
   problem rather than ahead of it.

None of these is a prerequisite for the fixes landed here; each is a
prerequisite for calling the corresponding sub-class closed.

[#102]: https://github.com/rdratlos/racoon-ipsec-tools/pull/102
[#105]: https://github.com/rdratlos/racoon-ipsec-tools/issues/105
