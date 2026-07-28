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

| Fault | Why it stays fatal |
| --- | --- |
| `privsep_recv()` failure (EOF, `ECONNRESET`, short/corrupt framing) | The socket itself is gone or the stream boundary is lost. Nothing to answer, nothing to resynchronise on. |
| `racoon_malloc()` failure for the reply buffer itself | With no reply buffer there is no way to answer at all, and the client blocks in `privsep_recv()` forever. A hang is strictly worse than an exit: exiting turns into the child's ordinary `SIGTERM` shutdown path. |
| `send_fd()` failure (`PRIVSEP_SOCKET`) | The client is already blocked in `rec_fd()` with nothing coming. |
| `rec_fd()` failure (`BIND`, `SETSOCKOPTS`) | The descriptor the client sent is unaccounted for; stream position is no longer known. |
| `privsep_send()` failure | The reply could not be delivered; same blocked-client argument. |

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

### 2.5 Note on the privsep threat model

The privileged process treats messages from the unprivileged one as
untrusted. Refusing an unauthorized operation is what that requires;
*exiting* was never part of it, and refusing is strictly more informative.
A compromised child can now make the privileged process block in `rec_fd()`
by claiming `PRIVSEP_BIND` and sending no descriptor — but a compromised
child can already end the daemon simply by exiting, and if it does, the
socketpair EOFs, `rec_fd()` returns -1 and the privileged process takes its
channel-scoped exit. No new capability, no stuck process.

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

Two new regression tests, following this project's established
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
  exiting legal for `PRIVSEP_SOCKET`.

Full suite: **42/42 pass** (40 before, plus these two), release build,
`--enable-adminport --enable-hybrid --enable-natt --enable-frag`.
`privsep.c` and `isakmp_xauth.c` additionally syntax-checked with
`-DHAVE_LIBPAM` (`-Wall -Werror`), since the PAM cases are not compiled in
the default configuration.

### What could not be verified here

* **`privsep_priv()`'s loop end to end.** It only runs inside
  `privsep_init()`'s privilege-dropping `fork()`, which needs a real
  PF_KEY/XFRM-capable kernel — the same constraint noted throughout
  `daemon-issues.md` and in `test_privsep_sigterm_forward.c`. The
  descriptor handshake the containment depends on is tested directly
  instead. A live run under `user`/`group` privsep config, exercising a
  certificate load, a PSK lookup and a phase1-up hook, is the recommended
  next step.
* **`policy.c`'s `#ifndef __linux__` branch**, which is not compiled on
  this project's primary platform. It is exercised by the NetBSD CI
  workflow; the change mirrors the sibling check immediately above it,
  including its types and format specifiers.

---

## 6. Files changed

| File | Change |
| --- | --- |
| `src/racoon/privsep.c` | Dispatch-loop containment; `send_fd(-1)`/`rec_fd()` no-descriptor handshake; descriptor-first ordering for `BIND`/`SETSOCKOPTS`; `privsep_socket()` client fix; errno on silent-success rejections; two `ENABLE_UNITTEST` accessors |
| `src/racoon/session.c`, `session.h` | `monitor_fd()` returns 0/-1; `unmonitor_fd()` no longer exits |
| `src/racoon/evt.c` | `evt_subscribe()` drops just the connection when it cannot be watched |
| `src/racoon/isakmp.c` | `isakmp_open()` fails just that address |
| `src/racoon/admin.c`, `pfkey.c`, `grabmyaddr.c` | Startup callers check `monitor_fd()` and clean up |
| `src/racoon/sockmisc.c`, `sockmisc.h` | `mask_sockaddr()` returns 0/-1 |
| `src/racoon/policy.c` | `cmpspidxwild()` dst check returns "no match"; masking failures likewise |
| `src/racoon/isakmp_xauth.c` | `PAM_conv()` returns `PAM_CONV_ERR` instead of exiting |
| `src/racoon/cfparse.y` | `cfparse()` returns -1 instead of exiting on the `yyerrorcount` branch |
| `test/test_monitor_fd_range.c`, `test/test_privsep_fd_passing.c`, `test/Makefile.am` | New regression tests |

[#102]: https://github.com/rdratlos/racoon-ipsec-tools/pull/102
[#105]: https://github.com/rdratlos/racoon-ipsec-tools/issues/105
