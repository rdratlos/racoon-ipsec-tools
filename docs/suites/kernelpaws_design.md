# Kernelpaws: Racoon Kernel Abstraction Layer Design

## 1. Objective

Design a kernel abstraction layer ("kernelpaws") for the Racoon IKEv1 daemon to
migrate from the legacy PF_KEYv2 (Key) API to the modern XFRM netlink API.
The design follows LibreSwan's dual-backend structural adapter pattern to
enable compile-time or runtime backend selection, keeping PF_KEYv2 support
as a fallback path.

**Scope**: IKEv1 only. IKEv2 out of scope.

## 1.1 Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Single-threaded** | Racoon is and will remain single-threaded. No mutexes, condvars, or threading primitives needed. All kernel I/O integrates into the existing `select()` loop via `monitor_fd()`. |
| **libipsec merged into daemon** | No external consumers of `libipsec`. Merging eliminates ABI burden, shared library dependency, and build complexity. Aligns with LibreSwan's approach of inlining PF_KEY code directly into the backend implementation. |
| **Compile-time backend selection** | Simpler than runtime switching. No in-flight request drainage logic. Configure flag `--enable-xfrm` selects backend. |
| **Flush + reinstall on reload** | XFRM policy dump returns all policies (including kernel defaults and other daemons'), making it impossible to isolate "our" policies. Racoon's internal `secpolicy` list persists across SIGHUP and is the authoritative source for reinstall. |
| **Kernel as SAD authority** | No userland SAD cache. The kernel is the authoritative record. Racoon tracks only what the IKE state machine needs: SA-to-QuickMode mapping, lifetime tracking, rekeying scheduling. Correlation uses (SPI, protocol, destination) tuple. |
| **GETSA deferred** | `XFRM_MSG_GETSA` is rarely needed for IKEv1. Defer to a follow-up for `setkey`-like debugging functionality. Critical path is SPI allocation → SA install → SA delete only. |

---

## 2. Reference Architecture

LibreSwan's `kernel_ops` pattern provides a struct of function pointers that
abstracts all kernel interactions. Two backends implement the same interface:
- `kernel_pfkeyv2.c` - legacy PF_KEYv2
- `kernel_xfrm.c`   - netlink XFRM

Racoon will adopt the same approach.

---

## 3. Racoon Architecture Overview (Current State)

### 3.1 Two-Layer Structure
```
+-------------------+         +-------------------+
|   racoon daemon   |         |   libipsec .so    |
|                   |         |                   |
|  src/racoon/      |  calls  |  src/libipsec/    |
|  pfkey.c          |  -----> |  pfkey.c          |
|  (pk_* wrappers)  |         |  (low-level send) |
+-------------------+         +-------------------+
         |
         v
   pfkey_handler()  --  monitor_fd()  --  select() loop in session.c
         |
         v
   Dispatch table: pkevent(), pksadone(), pkspdadd(), pkspdupdate(), ...
         |
         v
   State machine integration: ph2handle, isakmp_quick.c, session.c
```

### 3.2 Critical Data Structures
| Struct | File | Purpose |
|--------|------|---------|
| `ph2handle` | `handler.h:263` | Represents an established IPsec SA (Phase 2). Fields: `spid`, `seq`, `satype`, `ph1` back-pointer. |
| `secpolicy` | `policy.h:75` | SPD entry; linked-list of `ipsecrequest`. |
| `policyindex` | `policy.h:60` | SPD selectors (src/dst/protoport). |
| `secasindex` | `policy.h:95` | SA identifiers (spi/src/dst/proposal). |
| `sainfo_t` | `sainfo.c` | SA configuration from racoon.conf. |
| `struct pfkey_send_sa_args` | `libpfkey.h:70` | Arguments for `pfkey_send_add2`/`pfkey_send_update2`. |

### 3.3 Event Loop Integration
- `session.c:134` `monitor_fd()` registers a file descriptor with a callback.
- `session.c:177` main loop uses `select()` on all registered FDs.
- `session.c:322-336` dispatches active FDs to their callbacks in priority order.
- PF_KEY registers: `pfkey.c:493` `monitor_fd(lcconf->sock_pfkey, pfkey_handler, NULL, 0)`.
- **Note**: Racoon is strictly single-threaded. The blocking `recvmsg()` approach used by PF_KEY is safe and can be replicated for XFRM request/response correlation without condvars.

### 3.4 Sequence Number Correlation
- `pk_getseq()` increments a global counter.
- `getph2seq()` maps `(src, dst, doi, type)` tuple to a sequence number.
- Used to correlate async PF_KEY request/response pairs (e.g., GETSPI -> X_GETSPI DONE).
- **XFRM backend must provide equivalent correlation mechanism** (netlink sequence IDs or in-memory maps).

---

## 4. Target Architecture

```
+-------------------+
|   racoon daemon   |
|                   |
|  kernelpaws.h    |  <-- unified ops interface
|  kernelpaws_ops  |  <-- function pointer table
|                   |
|  +---------------+|
|  | kernelpaws   ||
|  | _pfkeyv2.c    ||  <-- merged PF_KEY code (was: libipsec + pfkey.c)
|  +---------------+|
|                   |
|  +---------------+|
|  | kernelpaws   ||  <-- native netlink XFRM implementation
|  | _xfrm.c       ||
|  +---------------+|
+-------------------+
         |
         v
   kernelpaws_init()  --  monitor_fd()  --  select() loop
         |
         v
   kernelpaws_handler() dispatches to backend-specific handlers
```

### 4.1 Backend Selection Mechanism
Compile-time selection via `configure.ac` macro. Both backends are compiled
into the binary; the linker resolves the symbol at build time.

```c
// kernelpaws.h
#ifdef USE_XFRM
extern const struct kernelpaws_ops *const kernelpaws_backend;
#else
extern const struct kernelpaws_ops *const kernelpaws_backend;
#endif
```

---

## 5. kernelpaws_ops Interface

### 5.1 Struct Definition (`src/racoon/kernelpaws.h`)

```c
// Optional: XFRM policy mark (for VRF, namespace isolation)
struct kernelpaws_mark {
    uint32_t value;
    uint32_t mask;
};

struct kernelpaws_ops {
    const char *name;

    // ===== Configuration =====
    int replay_window;            // Replay window size (default 32)
    int esn;                      // Extended Sequence Number (0/1)
    struct kernelpaws_mark mark;  // Policy mark (default 0/0 = no mark)

    // ===== Lifecycle =====
    int  (*init)(void);           // Open sockets, register protocols, monitor_fd()
    void (*shutdown)(void);       // Unmonitor fds, close sockets
    void (*reload)(void);         // Flush SPD/SAD, reinstall from internal state

    // ===== SA Lifecycle (SAD) =====
    int  (*send_add)(struct ph2handle *);      // Install new SA
    int  (*send_update)(struct ph2handle *);   // Update SA (lifetime/bytecount)
    int  (*send_delete)(struct ph2handle *);   // Delete SA
    int  (*send_getspi)(struct ph2handle *);   // Allocate SPI

    // ===== Policy Lifecycle (SPD) =====
    int  (*spd_add)(struct secpolicy *);       // Add policy entry
    int  (*spd_delete)(struct secpolicy *);    // Delete policy entry
    int  (*spd_update)(struct secpolicy *);    // Update policy entry
    void (*spd_flush)(void);                   // Flush all policies
    void (*spi_flush)(void);                   // Flush all SAs
    // Note: spd_dump removed — Racoon maintains its own secpolicy list
    // and flushes + reinstalls on reload. No kernel policy dump needed.

    // ===== Kernel-initiated Events =====
    int  (*send_eacquire)(struct secpolicy *); // Acknowledge acquire request

    // ===== Address Migration =====
    int  (*fixup_addresses)(struct ph2handle *);
};

extern const struct kernelpaws_ops *const kernelpaws_backend;
```

### 5.2 Abstraction Principle

All `pk_*` call sites replace `pk_foo()` with `kernelpaws_backend->foo()`.
The existing Racoon data structures (`ph2handle`, `secpolicy`, `policyindex`,
`secasindex`, `sainfo_t`) remain unchanged. The backend implementations are
responsible for translating these into PF_KEY or XFRM wire formats.

---

## 6. Per-Function Mapping

### 6.1 SA Operations

| Current PF_KEY Call | kernelpaws_ops | pfkeyv2 backend | xfrm backend |
|---------------------|-----------------|-----------------|--------------|
| `pk_sendgetspi()` | `send_getspi` | `pfkey_send_getspi2()` (sync wait for X_GETSPI response) | Send `XFRM_MSG_ALLOCSPI` netlink request on `NL_SEND_FD`; wait for response via `kernelpaws_xfrm_recv_response()` |
| `pk_sendadd()` | `send_add` | `pfkey_send_add2()` + `pfkey_send_update2()` (sync wait for DONE) | Send `XFRM_MSG_NEWSA` with `NLM_F_ACK`; wait for response on `NL_SEND_FD` |
| `pk_sendupdate()` | `send_update` | `pfkey_send_update2()` (sync wait for DONE) | Send `XFRM_MSG_UPDSA`; wait for response |
| `pk_senddelete()` | `send_delete` | `pfkey_send_delete()` | Send `XFRM_MSG_DELSA` |
| `pk_fixup_sa_addresses()` | `fixup_addresses` | `pfkey_send_update2()` with new addresses | Send `XFRM_MSG_UPDSA` with updated addresses. Note: XFRM does not have `XFRM_MSG_MIGRATE` for local address changes. Use `NETLINK_ROUTE` for local address change notifications (`RTM_NEWADDR`/`RTM_DELADDR`). |

### 6.2 Policy Operations

| Current PF_KEY Call | kernelpaws_ops | pfkeyv2 backend | xfrm backend |
|---------------------|-----------------|-----------------|--------------|
| `pk_sendspdadd2()` | `spd_add` | `pfkey_send_spdadd2()` | Send `XFRM_MSG_NEWPOLICY`; track kernel-assigned policy `index` in `secpolicy` |
| `pk_sendspddelete()` | `spd_delete` | `pfkey_send_spddelete()` | Send `XFRM_MSG_DELPOLICY` with kernel-assigned policy `index` |
| `pk_spdupdate()` | `spd_update` | `pfkey_send_spdupdate()` | Send `XFRM_MSG_NEWPOLICY` with kernel-assigned policy `index` |
| `pk_spdflush()` | `spd_flush` | `pfkey_send_flush(SADB_X_SPD_FLUSH)` | Send `XFRM_MSG_FLUSHPOLICY` |
| `pk_spiflush()` | `spi_flush` | `pfkey_send_flush(SADB_SATYPE_UNSPEC)` | Send `XFRM_MSG_FLUSHSAD`. Note: flushes ALL SAs, not just "our" ones. Same semantic as PF_KEY. |
| `pk_sendeacquire()` | `send_eacquire` | `pfkey_send_eacquire()` | Send `XFRM_MSG_NEWPOLICY` with `XFRM_POLICY_ADD` to install a "skip" policy, acknowledging the acquire. The XFRM backend must track the kernel-assigned policy `index` for subsequent `spd_delete`. |

### 6.3 Notification/Event Handling

| Current PF_KEY Notification | kernelpaws_ops callback | pfkeyv2 backend | xfrm backend |
|-----------------------------|--------------------------|-----------------|--------------|
| `SADB_X_EVENT_EXPIRE` | (handled in handler loop) | `pk_recvexpire()` | `XFRM_MSG_EXPIRE` netlink multicast |
| `SADB_X_GETSPI` (response) | (handled in handler loop) | `pksadone()` -> `pk_allocresolv()` | Correlated `XFRM_MSG_ALLOCSPI` response |
| `SADB_EXPIRE` | (handled in handler loop) | `pk_recvexpire()` | `XFRM_MSG_EXPIRE` |
| `SADB_X_SPDEVENT_EXPIRE` | (handled in handler loop) | `pk_spdeventexpire()` | `XFRM_MSG_POLEXPIRE` |
| `SADB_X_SPDDELETE` | (handled in handler loop) | `pk_spddelete()` | `XFRM_MSG_DELPOLICY` multicast |
| `SADB_X_ACQUIRE` | (handled in handler loop) | `pk_recvacquire()` | `XFRM_MSG_ACQUIRE` netlink multicast |
| `SADB_X_MIGRATE` | (handled in handler loop) | `pk_recvmigrate()` | `XFRM_MSG_MIGRATE` netlink multicast (peer changes only). Local address changes come from `NETLINK_ROUTE` (`RTM_NEWADDR`/`RTM_DELADDR`). |
| DONE responses | (handled in handler loop) | `pk_donemsg()` / `pksadone()` / `pkspdadd()` / `pkspdupdate()` | Correlated netlink responses |

---

## 7. File Structure

```
src/racoon/
  kernelpaws.h           - Unified ops interface + public API macros
  kernelpaws.c           - Backend selection, init/shutdown glue
  kernelpaws_pfkeyv2.c   - PF_KEYv2 backend (wraps existing libipsec)
  kernelpaws_xfrm.c      - XFRM netlink backend (new implementation)
  kernelpaws_addr.c      - Address conversion utilities (shared by both backends)
```

### 7.1 File Responsibilities

| File | Responsibility |
|------|----------------|
| `kernelpaws.h` | `struct kernelpaws_ops` definition, `kernelpaws_init()`, `kernelpaws_shutdown()`, `kernelpaws_handler()` public API. Correlation ID types. |
| `kernelpaws.c` | Selects backend at init time based on compile config. Provides `kernelpaws_handler()` dispatcher that routes to backend-specific handlers. |
| `kernelpaws_pfkeyv2.c` | Implements `kernelpaws_ops` using PF_KEYv2. Contains merged code from `libipsec` and `pfkey.c`. This is the "safe" migration path. |
| `kernelpaws_xfrm.c` | Implements `kernelpaws_ops` using raw netlink XFRM. Handles socket creation, message construction, async correlation, multicast subscriptions. |
| `kernelpaws_addr.c` | Converts `struct ph2handle` / `struct secpolicy` addresses to/from `struct xfrm_selector` / `struct xfrm_mark`. |

---

## 8. XFRM Backend Design Details

### 8.1 Socket Model
The XFRM backend requires **three netlink sockets**:

1. **`NL_SEND_FD`** — `NETLINK_XFRM` socket for sending unicast requests
   (`XFRM_MSG_NEWSA`, `XFRM_MSG_ALLOCSPI`, etc.) and receiving correlated
   responses. Not subscribed to any multicast group. This is the dedicated
   send-then-receive socket used by `kernelpaws_xfrm_recv_response()`.

2. **`NL_XFRM_FD`** — `NETLINK_XFRM` socket subscribed to `XFRMNLGRP_MEMBERSHIP`
   for multicast notifications (`XFRM_MSG_ACQUIRE`, `XFRM_MSG_EXPIRE`,
   `XFRM_MSG_POLEXPIRE`, `XFRM_MSG_MIGRATE`, `XFRM_MSG_DELPOLICY`,
   `XFRM_MSG_DELSA`).

3. **`NL_ROUTE_FD`** — `NETLINK_ROUTE` socket subscribed to `RTMGRP_IPV4_IFADDR`,
   `RTMGRP_IPV6_IFADDR` for local address change notifications
   (`RTM_NEWADDR`, `RTM_DELADDR`). Required because `XFRM_MSG_MIGRATE` only
   notifies about peer address changes, not local address changes.

All three sockets registered via `monitor_fd()` in `init()`. Note:
`RTMGRP_IPV4_ADDRCONF` (RFC 4861 IPv4 address configuration) is NOT needed.
Subscribe only to address change groups.

### 8.2 Request/Response Correlation (Single-Threaded)

PF_KEY uses `sadb_msg_seq` for correlation. XFRM netlink uses the standard
netlink sequence number (`nlmsg->nlmsg_seq`).

**No threading primitives needed.** Racoon is single-threaded. The entire
daemon runs in one thread driven by `select()`. The correlation mechanism uses
a dedicated unicast socket (`NL_SEND_FD`) for synchronous request/response:

- Each `send_*` operation assigns a unique sequence number and sends the
  netlink request on `NL_SEND_FD`.
- After sending, the caller invokes `kernelpaws_xfrm_recv_response(seq)` which
  enters a blocking `recvmsg()` loop on `NL_SEND_FD` until the matching
  response or error arrives. This is safe because Racoon is single-threaded —
  no other code can interfere.
- **Critical**: Must handle `NLMSG_ERROR` responses. A negative error value
  in the `NLMSG_ERROR` payload indicates failure (e.g., `-EEXIST`, `-EINVAL`).
- **Critical**: On Linux 3.6+ use `NETLINK_CAP_ACK` (or `NETLINK_EXT_ACK`)
  to receive acknowledgments for write-only messages. Without it, the kernel
  may not send any response on success, causing `kernelpaws_xfrm_recv_response()` to
  block indefinitely.

```c
struct xfrm_pending_req {
    uint32_t seq;                     // netlink sequence number
    uint16_t msg_type;                // expected response type
    int (*done)(struct ph2handle *, struct nlmsghdr *);  // completion callback
    struct ph2handle *target;         // associated ph2 handle (or NULL)
    int result;                       // completion status
};

#define XFRM_MAX_PENDING 32

static struct xfrm_pending_req pending[XFRM_MAX_PENDING];
static unsigned pending_count;
```

**Blocking behavior in `send_*` calls**: Operations like `send_getspi()` and
`send_add()` are inherently synchronous from the daemon's perspective — the
IKE state machine cannot proceed until the kernel confirms the SA/SPD install.
The `kernelpaws_xfrm_recv_response()` loop does a direct `recvmsg()` on the
`NL_SEND_FD` socket with a timeout (e.g., 5 seconds). This does NOT block the
main `select()` loop because it's a dedicated socket separate from the
multicast sockets, same thread — it's a send-then-receive handshake pattern,
not a long block.

**Alternative: fully async integration**: If blocking `recvmsg()` is
unacceptable, the XFRM handler can be re-entered manually:
```c
// In send_getspi():
xfrm_send_allocspi(p);
// Instead of blocking, pump the handler until done:
while (!p->spid_allocated) {
    kernelpaws_handler(NULL, lcconf->sock_xfrm);
}
```
This keeps everything within the existing event loop semantics without
introducing any threading.

The `send_*` operations (e.g., `send_getspi`, `send_add`) use this pattern:

```c
int kernelpaws_xfrm_recv_response(int sock, uint32_t pid, uint32_t seq,
                                   struct nlmsghdr **out)
{
    struct msghdr msg;
    struct iovec iov;
    char buf[8192];
    struct cmsghdr *cmsg;
    struct nlmsghdr *nh;
    struct sockaddr_nl addr;

    for (;;) {
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &addr;
        msg.msg_namelen = sizeof(addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        nh = recvmsg(sock, &msg, 0);
        if (!nh || NLMSG_DONE(nh))
            return -1;

        // Must be from kernel (pid == 0), matching our pid and seq
        if (addr.nl_pid != 0 || nh->nlmsg_pid != pid || nh->nlmsg_seq != seq)
            continue;  // not our response, skip

        // CRITICAL: Handle NLMSG_ERROR — contains the actual kernel error code
        if (nh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = NLMSG_DATA(nh);
            if (err->error == 0) {
                // Kernel returned success via NLMSG_ERROR (no CAP_ACK)
                // This is normal behavior when NETLINK_CAP_ACK is not set
                continue;
            }
            errno = -err->error;
            return -1;
        }

        *out = nh;
        return 0;
    }
}
```

**NLMSG_ERROR semantics**:
- If `err->error == 0`, the operation succeeded but the kernel chose to report
  success via `NLMSG_ERROR` instead of an echoed request. This happens when
  `NETLINK_CAP_ACK` (or `NLM_F_ACK`) is not set. The caller should treat
  `error == 0` as success.
- If `err->error < 0`, it contains a negated errno (e.g., `-EINVAL`,
  `-EEXIST`, `-ENOBUFS`). Map to `errno` and return failure.
- Without `NETLINK_CAP_ACK`, a successful operation may return **no response at
  all**, causing `recvmsg()` to block indefinitely. Mitigation: set `NLM_F_ACK`
  flag on all requests, or use `NETLINK_CAP_ACK` socket option (Linux 3.2+), or
  use a timeout on `recvmsg()`.

**Dedicated send socket**: The unicast send socket (`NL_SEND_FD`) is separate
from the multicast sockets (`NL_XFRM_FD`, `NL_ROUTE_FD`). This prevents
multicast notifications from interfering with request/response correlation.
The `kernelpaws_xfrm_recv_response()` function reads only from the send socket.

### 8.3 Multicast Event Subscription
The `NL_XFRM_FD` socket must subscribe to `XFRMNLGRP_MEMBERSHIP` (1) in
`init()` to receive `XFRM_MSG_EXPIRE`, `XFRM_MSG_POLEXPIRE`, `XFRM_MSG_DELPOLICY`,
`XFRM_MSG_ACQUIRE`, and `XFRM_MSG_MIGRATE` multicast notifications.

The `NL_SEND_FD` socket subscribes to no multicast group (`XFRMNLGRP_NONE` / 0),
receiving only unicast responses to sent requests.

### 8.4 Netlink Message Construction

Key netlink message types for XFRM:
```
XFRM_MSG_NEWSA / XFRM_MSG_UPDSA / XFRM_MSG_DELSA
XFRM_MSG_ALLOCSPI
XFRM_MSG_NEWPOLICY / XFRM_MSG_DELPOLICY
XFRM_MSG_GETPOLICY (for dump)
XFRM_MSG_GETSA (for dump)
```

NLAttr nesting follows standard libnl pattern. The XFRM backend should use
raw netlink sockets (no libnl dependency) to minimize external dependencies.

**32-bit alignment warning**: Some XFRM netlink structures have 32-bit aligned
64-bit fields. On architectures with strict alignment requirements (e.g.,
SPARC, S390x), direct struct access can cause data corruption. Always use
`memcpy` to access 64-bit fields from these structs. For example:

```c
struct xfrm_user_acquire *acq = NLMSG_DATA(nh);
uint64_t replay_seq;
memcpy(&replay_seq, &acq->replay_seq, sizeof(replay_seq));
```

This is especially critical for `xfrm_user_expire`, `xfrm_user_migrate`,
and `xfrm_userpolicy_id` families, which have 32-bit padding before 64-bit
fields.

### 8.5 Address Family Handling
Racoon currently supports AF_INET and AF_INET6. The XFRM backend must handle
both via appropriate `xfrm_selector` address lengths and `nladdr` attributes.

---

## 9. Migration from pfkey.c

### 9.1 Current pfkey.c Call Sites

```
src/racoon/isakmp_quick.c  -> pk_sendadd, pk_sendupdate, pk_sendgetspi
src/racoon/isakmp_agg.c    -> pk_sendadd
src/racoon/session.c       -> pfkey_init, pfkey_reload
src/racoon/pfkey.c         -> pk_sendspdadd2, pk_sendspddelete, pk_sendget,
                               pk_sendeacquire, pk_spdflush, pk_spiflush
                               (also: notification handlers internally)
src/racoon/backupsa.c      -> pk_fixup_sa_addresses
```

**Note on `pfkey_send_get()`**: This is `pk_sendget()` in pfkey.c, currently
used for querying SA state. The XFRM equivalent (`XFRM_MSG_GETSA`) is deferred
to a follow-up (see §11.2, resolved question 3).

### 9.2 Migration Steps

**Phase 0: Merge libipsec into racoon daemon**
1. Move `src/libipsec/` source files into `src/racoon/`.
2. Remove `src/libipsec/` from the build system.
3. Update include paths and symbol references.

**Phase 1: Abstraction Layer (No Behavioral Change)**
1. Create `kernelpaws.h`, `kernelpaws.c`, `kernelpaws_pfkeyv2.c`.
2. `kernelpaws_pfkeyv2` contains the PF_KEY logic (merged from libipsec + pfkey.c).
3. Replace `pk_*` calls with `kernelpaws_backend->*()` calls.
4. Verify IKEv1 SA establishment works identically.

**Phase 2: XFRM Backend**
1. Implement `kernelpaws_xfrm.c` with all `kernelpaws_ops`.
2. Start with `init()`/`shutdown()` and basic socket management.
3. Implement `send_getspi` -> `send_add` critical path end-to-end.
4. Implement policy operations.
5. Implement notification handlers (EXPIRE, ACQUIRE, MIGRATE).
6. Switch backend to XFRM via configure flag; test.

**Phase 3: Cleanup**
1. Optionally deprecate `kernelpaws_pfkeyv2.c`.
2. Remove dead code paths.
3. Update documentation.

### 9.3 Call Site Replacement Map

```c
// Before (isakmp_quick.c)
pk_sendadd(p);
pk_sendupdate(p);

// After
kernelpaws_backend->send_add(p);
kernelpaws_backend->send_update(p);

// Before (session.c)
pfkey_init();
pfkey_reload();

// After
kernelpaws_init();
kernelpaws_backend->reload();
```

---

## 10. Notification Handler Integration

### 10.1 Current PF_KEY Notification Flow
```
pfkey_handler() in pfkey.c:430
  -> pk_pfkey() reads/aligns/checks message
  -> dispatch switch on sadb_msg_type:
     SADB_X_GETSPI     -> pksadone()    -> pk_allocresolv()
     SADB_X_SPDADD     -> pkspdadd()
     SADB_X_SPDUPDATE  -> pkspdupdate()
     SADB_X_EVENT_EXPIRE -> pk_recvexpire()
     SADB_X_SPDEVENT_EXPIRE -> pk_spdeventexpire()
     SADB_X_SPDDELETE  -> pk_spddelete()
     SADB_X_ACQUIRE    -> pk_recvacquire() -> isakmp_request_acquire()
     SADB_X_MIGRATE    -> pk_recvmigrate() -> handle_remote_address_change()
     SADB_X_MESGTYPE_DONE -> pk_donemsg()
```

### 10.2 XFRM Notification Flow
```
kernelpaws_xfrm_handler() in kernelpaws_xfrm.c
  -> read netlink messages from xfrm socket
  -> dispatch switch on nlmsg_type:
      XFRM_MSG_EXPIRE     -> xfrm_recvexpire()     -> ph2handle expire logic
      XFRM_MSG_POLEXPIRE  -> xfrm_recvpolexpire()  -> policy expire logic
      XFRM_MSG_DELPOLICY  -> xfrm_recvdelpolicy()  -> policy delete logic
      XFRM_MSG_ACQUIRE    -> xfrm_recvacquire()    -> isakmp_request_acquire()
      XFRM_MSG_MIGRATE    -> xfrm_recvmigrate()    -> handle_remote_address_change()
      (correlated responses) -> completion callbacks for send_* operations
```

**CRITICAL: Alignment of `xfrm_user_acquire`**. The `xfrm_user_acquire` struct
in kernel headers has `id.daddr` (64-bit `sa_family_t` + `union xfrm_address_t`)
at 32-bit alignment. On strict architectures (SPARC, S390x), direct access
will cause bus errors or silent data corruption. **Must use `memcpy()`** to
read 64-bit fields from these structures. This applies to ALL `xfrm_user_*`
structs in netlink payloads. The `kernel_xfrm.c` code uses `memcpy` for all
64-bit fields from `xfrm_user_acquire`, and Racoon must follow the same pattern.

The XFRM backend handlers must invoke the same Racoon state machine functions
as the PF_KEY handlers, so the IKE state machines remain unchanged.

### 10.3 PF_KEY vs XFRM Notification Semantics

| Aspect | PF_KEY | XFRM |
|--------|--------|------|
| **EXPIRE** | Userland-timer driven. Racoon decides lifetime and sends EXPIRE. | Kernel-timer driven. Kernel sends `XFRM_MSG_EXPIRE` when hard lifetime is reached. |
| **EXPIRE timing** | Controlled by Racoon's `sainfo` lifetime values. | Controlled by kernel XFRM timers (added via `XFRMA_LTIME_*`). |
| **ACQUIRE selectors** | Full selector passed in PF_KEY message. | Kernel sends `xfrm_user_acquire` with `xfrm_selector` (may be partial). |
| **Policy type** | `SADB_X_SPDTYPE_IPSEC` is explicit. | `XFRM_POLICY_TYPE_MAIN` is the default; no explicit IPCOMP type. |
| **Address migration** | `SADB_X_MIGRATE` covers both peer and local address changes. | `XFRM_MSG_MIGRATE` is only for **peer** address changes. Local address changes require a separate `NETLINK_ROUTE` socket listening for `RTM_NEWADDR` / `RTM_DELADDR`. |
| **Multicast groups** | Single socket, single protocol. | `XFRMNLGRP_MEMBERSHIP` (1) for SA/SPD events. `RTMGRP_IPV4_IFADDR` / `RTMGRP_IPV6_IFADDR` for local address changes. |

**Implication for EXPIRE**: In the PF_KEY backend, Racoon's userland timers
drive SA expiration. In the XFRM backend, the kernel drives expiration. Racoon
must adapt its rekeying logic to react to kernel-initiated `XFRM_MSG_EXPIRE`
events rather than relying on its own userland timer.

---

## 11. Risks and Resolved Design Questions

### 11.1 Risks
| Risk | Mitigation |
|------|------------|
| PF_KEY synchronous semantics vs XFRM async netlink | Use blocking read on dedicated send socket (`NL_SEND_FD`) per-request. Same pattern as PF_KEY. |
| NLMSG_ERROR handling | Always check for `NLMSG_ERROR` in response. Use `NLM_F_ACK` or `NETLINK_CAP_ACK` to guarantee responses. |
| Multicast event ordering | XFRM multicast may have different ordering guarantees than PF_KEY. Add sequencing logic. |
| AF_INET6 support | XFRM netlink requires correct address length handling. Thorough testing required. |
| IPCOMP support | XFRM IPCOMP handling differs from PF_KEY. Verify transformation type mapping. Note: `XFRMA_ALG_COMP` is supported but kernel IPCOMP support has been deprecated since 5.x. |
| `xfrm_acq_expires` sysctl | If `net.ipv4.xfrm_acq_expires` is 0 (default on some kernels), old acquires never expire, causing memory leaks on long-running daemons. Racoon should either set this sysctl at startup or handle acquire expiration itself. |
| Alignment of 64-bit fields | `xfrm_user_acquire` has 32-bit aligned 64-bit fields. Direct access on strict architectures causes bus errors or silent corruption. Must use `memcpy()`. |
| Replay window complexity | XFRM replay state is more complex than PF_KEY. The kernel tracks the replay window, but Racoon must handle ESN enablement, replay window size configuration, and ESN negotiation in IKE. The kernelpaws interface should expose simple knobs (`replay_window` int, `esn` bool) and let the backend handle the XFRM-specific encoding. |
| Policy mark support | XFRM supports `mark` for policy selection (used with network namespaces, VRFs). Racoon currently has no mark concept. The `kernelpaws_ops` interface should include a `mark` field in the ops struct, defaulting to 0 for backward compatibility. |

### 11.2 Resolved Questions (from LibreSwan XFRM maintainer feedback)
1. **libipsec: replace entirely, not keep as backend.** Merging libipsec into
   the racoon daemon eliminates ABI burden, shared library dependency, and
   build complexity. The PF_KEY backend code becomes part of `kernelpaws_pfkeyv2.c`,
   not a wrapper around the separate `libipsec` library. Same approach as
   LibreSwan's `kernel_pfkeyv2.c`.

2. **`spd_dump`: do NOT use.** XFRM policy dump returns ALL policies,
   including kernel-generated defaults, policies from other daemons, and
   policies with no `XFRM_POLICY_LOCALOK` flag. It's impossible to isolate
   "our" policies. Instead, Racoon should maintain its own internal list of
   `secpolicy` entries and flush + reinstall from that list on reload.

3. **`pfkey_send_get()` / `XFRM_MSG_GETSA`: defer.** `GETSA` is rarely needed
   for IKEv1. Defer to a follow-up. For now, only implement what the critical
   path requires: SPI allocation → SA install → SA delete. If `GETSA` is needed
   later for `setkey`-like functionality, it can be added as a separate ops entry.

4. **`pfkey_promisc_toggle()`: no equivalent needed.** This is disabled (`#if 0`)
   in Racoon's pfkey.c. The XFRM multicast subscription serves the same purpose
   and is always active.

5. **Runtime vs compile-time backend selection.** Compile-time is simpler
   and sufficient. No in-flight request drainage logic needed. Configure flag
   `--enable-xfrm` selects backend at build time.

6. **XFRM state tracking.** No SAD cache is needed. The kernel is the
   authoritative record of SAs. Racoon tracks only what the IKE state machine
   needs: SA-to-QuickMode mapping, lifetime tracking, rekeying scheduling.
   For correlation: use (SPI, protocol, destination) tuple to identify which
   `ph2handle` a kernel event belongs to.

7. **Policy index management.** XFRM policies have a `index` field. The backend
   should track the kernel-assigned index when creating a policy (from the
   response to `XFRM_MSG_NEWPOLICY`) and store it alongside the `secpolicy`.
   This is needed for `XFRM_MSG_DELPOLICY` and `XFRM_MSG_NEWPOLICY` (update).

---

## 12. Build System Integration

### 12.1 configure.ac Changes
```autoconf
AC_ARG_ENABLE([xfrm],
  [AS_HELP_STRING([--enable-xfrm], [use XFRM netlink backend @<default=no>@])],
  [], [enable_xfrm=no])

AS_IF([test "x$enable_xfrm" = "xyes"],
  [AC_DEFINE([USE_XFRM], [1], [Use XFRM netlink backend])])

AC_SUBST([KERNELPAWS_SRCS],
  [kernelpaws.c kernelpaws_addr.c
    kernelpaws_pfkeyv2.c kernelpaws_xfrm.c])
```

### 12.2 Makefile.am Changes
```makefile
noinst_HEADERS += kernelpaws.h kernelpaws_addr.h

racoon_SOURCES += $(KERNELPAWS_SRCS)
```

**Remove libipsec from build**: After Phase 0, remove `src/libipsec/` from the
build entirely. The PF_KEY code becomes part of `kernelpaws_pfkeyv2.c`. No more
`libipsec` library, `.so`, or LD_LIBRARY_PATH dependency.

### 12.3 Backend Selection (`kernelpaws.c`)
```c
#ifdef USE_XFRM
const struct kernelpaws_ops *const kernelpaws_backend = &kernelpaws_xfrm_ops;
#else
const struct kernelpaws_ops *const kernelpaws_backend = &kernelpaws_pfkeyv2_ops;
#endif
```

---

## 13. Testing Strategy

1. **Unit tests**: Backend init/shutdown, address conversion, message construction.
2. **Integration tests**: IKEv1 main mode + quick mode SA establishment, policy install/delete.
3. **Regression tests**: Run existing Racoon test suite against both backends.
4. **Traffic tests**: Verify ESP/AH traffic flows correctly with XFRM backend.
5. **Lifecycle tests**: SA expiration, policy expiration, address migration.

---

## 14. Summary of Next Steps (Implementation Order)

1. Merge `src/libipsec/` into `src/racoon/` (Phase 0).
2. Create `kernelpaws.h` with `kernelpaws_ops` struct and public API.
3. Create `kernelpaws_pfkeyv2.c` containing merged PF_KEY code (Phase 1).
4. Refactor `pfkey.c` call sites to use `kernelpaws_backend->*`.
5. Verify PF_KEY backend works identically to current behavior.
6. Create `kernelpaws_xfrm.c` with init/shutdown and 3-socket management (Phase 2).
7. Implement `send_getspi` -> `send_add` critical path in XFRM backend.
8. Implement policy operations with index tracking in XFRM backend.
9. Implement notification handlers in XFRM backend.
10. Test XFRM backend end-to-end.
11. Clean up and document (Phase 3).

---

## 15. Additional XFRM Considerations (from LibreSwan Expert Review)

### 15.1 IPCOMP Support
- XFRM supports IPCOMP via `XFRMA_ALG_COMP` netlink attribute.
- Kernel IPCOMP support varies and has been deprecated since Linux 5.x.
- Racoon's `kernelpaws_xfrm.c` should attempt to install IPCOMP but handle
  kernel rejection gracefully (fall back to transport mode or error).
- At init time, probe kernel IPCOMP support by attempting a test SA install.

### 15.2 Replay Window and ESN
- XFRM replay state is more complex than PF_KEY: window size, ESN enablement,
  and bitmap tracking are all kernel-managed.
- The `kernelpaws_ops` interface should expose:
  - `replay_window` (int) — window size (default 32, as in PF_KEY)
  - `esn` (bool) — Extended Sequence Number enablement
- The XFRM backend handles the `XFRMA_REPLAY_ESN_VAL` attribute encoding.
- Racoon's IKE code only needs to know whether ESN is enabled for negotiation.

### 15.3 Policy Mark
- XFRM supports `mark` for policy selection (used with network namespaces, VRFs,
  traffic separation).
- Racoon currently has no `mark` concept in its configuration.
- The `kernelpaws_ops` interface should include a `mark` field:
  ```c
  struct kernelpaws_mark {
      uint32_t value;
      uint32_t mask;
  };
  ```

---