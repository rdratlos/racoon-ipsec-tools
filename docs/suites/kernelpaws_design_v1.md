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
| **Static library within daemon** | No external consumers. Shared library `.so` adds ABI burden, data ownership tension, and debugging complexity with no reuse benefit. Same model as existing `libipsec`. |
| **Compile-time backend selection** | Simpler than runtime switching. No in-flight request drainage logic. Configure flag `--enable-xfrm` selects backend. |

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
|  | _pfkeyv2.c    ||  <-- wraps existing libipsec PF_KEY calls
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
struct kernelpaws_ops {
    const char *name;

    // ===== Lifecycle =====
    int  (*init)(void);           // Open sockets, register protocols, monitor_fd()
    void (*shutdown)(void);       // Unmonitor fds, close sockets
    void (*reload)(void);         // Flush SPD/SAD, re-dump persistent policies

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
    int  (*spd_dump)(void);                    // Dump existing policies (for reload)

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
| `pk_sendgetspi()` | `send_getspi` | `pfkey_send_getspi2()` (sync wait for X_GETSPI response) | Send `XFRM_MSG_ALLOCSPI` netlink request; wait for response via seq correlation |
| `pk_sendadd()` | `send_add` | `pfkey_send_add2()` + `pfkey_send_update2()` (sync wait for DONE) | Send `XFRM_MSG_NEWSA`; wait for `XFRM_MSG_NEWSA` response |
| `pk_sendupdate()` | `send_update` | `pfkey_send_update2()` (sync wait for DONE) | Send `XFRM_MSG_UPDSA`; wait for response |
| `pk_senddelete()` | `send_delete` | `pfkey_send_delete()` | Send `XFRM_MSG_DELSA` |
| `pk_fixup_sa_addresses()` | `fixup_addresses` | `pfkey_send_update2()` with new addresses | Send `XFRM_MSG_UPDSA` with updated `if_id`/`mark` |

### 6.2 Policy Operations

| Current PF_KEY Call | kernelpaws_ops | pfkeyv2 backend | xfrm backend |
|---------------------|-----------------|-----------------|--------------|
| `pk_sendspdadd2()` | `spd_add` | `pfkey_send_spdadd2()` | Send `XFRM_MSG_NEWPOLICY` |
| `pk_sendspddelete()` | `spd_delete` | `pfkey_send_spddelete()` | Send `XFRM_MSG_DELPOLICY` |
| `pk_spdupdate()` | `spd_update` | `pfkey_send_spdupdate()` | Send `XFRM_MSG_NEWPOLICY` with existing index |
| `pk_spdflush()` | `spd_flush` | `pfkey_send_flush(SADB_X_SPD_FLUSH)` | Send `XFRM_MSG_FLUSHPOLICY` |
| `pk_spiflush()` | `spi_flush` | `pfkey_send_flush(SADB_SATYPE_UNSPEC)` | Send `XFRM_MSG_FLUSHSAD` |
| `pfkey_send_spddump()` | `spd_dump` | `pfkey_send_spddump()` + read loop | Send `XFRM_MSG_GETPOLICY` dump; read responses |
| `pk_sendeacquire()` | `send_eacquire` | `pfkey_send_eacquire()` | Send `XFRM_MSG_NEWPOLICY` with `XFRM_POLICY_ADD` (ack) |

### 6.3 Notification/Event Handling

| Current PF_KEY Notification | kernelpaws_ops callback | pfkeyv2 backend | xfrm backend |
|-----------------------------|--------------------------|-----------------|--------------|
| `SADB_X_EVENT_EXPIRE` | (handled in handler loop) | `pk_recvexpire()` | `XFRM_MSG_EXPIRE` netlink multicast |
| `SADB_X_GETSPI` (response) | (handled in handler loop) | `pksadone()` -> `pk_allocresolv()` | Correlated `XFRM_MSG_ALLOCSPI` response |
| `SADB_EXPIRE` | (handled in handler loop) | `pk_recvexpire()` | `XFRM_MSG_EXPIRE` |
| `SADB_X_SPDEVENT_EXPIRE` | (handled in handler loop) | `pk_spdeventexpire()` | `XFRM_MSG_POLEXPIRE` |
| `SADB_X_SPDDELETE` | (handled in handler loop) | `pk_spddelete()` | `XFRM_MSG_DELPOLICY` multicast |
| `SADB_X_ACQUIRE` | (handled in handler loop) | `pk_recvacquire()` | `XFRM_MSG_ACQUIRE` netlink multicast |
| `SADB_X_MIGRATE` | (handled in handler loop) | `pk_recvmigrate()` | `XFRM_MSG_MIGRATE` netlink multicast |
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
| `kernelpaws_pfkeyv2.c` | Implements `kernelpaws_ops` using existing `libipsec` PF_KEY calls. Reuses `pfkey.c` logic. This is the "safe" migration path. |
| `kernelpaws_xfrm.c` | Implements `kernelpaws_ops` using raw netlink XFRM. Handles socket creation, message construction, async correlation, multicast subscriptions. |
| `kernelpaws_addr.c` | Converts `struct ph2handle` / `struct secpolicy` addresses to/from `struct xfrm_selector` / `struct xfrm_mark`. |

---

## 8. XFRM Backend Design Details

### 8.1 Socket Model
The XFRM backend requires **two netlink sockets**:
1. `NETLINK_XFRM` - SA/SPD management (XFRM_MSG_*).
2. `NETLINK_ROUTE` - Address/route notifications (RTM_*).

Both sockets registered via `monitor_fd()` in `init()`.

### 8.2 Request/Response Correlation (Single-Threaded)
PF_KEY uses `sadb_msg_seq` for correlation. XFRM netlink uses the standard
netlink sequence number (`nlmsg->nlmsg_seq`).

**No threading primitives needed.** Racoon is single-threaded. The entire
daemon runs in one thread driven by `select()`. The correlation mechanism is
simpler than the multi-threaded case:

- Maintain a small fixed-size array of pending correlation entries (max ~32,
  corresponding to concurrent Phase 2 negotiations).
- Each `send_*` operation assigns a unique sequence number, creates a
  correlation entry, and sends the netlink request.
- After sending, the caller invokes `kernelpaws_xfrm_wait(seq)` which enters
  a tight `sendmsg()`/`recvmsg()` loop on the XFRM socket until the matching
  response arrives. This is safe because Racoon is single-threaded — no other
  code can interfere.
- The netlink read handler (for async multicast events) matches incoming
  responses to pending entries using a simple linear scan.

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
The `kernelpaws_xfrm_wait()` loop does a direct `recvmsg()` on the netlink
socket with a timeout (e.g., 5 seconds). This does NOT block the main
`select()` loop because it's the same socket, same thread — it's a
send-then-receive handshake pattern, not a long block.

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

### 8.3 Multicast Event Subscription
XFRM notifies userspace via multicast groups:
- `XFRMNLGRP_NONE` (0) - unicast responses only
- `XFRMNLGRP_MEMBERSHIP` (1) - SA/SPD events

The XFRM backend must subscribe to group 1 in `init()` to receive EXPIRE,
DELETE, ACQUIRE, MIGRATE notifications.

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

### 9.2 Migration Steps

**Phase 1: Abstraction Layer (No Behavioral Change)**
1. Create `kernelpaws.h`, `kernelpaws.c`, `kernelpaws_pfkeyv2.c`.
2. `kernelpaws_pfkeyv2` wraps existing `pfkey.c` logic (no code changes to callers).
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

The XFRM backend handlers must invoke the same Racoon state machine functions
as the PF_KEY handlers, so the IKE state machines remain unchanged.

---

## 11. Risks and Open Questions

### 11.1 Risks
| Risk | Mitigation |
|------|------------|
| PF_KEY synchronous semantics vs XFRM async netlink | Use blocking read per-request or condvar-based correlation. |
| Multicast event ordering | XFRM multicast may have different ordering guarantees than PF_KEY. Add sequencing logic. |
| libipsec dependency | The PF_KEY backend still depends on libipsec. For clean migration, consider inlining libipsec into racoon daemon. |
| AF_INET6 support | XFRM netlink requires correct address length handling. Thorough testing required. |
| IPCOMP support | XFRM IPCOMP handling differs from PF_KEY. Verify transformation type mapping. |
| `pfkey_reload()` dump/restore semantics | XFRM dump may not return all policies in same format. May need to maintain internal policy cache. |

### 11.2 Open Questions
1. **Should libipsec be merged into racoon daemon?** Currently libipsec is a
   shared library. The kernelpaws layer could either replace libipsec entirely
   or keep it for the PF_KEY backend. Recommendation: replace entirely.
2. **Runtime vs compile-time backend selection?** Compile-time is simpler.
   Runtime requires both backends compiled and loaded. Start with compile-time.
3. **Do we need XFRM state tracking?** PF_KEY relies on kernel state. XFRM
   may need additional tracking for policy index mapping.
4. **How to handle `pfkey_send_get()`?** Currently used for querying SA state.
   XFRM equivalent is `XFRM_MSG_GETSA`. Need to determine if this path is
   actively used.
5. **What about `pfkey_promisc_toggle()`?** Currently disabled (`#if 0`) in
   pfkey.c. XFRM doesn't have a direct equivalent; multicast subscription
   serves the same purpose.

---

## 12. Build System Integration

### 12.1 configure.ac Changes
```autoconf
AC_ARG_ENABLE([xfrm],
  [AS_HELP_STRING([--enable-xfrm], [use XFRM netlink backend @<default=no>@])],
  [], [enable_xfrm=no])

AS_IF([test "x$enable_xfrm" = "xyes"],
  [AC_DEFINE([USE_XFRM], [1], [Use XFRM netlink backend])])

AC_SUBST([THUNDERBIRD_SRCS],
  [kernelpaws.c kernelpaws_addr.c
   kernelpaws_pfkeyv2.c kernelpaws_xfrm.c])
```

### 12.2 Makefile.am Changes
```makefile
noinst_HEADERS += kernelpaws.h kernelpaws_addr.h

racoon_SOURCES += $(THUNDERBIRD_SRCS)
```

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

1. Create `kernelpaws.h` with `kernelpaws_ops` struct and public API.
2. Create `kernelpaws_pfkeyv2.c` wrapping existing PF_KEY logic.
3. Refactor `pfkey.c` call sites to use `kernelpaws_backend->*`.
4. Verify PF_KEY backend works identically to current behavior.
5. Create `kernelpaws_xfrm.c` with init/shutdown and socket management.
6. Implement `send_getspi` -> `send_add` critical path in XFRM backend.
7. Implement policy operations in XFRM backend.
8. Implement notification handlers in XFRM backend.
9. Test XFRM backend end-to-end.
10. Clean up and document.