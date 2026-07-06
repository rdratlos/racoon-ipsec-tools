# RFC 0002: Kernelpaws — XFRM Kernel Abstraction Layer for PF_KEYv2 Migration

## Status

Draft

## Authors

- Racoon IPsec Tools maintainers

## Reviewers

- @maintainer (decision)
- LibreSwan XFRM maintainer (external expert review incorporated)

## Motivation

The PF_KEYv2 (Key) API in the Linux kernel is deprecated and receiving minimal maintenance. Racoon currently depends exclusively on PF_KEYv2 for all kernel IPsec SA and SPD operations. As kernels phase out PF_KEYv2 support, Racoon will lose the ability to install and manage IPsec security associations on modern Linux systems.

This RFC defines "kernelpaws", a kernel abstraction layer that enables migration to the XFRM netlink API while preserving backward compatibility with PF_KEYv2. The design follows LibreSwan's proven dual-backend structural adapter pattern, enabling compile-time backend selection.

Without this migration, Racoon becomes unusable on Linux kernels that remove PF_KEYv2. The XFRM netlink API is the actively maintained, kernel-preferred interface for IPsec SA/SPD management.

## Goals

- Enable Racoon to install, update, delete, and query IPsec SAs and SPD policies via XFRM netlink on Linux.
- Preserve full backward compatibility with PF_KEYv2 as a compile-time alternative.
- Maintain behavioral equivalence: IKEv1 SA establishment, policy management, rekeying, and expiration must work identically under both backends.
- Eliminate the `libipsec` shared library dependency by merging its code into the daemon binary.
- Achieve zero memory errors under valgrind for the XFRM backend.
- Cover all XFRM backend functions with 77 tests (36 unit, 19 integration, 12 failure path, 10 notification) before Phase 2 is considered complete.

## Design Scope

Racoon is an extremely lightweight IPsec implementation — low footprint, fast build, minimal dependencies. The kernelpaws abstraction layer must preserve this characteristic. Design decisions that trade complexity for capabilities (coexistence, userland caches, selective deletion) are explicitly out of scope unless they are the only viable path.

Key consequence: Racoon assumes **exclusive ownership** of the host XFRM tables. Operations such as `spd_flush` and `spi_flush` use blanket `XFRM_MSG_FLUSHPOLICY` and `XFRM_MSG_FLUSHSA`, which affect all SAs and policies on the host — including those installed by other IPsec daemons. This is a deliberate choice to keep the implementation simple and lightweight. StrongSwan follows a different path: it tracks its own entries and performs selective `DELSA`/`DELPOLICY` to allow coexistence. Racoon does not.

Distributions packaging Racoon with the XFRM backend should enforce exclusive deployment (e.g., Debian `Breaks`/`Conflicts` against other XFRM-based IPsec daemons).

## Non-goals

- IKEv2 support — scope is IKEv1 only.
- Runtime backend switching — selection is compile-time via `--enable-xfrm`.
- `XFRM_MSG_GETSA` support — deferred to a follow-up; not needed for the IKEv1 critical path.
- Independent userland SAD cache — the kernel is the authoritative SAD; Racoon only tracks what the IKE state machine needs.
- Coexistence with other XFRM-based IPsec daemons — Racoon assumes exclusive ownership of host XFRM tables (see Design Scope).
- NetBSD/OpenBSD PF_KEY migration — this RFC targets Linux XFRM specifically. NetBSD retains PF_KEYv2.

## Current Design

Racoon has a two-layer structure for kernel communication:

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
```

Key characteristics:
- `pfkey.c` provides `pk_*` wrapper functions for SA and policy operations.
- `libipsec` is a shared library providing low-level PF_KEY message construction.
- Racoon is strictly single-threaded, driven by a `select()` loop in `session.c`.
- PF_KEY registers one socket via `monitor_fd()`. The `pfkey_handler()` dispatches async notifications (EXPIRE, ACQUIRE, MIGRATE, DONE responses) via a type-based switch.
- Request/response correlation uses `sadb_msg_seq` (per-request sequence numbers).
- Critical data structures: `ph2handle` (IPsec SA state), `secpolicy` (SPD entries), `policyindex` (selectors), `secasindex` (SA identifiers).

Call sites that use PF_KEY:
- `isakmp_quick.c` — `pk_sendadd`, `pk_sendupdate`, `pk_sendgetspi`
- `isakmp_agg.c` — `pk_sendadd`
- `session.c` — `pfkey_init`, `pfkey_reload`
- `pfkey.c` — `pk_sendspdadd2`, `pk_sendspddelete`, `pk_sendeacquire`, `pk_spdflush`, `pk_spiflush`
- `backupsa.c` — `pk_fixup_sa_addresses`

## Proposed Design

### Architecture

Replace the two-layer daemon + libipsec structure with a unified abstraction layer:

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
|  | kernelpaws   ||
|  | _xfrm.c       ||  <-- native netlink XFRM implementation
|  +---------------+|
+-------------------+
         |
         v
   kernelpaws_init()  --  monitor_fd()  --  select() loop
```

### Backend Selection

Compile-time selection via `configure.ac` flag `--enable-xfrm`. Both backends compile into the binary; the linker resolves the symbol at build time:

```c
#ifdef USE_XFRM
const struct kernelpaws_ops *const kernelpaws_backend = &kernelpaws_xfrm_ops;
#else
const struct kernelpaws_ops *const kernelpaws_backend = &kernelpaws_pfkeyv2_ops;
#endif
```

### kernelpaws_ops Interface

```c
struct kernelpaws_mark {
    uint32_t value;
    uint32_t mask;
};

struct kernelpaws_ops {
    const char *name;
    int replay_window;
    int esn;
    struct kernelpaws_mark mark;

    int  (*init)(void);
    void (*shutdown)(void);
    void (*reload)(void);

    int  (*send_add)(struct ph2handle *);
    int  (*send_update)(struct ph2handle *);
    int  (*send_delete)(struct ph2handle *);
    int  (*send_getspi)(struct ph2handle *);

    int  (*spd_add)(struct secpolicy *);
    int  (*spd_delete)(struct secpolicy *);
    int  (*spd_update)(struct secpolicy *);
    void (*spd_flush)(void);
    void (*spi_flush)(void);

    int  (*send_eacquire)(struct secpolicy *);
    int  (*fixup_addresses)(struct ph2handle *);
};

extern const struct kernelpaws_ops *const kernelpaws_backend;
```

All existing Racoon data structures (`ph2handle`, `secpolicy`, `policyindex`, `secasindex`, `sainfo_t`) remain unchanged. Backend implementations translate these into PF_KEY or XFRM wire formats.

### Per-Function Mapping

| kernelpaws_ops | pfkeyv2 backend | xfrm backend |
|----------------|-----------------|--------------|
| `send_getspi` | `pfkey_send_getspi2()` | `XFRM_MSG_ALLOCSPI` |
| `send_add` | `pfkey_send_add2()` | `XFRM_MSG_NEWSA` |
| `send_update` | `pfkey_send_update2()` | `XFRM_MSG_UPDSA` |
| `send_delete` | `pfkey_send_delete()` | `XFRM_MSG_DELSA` |
| `spd_add` | `pfkey_send_spdadd2()` | `XFRM_MSG_NEWPOLICY` |
| `spd_delete` | `pfkey_send_spddelete()` | `XFRM_MSG_DELPOLICY` |
| `spd_update` | `pfkey_send_spdupdate()` | `XFRM_MSG_NEWPOLICY` (with index) |
| `spd_flush` | `pfkey_send_flush(SADB_X_SPD_FLUSH)` | `XFRM_MSG_FLUSHPOLICY` (no payload, host-wide, see Design Scope) |
| `spi_flush` | `pfkey_send_flush(SADB_SATYPE_UNSPEC)` | `XFRM_MSG_FLUSHSA` per protocol (AH, ESP, COMP, host-wide, see Design Scope) |
| `send_eacquire` | `pfkey_send_eacquire()` | no direct XFRM equivalent — let larval acquire lapse via `xfrm_acq_expires`; optionally install short-lived `XFRM_POLICY_BLOCK` policy |
| `fixup_addresses` | `pfkey_send_update2()` | `XFRM_MSG_UPDSA` + `NETLINK_ROUTE` for local addr changes |

### XFRM Backend: 3-Socket Model

| Socket | Protocol | Multicast Groups | Purpose |
|--------|----------|-----------------|---------|
| `NL_SEND_FD` | `NETLINK_XFRM` | None | Dedicated send socket for unicast requests. Used exclusively for `sendmsg()` followed by blocking `recvmsg()` to obtain the correlated response. Does NOT join any multicast group; receives only ACK/error replies to own requests. |
| `NL_XFRM_FD` | `NETLINK_XFRM` | `setsockopt()` once per group: `XFRMNLGRP_EXPIRE`, `_ACQUIRE`, `_SA`, `_POLICY`, `_MIGRATE`, `_MAPPING` | Dedicated notification socket for XFRM multicast events (EXPIRE, POLEXPIRE, DELSA, DELPOLICY, ACQUIRE, MIGRATE, MAP). Used only for non-blocking `recvmsg()` in the `select()` loop. Never used for request/response. |
| `NL_ROUTE_FD` | `NETLINK_ROUTE` | `RTMGRP_IPV4_IFADDR \| RTMGRP_IPV6_IFADDR` | Dedicated notification socket for local address changes (`RTM_NEWADDR`, `RTM_DELADDR`). Triggers SA address fixup via `fixup_addresses()`. |

All three sockets register via `monitor_fd()` in `init()`. The `select()` loop monitors `NL_XFRM_FD` and `NL_ROUTE_FD`. `NL_SEND_FD` is only read synchronously within a `send_*` call.

**Multicast group subscription**: XFRM `XFRMNLGRP_*` values are 1-indexed group numbers (ACQUIRE=1, EXPIRE=2, SA=3, …, MAPPING=8), not bitmask flags. Subscribe via `setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &grp, sizeof(grp))` once per group. OR-ing the raw enum values into `sockaddr_nl.nl_groups` produces the wrong subscription (the legacy bitmask requires `1 << (grp - 1)`). This is distinct from the route socket where `RTMGRP_IPV4_IFADDR` and `RTMGRP_IPV6_IFADDR` are already-shifted bitmask macros that can be OR-ed correctly.

**strongSwan comparison**: strongSwan's `kernel_netlink_ipsec` uses the same 3-socket model: `socket_xfrm` (send), `socket` (XFRM notifications), and a shared `kernel_netlink_net` for route notifications. The separation of send and notification sockets is the established pattern to prevent notification messages from interfering with request/response correlation.

### XFRM Backend: Request/Response Correlation

Single-threaded blocking `recvmsg()` on `NL_SEND_FD` per request. The correlation follows the `send_once` pattern:

1. **Sequence number generation**: Use an atomic, monotonically increasing `uint32_t` counter (e.g., `__sync_add_and_fetch(&seq_counter, 1)`). Never reuse sequence numbers; skip 0 if the increment wraps.
2. **Send**: Set `hdr->nlmsg_seq = seq`, `hdr->nlmsg_pid = 0`, `hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK`. Call `sendmsg(NL_SEND_FD, ...)`.
3. **Receive**: Block on `recvmsg(NL_SEND_FD, ...)` with a 5-second timeout (`struct timespec {tv_sec=5}`). Discard messages where `hdr->nlmsg_seq != seq` or `hdr->nlmsg_pid != 0`. Process the first matching message.
4. **Retry**: On `NLMSG_ERROR` with `err->error == -EBUSY`, retry the entire send/receive cycle up to 3 times. For dump requests (e.g., deferred `XFRM_MSG_GETSA`), continue receiving until `NLMSG_DONE`. For normal requests, the response is a single `NLMSG_ERROR` ACK — there is no `NLMSG_DONE`. Note: `XFRM_MSG_ALLOCSPI` returns a `NEWSA` *data* reply carrying the allocated SPI (not just an ACK); the correlation handler must parse the typed data payload for that message type.
5. **Timeout**: If no matching response arrives within 5 seconds after 3 retries, log an error and return -1.

**strongSwan comparison**: strongSwan uses `ref_get_nonzero(&this->seq)` for atomic sequence generation and `send_once(this, in, seq, &hdr, &len)` with a configurable retry loop (`this->retries`). strongSwan's `netlink_send()` retries on `OUT_OF_RES` and `-EBUSY`. Racoon adopts the same `send_once` blocking pattern with atomic sequence numbers and retry on `-EBUSY`.

### XFRM Backend: Error Handling

Distinguish between recoverable and fatal errors. The following table defines the error classification:

| Error | Context | Classification | Action |
|-------|---------|---------------|--------|
| `NLMSG_ERROR`, `err->error == 0` | Any request | Success | ACK received; proceed normally |
| `-EEXIST` | `XFRM_MSG_NEWSA`, `XFRM_MSG_NEWPOLICY` | Recoverable | Treat as success (idempotent); return 0 |
| `-ENOENT` | `XFRM_MSG_DELSA`, `XFRM_MSG_DELPOLICY` | Recoverable | Treat as success (already gone); return 0 |
| `-EBUSY` | Any request | Retry | Retry send/receive up to 3 times |
| `-EINVAL` | Any request | Fatal | Log error, return -1 |
| `-EPERM` | Any request | Fatal | Log error, return -1 |
| `-ESRCH` | `XFRM_MSG_DELSA` | Recoverable | Treat as NOT_FOUND; return 0 |
| `-ENOBUFS` | Notify socket `recvmsg` | Warning | Log warning, drain buffer in tight loop until `EAGAIN` |
| Timeout | Send socket `recvmsg` | Fatal | Log error, return -1 |
| `recvmsg` returns 0 | Any socket | Fatal | Kernel closed socket; log and abort |

**strongSwan comparison**: strongSwan's `ignore_retransmit_error()` silences `-EEXIST` for NEWSA/NEWPOLICY and `-ENOENT` for DELSA/DELPOLICY on retries. `netlink_send_ack()` maps `-EEXIST` to `ALREADY_DONE` and `-ESRCH` to `NOT_FOUND`. Racoon adopts the same approach: idempotent CREATE and DELETE operations silently succeed on these errors.

### XFRM Backend: Notification Handling

XFRM notifications map to PF_KEY equivalents:

| PF_KEY Notification | XFRM Equivalent | Handler |
|---------------------|-----------------|---------|
| `SADB_X_EVENT_EXPIRE` | `XFRM_MSG_EXPIRE` | SA expire logic |
| `SADB_X_SPDEVENT_EXPIRE` | `XFRM_MSG_POLEXPIRE` | Policy expire logic |
| `SADB_X_SPDDELETE` | `XFRM_MSG_DELPOLICY` | Policy delete logic |
| `SADB_X_ACQUIRE` | `XFRM_MSG_ACQUIRE` | `isakmp_request_acquire()` |
| `SADB_X_MIGRATE` | `XFRM_MSG_MIGRATE` + `NETLINK_ROUTE` | Address migration |
| `SADB_X_NAT_T_NEW_MAPPING` | `XFRM_MSG_MAPPING` | NAT-T peer port change |

Critical: `XFRM_MSG_MIGRATE` only covers peer address changes. Local address changes come from `NETLINK_ROUTE` (`RTM_NEWADDR`/`RTM_DELADDR`).

#### Notification Socket Buffer Management

The notification socket (`NL_XFRM_FD`) can overflow under high event rates. To prevent lost notifications:

1. **Buffer size**: Set `SO_RCVBUF` to 256 KB on socket creation. Try `SO_RCVBUFFORCE` first (requires `CAP_NET_ADMIN`), fall back to `SO_RCVBUF`.
2. **ENOBUFS drain**: If `recvmsg()` returns `-1` with `errno == ENOBUFS`, log a warning and enter a tight drain loop: continue calling `recvmsg()` until `EAGAIN`/`EWOULDBLOCK`. This ensures the socket buffer is cleared before processing continues.
3. **Non-blocking**: The notification socket must be non-blocking (`O_NONBLOCK`) to allow the drain loop to work.

**strongSwan comparison**: strongSwan's `set_rcvbuf_size()` configures `SO_RCVBUFFORCE` first, falling back to `SO_RCVBUF`, using a configurable default (`NETLINK_RCVBUF_DEFAULT`). Racoon adopts the same fallback pattern with a fixed 256 KB default.

### Key Semantic Differences (PF_KEY vs XFRM)

| Aspect | PF_KEY | XFRM |
|--------|--------|------|
| EXPIRE source | Kernel timer driven | Kernel timer driven (`hard` flag in `XFRM_MSG_EXPIRE`: soft → rekey, hard → SA gone) |
| Address migration | Single notification for peer+local | `XFRM_MSG_MIGRATE` (peer only) + `NETLINK_ROUTE` (local) |
| Policy dump | Not used | Returns all policies (including kernel defaults); cannot isolate "our" policies |
| Reload strategy | Direct reinstall | Flush + reinstall from internal `secpolicy` list (host-wide, see Design Scope) |
| 64-bit alignment | N/A | `xfrm_user_acquire` and related structs have 32-bit aligned 64-bit fields — must use `memcpy()` |

### XFRM Backend: 64-Bit Field Alignment

Several `xfrm_user_*` structures contain 64-bit fields that are only 32-bit aligned in the kernel's netlink wire format. Direct struct assignment causes bus errors on strict architectures (SPARC, ARM64 with strict alignment).

**Required pattern**: Always use `memcpy()` to populate or read 64-bit fields in netlink payloads:

```c
/* WRONG - may fault on strict architectures */
xfrmu->lft.add_time_expires = add_time_expires;

/* CORRECT - safe on all architectures */
memcpy(&xfrmu->lft.add_time_expires, &add_time_expires, sizeof(add_time_expires));
```

Affected structures:
- `xfrm_user_expire` — u64 lifetime fields in embedded `xfrm_lifetime_cur`
- `xfrm_usersa_info` — u64 lifetime fields in embedded `xfrm_lifetime_cfg` / `xfrm_lifetime_cur`
- `xfrm_usersa_id` — `reqid` (u32, OK), but embedded in multipart messages
- `xfrm_user_acquire` — `reqid` (u32), `seq` (u32), u64 fields in embedded `xfrm_lifetime_cur`

**strongSwan comparison**: strongSwan consistently uses `memcpy` for all 64-bit fields in `xfrm_user_*` struct population, both for send and receive paths. Racoon must adopt the same discipline.

### XFRM Backend: Byte Order

Beyond alignment, XFRM netlink attributes use a mix of network byte order and host byte order. Mixing them up produces correct behavior on little-endian x86_64 but fails silently on big-endian architectures (s390x, sparc64).

**Network order (`__be` prefix)** — must use `htons()`/`htonl()`/`be16_to_cpu()`/`be32_to_cpu()`:
- SPI — `__be32`
- Selector source/dest ports (`xfrm_selector.sport`/`dport`) — `__be16`
- Encapsulation ports (`xfrm_encap_tmpl.sport`/`dport`) — `__be16`

**Host order** — no conversion needed:
- `reqid`, `ifindex`, `mark` / `mask`, `replay_window`, `family`
- `xfrm_lifetime_cfg` / `xfrm_lifetime_cur` fields (bytes, packets, add_time, use_time, expires) — 64-bit, apply `memcpy()` discipline on strict-alignment arches

Always use the canonical `linux/xfrm.h` struct definitions — never hand-redefine.

### XFRM Flush Semantics

`XFRM_MSG_FLUSHSA` requires a `struct xfrm_usersa_flush` payload with a `proto` field. To flush all SAs, iterate over `{IPPROTO_AH, IPPROTO_ESP, IPPROTO_COMP}` and send `XFRM_MSG_FLUSHSA` for each. `XFRM_MSG_FLUSHPOLICY` requires no payload.

**strongSwan comparison**: strongSwan's `_flush_sas()` iterates over AH, ESP, COMP sending `XFRM_MSG_FLUSHSA` per protocol. `_flush_policies()` sends `XFRM_MSG_FLUSHPOLICY` with no payload. Racoon adopts the same approach.

### Comparative Analysis with strongSwan

| Aspect | strongSwan (`kernel_netlink`) | racoon (kernelpaws) |
|--------|-------------------------------|---------------------|
| Socket model | 3 sockets via `netlink_socket_t` shared infrastructure | 3 sockets, direct fd management |
| Threading | Multi-threaded with mutex/condvar | Single-threaded `select()` loop |
| Seq numbers | `ref_get_nonzero(&this->seq)` per socket instance | Atomic `uint32_t` counter |
| Request/response | `send_once()` blocking + retry loop | `send_once()` blocking + retry loop |
| Error handling | `ignore_retransmit_error()` + `send_ack()` | Error classification table |
| Buffer management | Configurable `SO_RCVBUF`/`SO_RCVBUFFORCE` | Fixed 256 KB, `SO_RCVBUFFORCE` fallback |
| SAD authority | Userland cache synchronized with kernel | Kernel is authority; no userland cache |
| Policy reload | Selective DELSA/DELPOLICY (coexistence) | Host-wide FLUSHSA/FLUSHPOLICY (exclusive ownership) |
| NAT-T | `XFRMA_ENCAP`, `XFRM_MSG_MAPPING` notifications | `XFRMA_ENCAP`, `XFRM_MSG_MAPPING` notifications |
| Mark | `XFRMA_MARK`, `XFRMA_SET_MARK`, `XFRMA_SET_MARK_MASK` (isolation) | `XFRMA_MARK` from config only; not used for coexistence (exclusive XFRM ownership) |
| Alignment | `memcpy()` for all 64-bit `xfrm_user_*` fields | `memcpy()` for all 64-bit `xfrm_user_*` fields |
| ACK mode | `NLM_F_ACK` on send socket | `NLM_F_ACK` on send socket |

Key divergences:

1. **SAD authority**: strongSwan maintains a userland SAD cache synchronized with the kernel, enabling fast local lookups. Racoon follows LibreSwan's approach: the kernel is the authoritative SAD; Racoon only tracks what the IKE state machine needs. This simplifies the design but means `XFRM_MSG_GETSA` may be needed for certain queries (deferred to a follow-up).

2. **XFRM table ownership**: strongSwan uses `XFRMA_SET_MARK` for mark-based isolation and selective `DELSA`/`DELPOLICY` during reload, allowing coexistence with other XFRM daemons. Racoon uses blanket `FLUSHSA`/`FLUSHPOLICY` and assumes exclusive ownership of host XFRM tables (see Design Scope). This is a deliberate trade-off: simplicity over coexistence, consistent with Racoon's lightweight design philosophy.

### File Structure

```
src/racoon/
  kernelpaws.h           - Unified ops interface + public API
  kernelpaws.c           - Backend selection, init/shutdown glue
  kernelpaws_pfkeyv2.c   - PF_KEYv2 backend (merged libipsec + pfkey.c)
  kernelpaws_xfrm.c      - XFRM netlink backend
  kernelpaws_addr.c      - Address conversion utilities (shared)
```

### Build System

```autoconf
AC_ARG_ENABLE([xfrm],
  [AS_HELP_STRING([--enable-xfrm], [use XFRM netlink backend @<default=no>@])],
  [], [enable_xfrm=no])

AS_IF([test "x$enable_xfrm" = "xyes"],
  [AC_DEFINE([USE_XFRM], [1], [Use XFRM netlink backend])])
```

After Phase 0, `libipsec.la` is removed from `racoon_LDADD`. The merged PF_KEY code becomes part of `kernelpaws_pfkeyv2.c`.

## Migration Plan

### Phase 0: Merge libipsec (Complete in prototype)
Move `src/libipsec/` sources into `src/racoon/`. Remove `libipsec` shared library from daemon linkage. Resolve symbol collisions with policy parser prefixes.

### Phase 1: Abstraction Layer (Complete in prototype)
Create `kernelpaws.h`, `kernelpaws.c`, `kernelpaws_pfkeyv2.c`. Replace all `pk_*` call sites with `kernelpaws_backend->*()` dispatch. Verify behavioral equivalence with PF_KEY backend.

### Phase 2: XFRM Backend (Stub in prototype)
Implement `kernelpaws_xfrm.c`: 3-socket model, request/response correlation, notification handlers, SPI allocation, SA add/update/delete, policy operations. Driven by TDD — tests must pass before each sub-phase is considered complete.

### Phase 3: Cleanup
Deprecate PF_KEY backend. Remove dead code. Update documentation.

### Prototype Status

A working prototype is available on the **`rfc-002/kernelpaws-prototype`** branch. It can be checked out and built to verify the abstraction layer compiles and links correctly:

```bash
git checkout rfc-002/kernelpaws-prototype
./autogen.sh && ./configure --enable-xfrm && make
```

Current prototype status:
- Phase 0: Complete. libipsec merged, symbol collisions resolved.
- Phase 1: Complete. All call sites migrated, builds cleanly with `-Wall -Werror`.
- Phase 2: Stub skeleton. All vtable entries return safe defaults (-1/NULL/0).

Gaps against design spec: `send_delete`, `shutdown`, `spd_flush`, `spi_flush`, `name`, `replay_window`, `esn`, `mark` fields need to be added to the vtable for full spec compliance.

## Testing Strategy

Testing follows a TDD approach with 77 tests across four categories. Each `kernelpaws_ops` function must have at least one unit test and one integration test before its XFRM implementation is considered complete. RFC 0001 defines the "itlab" Incus-based integration testing framework in which the end-to-end tests execute, using the Incus hybrid model (system containers by default, VMs for cross-kernel isolation).

### Prerequisite

**RFC 0001 integration suite must pass before kernelpaws tests can be executed.** The itlab framework provides the container and VM infrastructure, test execution, sanitizer pipeline, and CI integration that kernelpaws E2E tests depend on. Tests requiring kernel isolation (e.g., XFRM ABI changes, `xfrm_acq_expires` defaults) run in Incus VMs; all other tests run in fast-starting system containers.

### Test Categories

| Category | Count | Environment | Purpose |
|----------|-------|-------------|---------|
| A. Unit Tests | 36 | Mocked sockets | Netlink message construction/parsing, alignment, address conversion |
| B. Integration Tests | 19 | Real kernel, `CAP_NET_ADMIN` | SA/Policy lifecycle against live XFRM |
| C. Failure Path Tests | 12 | Error injection / real kernel | Kernel rejection, correlation failure, socket errors |
| D. Notification Tests | 10 | Buffer parsing + real kernel | ACQUIRE, EXPIRE, POLEXPIRE, MIGRATE handling |
| **Total** | **77** | | |

### End-to-End Tests (within itlab — RFC 0001)

| ID | Description | Priority |
|----|-------------|----------|
| E1 | Basic host-to-host IKEv1 | Critical |
| E2 | Roadwarrior with subnet | Critical |
| E3 | SA expiration | High |
| E4 | Policy drop | Medium |
| E5 | SA rekeying | High |
| E6 | IPv6 support | High |
| E7 | Impairment recovery | Medium |
| E8 | Valgrind clean | Critical |

### Phase-Gated Test Requirements

| Phase | Required Tests |
|-------|---------------|
| Phase 1 (PF_KEYv2 wrapper) | A9-A11 (parsing/correlation) |
| Phase 2.X (XFRM init/shutdown) | A13, C11, C12 (alignment, socket failure) |
| Phase 2.Y (SPI allocation) | A1, B10-B13 |
| 2.Z (SA add/delete) | A2-A4, B1-B9, C1-C7 |
| 2.W (Policy) | A5-A7, B14-B18 |
| 2.V (Notifications) | D1-D10, E3, E5 |
| Phase 3 (Cleanup) | All 77 unit/integration + E1-E6 + E8 valgrind clean |

### Pre-Flight Checklist

- [ ] RFC 0001 itlab integration suite passes on target CI environment
- [ ] Incus infrastructure available with `CAP_NET_ADMIN` delegation (system containers and VMs)
- [ ] Minimum kernel version 5.10+ for XFRM netlink stability
- [ ] VM test images available for minimum and latest stable kernels (for `requires: vm` tests)
- [ ] `net.core.xfrm_acq_expires` sysctl set (prevent acquire storms; lives under `net.core.`, not `net.ipv4.`)

## Risks

| Risk | Mitigation |
|------|------------|
| XFRM behavior varies by kernel version | Pin minimum kernel 5.10+; `requires: vm` tests in Incus VMs with target kernel |
| PF_KEY synchronous vs XFRM async semantics | Dedicated send socket with blocking `recvmsg` per request |
| `NLMSG_ERROR` handling | Always check `NLMSG_ERROR`; use `NLM_F_ACK` (per-message) plus `NETLINK_CAP_ACK` (socket option) |
| 64-bit field alignment on strict architectures | Always use `memcpy()` for 64-bit fields in `xfrm_user_*` structs |
| Container networking differs from bare metal | Supplement with bare-metal smoke tests before release |
| Incus unavailable in CI | Fall back to `ip netns` (Linux network namespaces) for container tests; VM tests require dedicated runner |
| Replay window / ESN complexity | Encapsulate in XFRM backend; expose simple `replay_window` and `esn` knobs |
| IPCOMP kernel deprecation | Probe at init time; handle rejection gracefully |

## Referenced Documents

- RFC 0001: Incus-based Integration Testing Framework ("itlab") — defines Incus hybrid infrastructure (containers + VMs), test execution, and CI for end-to-end tests.
- Branch `rfc-002/kernelpaws-prototype` — working prototype implementation.
- Branch `prototype/kernelpaws`, `docs/suites/kernelpaws_design_v2.md` — finalized kernelpaws architecture design.
- Branch `prototype/kernelpaws`, `docs/suites/kernelpaws_testing.md` — detailed 77-test TDD proposal and integration testing annex.
- Branch `prototype/kernelpaws`, `docs/suites/kernelpaws_prototype.md` — prototype implementation status and compliance matrix.
- Branch `prototype/kernelpaws`, `docs/suites/kernelpaws_review.md` — LibreSwan XFRM maintainer design review feedback.
- Branch `prototype/kernelpaws`, `docs/suites/libreswan_xfrm_analysis.md` — PF_KEYv2 to XFRM reference architecture mapping.