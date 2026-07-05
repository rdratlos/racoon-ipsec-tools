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

## Non-goals

- IKEv2 support — scope is IKEv1 only.
- Runtime backend switching — selection is compile-time via `--enable-xfrm`.
- `XFRM_MSG_GETSA` support — deferred to a follow-up; not needed for the IKEv1 critical path.
- Independent userland SAD cache — the kernel is the authoritative SAD; Racoon only tracks what the IKE state machine needs.
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
| `spd_flush` | `pfkey_send_flush(SADB_X_SPD_FLUSH)` | `XFRM_MSG_FLUSHPOLICY` |
| `spi_flush` | `pfkey_send_flush(SADB_SATYPE_UNSPEC)` | `XFRM_MSG_FLUSHSAD` |
| `send_eacquire` | `pfkey_send_eacquire()` | `XFRM_MSG_NEWPOLICY` (SKIP action) |
| `fixup_addresses` | `pfkey_send_update2()` | `XFRM_MSG_UPDSA` + `NETLINK_ROUTE` for local addr changes |

### XFRM Backend: 3-Socket Model

| Socket | Purpose | Multicast Groups |
|--------|---------|-----------------|
| `NL_SEND_FD` | Unicast requests and correlated responses | None |
| `NL_XFRM_FD` | XFRM multicast notifications | `XFRMNLGRP_MEMBERSHIP` |
| `NL_ROUTE_FD` | Local address change notifications | `RTMGRP_IPV4_IFADDR`, `RTMGRP_IPV6_IFADDR` |

All three sockets register via `monitor_fd()` in `init()`.

### XFRM Backend: Request/Response Correlation

Single-threaded blocking `recvmsg()` on `NL_SEND_FD` per request. Each `send_*` operation assigns a unique netlink sequence number, sends the request, then blocks on `kernelpaws_xfrm_recv_response()` until the matching response arrives. Must handle `NLMSG_ERROR` responses (negative `err->error` indicates failure). Use `NLM_F_ACK` or `NETLINK_CAP_ACK` to guarantee kernel responses.

### XFRM Backend: Notification Handling

XFRM notifications map to PF_KEY equivalents:

| PF_KEY Notification | XFRM Equivalent | Handler |
|---------------------|-----------------|---------|
| `SADB_X_EVENT_EXPIRE` | `XFRM_MSG_EXPIRE` | SA expire logic |
| `SADB_X_SPDEVENT_EXPIRE` | `XFRM_MSG_POLEXPIRE` | Policy expire logic |
| `SADB_X_SPDDELETE` | `XFRM_MSG_DELPOLICY` | Policy delete logic |
| `SADB_X_ACQUIRE` | `XFRM_MSG_ACQUIRE` | `isakmp_request_acquire()` |
| `SADB_X_MIGRATE` | `XFRM_MSG_MIGRATE` + `NETLINK_ROUTE` | Address migration |

Critical: `XFRM_MSG_MIGRATE` only covers peer address changes. Local address changes come from `NETLINK_ROUTE` (`RTM_NEWADDR`/`RTM_DELADDR`).

### Key Semantic Differences (PF_KEY vs XFRM)

| Aspect | PF_KEY | XFRM |
|--------|--------|------|
| EXPIRE source | Userland timer driven | Kernel timer driven |
| Address migration | Single notification for peer+local | `XFRM_MSG_MIGRATE` (peer only) + `NETLINK_ROUTE` (local) |
| Policy dump | Not used | Returns all policies (including kernel defaults); cannot isolate "our" policies |
| Reload strategy | Direct reinstall | Flush + reinstall from internal `secpolicy` list |
| 64-bit alignment | N/A | `xfrm_user_acquire` and related structs have 32-bit aligned 64-bit fields — must use `memcpy()` |

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

Testing follows a TDD approach with 77 tests across four categories. Each `kernelpaws_ops` function must have at least one unit test and one integration test before its XFRM implementation is considered complete. RFC 0001 defines the "itlab" Incus-based integration testing framework in which the end-to-end tests execute.

### Prerequisite

**RFC 0001 integration suite must pass before kernelpaws tests can be executed.** The itlab framework provides the container infrastructure, test execution, sanitizer pipeline, and CI integration that kernelpaws E2E tests depend on.

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
- [ ] Incus/LXC container infrastructure available with `CAP_NET_ADMIN` delegation
- [ ] Minimum kernel version 5.10+ for XFRM netlink stability
- [ ] `net.ipv4.xfrm_acq_expires=1` sysctl set (prevent acquire storms)

## Risks

| Risk | Mitigation |
|------|------------|
| XFRM behavior varies by kernel version | Pin minimum kernel 5.10+; kernel-version-specific test markers |
| PF_KEY synchronous vs XFRM async semantics | Dedicated send socket with blocking `recvmsg` per request |
| `NLMSG_ERROR` handling | Always check `NLMSG_ERROR`; use `NLM_F_ACK`/`NETLINK_CAP_ACK` |
| 64-bit field alignment on strict architectures | Always use `memcpy()` for 64-bit fields in `xfrm_user_*` structs |
| Container networking differs from bare metal | Supplement with bare-metal smoke tests before release |
| Incus unavailable in CI | Fall back to `ip netns` (Linux network namespaces) |
| Replay window / ESN complexity | Encapsulate in XFRM backend; expose simple `replay_window` and `esn` knobs |
| IPCOMP kernel deprecation | Probe at init time; handle rejection gracefully |

## Referenced Documents

- RFC 0001: Incus-based Integration Testing Framework ("itlab") — defines container infrastructure, test execution, and CI for end-to-end tests.
- Branch `rfc-002/kernelpaws-prototype` — working prototype implementation.
- Branch `prototype/kernelpaws`, `docs/suites/kernelpaws_design_v2.md` — finalized kernelpaws architecture design.
- Branch `prototype/kernelpaws`, `docs/suites/kernelpaws_testing.md` — detailed 77-test TDD proposal and integration testing annex.
- Branch `prototype/kernelpaws`, `docs/suites/kernelpaws_prototype.md` — prototype implementation status and compliance matrix.
- Branch `prototype/kernelpaws`, `docs/suites/kernelpaws_review.md` — LibreSwan XFRM maintainer design review feedback.
- Branch `prototype/kernelpaws`, `docs/suites/libreswan_xfrm_analysis.md` — PF_KEYv2 to XFRM reference architecture mapping.