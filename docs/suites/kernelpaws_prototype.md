# Kernelpaws Prototype Status

## Overview

This document describes the current state of the kernelpaws prototype implementation, maps what has been built against the design spec in `kernelpaws_design.md`, and identifies remaining gaps.

**Branch**: `prototype/kernelpaws`
**Commits**:
- `2c3b5e6` — Initial prototype: merged libipsec, backend abstraction layer, PF_KEY vtable
- `9da14be` — Conditional XFRM backend selection, build system, stub XFRM backend

---

## Implementation Log

### Phase 0: Merge libipsec (Complete)

The PF_KEY code from `libipsec` has been merged into the racoon source tree. The following files were copied into `src/racoon/`:

| Source File | Destination | Notes |
|---|---|---|
| `libipsec/pfkey.c` | `libipsec_pfkey.c` | Core PF_KEY message construction and sending |
| `libipsec/pfkey_dump.c` | `libipsec_pfkey_dump.c` | PF_KEY dump utilities |
| `libipsec/ipsec_strerror.c` | `ipsec_strerror.c` | Error string conversion |
| `libipsec/ipsec_dump_policy.c` | `ipsec_dump_policy.c` | Policy dump support |
| `libipsec/ipsec_get_policylen.c` | `ipsec_get_policylen.c` | Policy length calculation |
| `libipsec/policy_parse.y` | `policy_parse.y` | Policy parser grammar |
| `libipsec/policy_token.l` | `policy_token.l` | Policy lexer |
| *(extracted from key_debug.c)* | `ipsec_hexdump.c` | Hex dump utility for policy dump |

**Symbol collision resolution**: The policy parser/lexer uses `%define api.prefix {__pol}` (bison) and `%option prefix="__pol"` (flex) to avoid collision with racoon's config parser (`cfparse.y`/`cftoken.l`, which use default `yy*` prefix). The `yylval` symbol must be manually aliased as `#define yylval __pollval` in the lexer user section because bison's prefix only applies to its own generated code.

**Build system**: `libipsec.la` has been removed from `racoon_LDADD`. The merged sources are listed in `racoon_SOURCES`. The `libipsec` library still builds for `setkey`, which has not been modified.

### Phase 1: Abstraction Layer (Complete)

Created the vtable-based backend abstraction:

| File | Purpose | Lines | Status |
|---|---|---|---|
| `kernelpaws.h` | `struct kernelpaws_ops` vtable with 18 function pointers; public API declarations | 70 | Complete |
| `kernelpaws.c` | Backend selection, dispatch functions (`kernelpaws_init`, `kernelpaws_reload`, `kernelpaws_register_fd`), `kernelpaws_select_backend_pfkeyv2`, `kernelpaws_select_backend_xfrm` | 89 | Complete |
| `kernelpaws_pfkeyv2.c` | PF_KEY backend — thin wrappers forwarding to existing `pfkey.c` and `libipsec_pfkey.c` functions | 232 | Complete |
| `kernelpaws_xfrm.c` | XFRM backend — stub implementation; all functions return -1/NULL/0/"" | 227 | Stub only |

**Call site migration**: All `pk_*`, `pfkey_*`, `sadbsecas2str`, `pfkey2ipsecdoi_*`, and `ipsecdoi2pfkey_*` calls outside the PF_KEY backend have been replaced with `kernelpaws_backend->*()` dispatch. Updated files:

- `session.c` — `kernelpaws_select_backend_*`, `kernelpaws_init`, `kernelpaws_reload`
- `cfparse.y` / `cftoken.l` — config parser uses `kernelpaws_backend->checkalg`
- `isakmp.c` — SA operations
- `isakmp_quick.c` — `sendgetspi`, `sendadd`, `sendupdate`
- `isakmp_inf.c` — informational exchange SA operations
- `admin.c` — `dump_sadb`, `flush_sadb`, `getseq`
- `proposal.c` — `backend2doi_mode`

All call sites compile cleanly with `-Wall -Werror`.

### Build System Integration (Complete)

**configure.ac**: Added `--enable-xfrm` option that defines `HAVE_XFRM` and sets `AM_CONDITIONAL([HAVE_XFRM])`.

**Makefile.am**: Conditionally compiles `kernelpaws_xfrm.c` when `HAVE_XFRM` is true. Includes all merged libipsec sources and new kernelpaws sources in `racoon_SOURCES`. Removed `../libipsec/libipsec.la` from `racoon_LDADD`.

**Verified builds**:
- Default (PF_KEY backend): Compiles and links successfully
- `--enable-xfrm` (XFRM backend): Compiles and links successfully
- No `libipsec.so` dependency in resulting `racoon` binary

---

## Compliance Matrix

### Design Spec §3: Data Structures

| Requirement | Status | Notes |
|---|---|---|
| Racoon data structures (`ph2handle`, `secpolicy`, etc.) remain unchanged | Compliant | Backend receives racoon structs and translates internally |
| `kernelpaws_ops` receives `struct ph2handle *` for SA operations | Compliant | All SA ops take `struct ph2handle *` parameter |

### Design Spec §4: Target Architecture

| Requirement | Status | Notes |
|---|---|---|
| `kernelpaws.h` — unified ops interface | Compliant | `struct kernelpaws_ops` with 18 function pointers |
| `kernelpaws_pfkeyv2.c` — PF_KEY backend | Compliant | Thin wrappers around existing `pfkey.c` functions |
| `kernelpaws_xfrm.c` — XFRM backend | Partial | Stub skeleton with all 18 entries, returns error/empty |
| Compile-time backend selection | Compliant | `#ifdef HAVE_XFRM` in `kernelpaws.c` and `session.c` |
| `--enable-xfrm` configure flag | Compliant | Added to `configure.ac` |

### Design Spec §5: kernelpaws_ops Interface

| ops Entry | Design Spec Name | Implemented | Notes |
|---|---|---|---|
| `name` | `const char *name` | **Missing** | Design spec includes a `name` field; prototype vtable omits it |
| `replay_window` | config field | **Missing** | Design spec exposes replay_window int |
| `esn` | config field | **Missing** | Design spec exposes esn bool |
| `mark` | config field | **Missing** | Design spec exposes kernelpaws_mark struct |
| `init` | lifecycle | Compliant | PF_KEY: wraps `pfkey_init()`; XFRM: returns -1 |
| `shutdown` | lifecycle | **Missing** | Design spec includes `shutdown`; prototype omits |
| `reload` | lifecycle | Compliant | PF_KEY: wraps `pfkey_reload()`; XFRM: returns -1 |
| `send_add` | SA ops | Compliant | PF_KEY: wraps `pk_sendadd()`; XFRM: returns -1 |
| `send_update` | SA ops | Compliant | PF_KEY: wraps `pk_sendupdate()`; XFRM: returns -1 |
| `send_delete` | SA ops | **Missing** | Design spec includes `send_delete`; prototype omits |
| `send_getspi` | SA ops | Compliant | Named `sendgetspi` in prototype (matching existing racoon naming) |
| `spd_add` | policy ops | Compliant | Named `sendspdadd2` |
| `spd_delete` | policy ops | Compliant | Named `sendspddelete` |
| `spd_update` | policy ops | Compliant | Named `sendspdupdate2` |
| `spd_flush` | policy ops | **Missing** | Design spec includes `spd_flush`; prototype omits (covered by `flush_sadb` for SAD) |
| `spi_flush` | policy ops | **Missing** | Design spec includes `spi_flush`; prototype omits |
| `send_eacquire` | event ops | Compliant | PF_KEY: wraps `pk_sendeacquire()`; XFRM: returns -1 |
| `fixup_addresses` | addr ops | Compliant | Named `fixup_sa_addresses` |
| `checkalg` | util | Compliant | PF_KEY: wraps `pk_checkalg()`; XFRM: returns -1 |
| `getseq` | util | Compliant | Named `getseq` |
| `dump_sadb` | util | Compliant | PF_KEY: wraps `pfkey_dump_sadb()`; XFRM: returns NULL |
| `flush_sadb` | util | Compliant | PF_KEY: wraps `pfkey_flush_sadb()`; XFRM: no-op |
| `backend2doi_proto` | util | Compliant | Maps backend protocol to DOI protocol |
| `doi2backend_proto` | util | Compliant | Maps DOI protocol to backend protocol |
| `backend2doi_mode` | util | Compliant | Maps backend mode to DOI mode |
| `doi2backend_mode` | util | Compliant | Maps DOI mode to backend mode |
| `secas2str` | util | Compliant | SA identifier to string conversion |

### Design Spec §6: Per-Function Mapping

| Function | PF_KEY Backend | XFRM Backend |
|---|---|---|
| `init` | Wraps `pfkey_init()` — opens PF_KEY socket, registers protocols, calls `monitor_fd()` | Stub — returns -1 |
| `reload` | Wraps `pfkey_reload()` — flushes and reinstalls policies | Stub — returns -1 |
| `send_getspi` | Wraps `pk_sendgetspi()` | Stub — returns -1 |
| `send_add` | Wraps `pk_sendadd()` | Stub — returns -1 |
| `send_update` | Wraps `pk_sendupdate()` | Stub — returns -1 |
| `spd_add` | Wraps `pk_sendspdadd2()` | Stub — returns -1 |
| `spd_delete` | Wraps `pk_sendspddelete()` | Stub — returns -1 |
| `spd_update` | Wraps `pk_sendspdupdate2()` | Stub — returns -1 |
| `send_eacquire` | Wraps `pk_sendeacquire()` | Stub — returns -1 |

### Design Spec §8: XFRM Backend

| Requirement | Status | Notes |
|---|---|---|
| 3-socket model (`NL_SEND_FD`, `NL_XFRM_FD`, `NL_ROUTE_FD`) | **Not implemented** | Stub backend |
| `monitor_fd()` registration for all 3 sockets | **Not implemented** | |
| Request/response correlation via netlink seq | **Not implemented** | |
| Multicast subscription (`XFRMNLGRP_MEMBERSHIP`) | **Not implemented** | |
| `NLMSG_ERROR` handling | **Not implemented** | |
| `NLM_F_ACK` flag usage | **Not implemented** | |
| 64-bit field memcpy alignment | **Not implemented** | |
| `xfrm_pending_req` correlation table | **Not implemented** | |

### Design Spec §9: Migration Steps

| Phase | Requirement | Status |
|---|---|---|
| Phase 0 | Merge libipsec into racoon | Complete |
| Phase 1 | Create kernelpaws.h, .c, pfkeyv2.c | Complete |
| Phase 1 | Replace `pk_*` calls with `kernelpaws_backend->*()` | Complete |
| Phase 1 | Verify IKEv1 SA establishment works identically | Not yet tested (build only) |
| Phase 2 | Implement XFRM backend | Stub skeleton only |
| Phase 3 | Cleanup | Not started |

### Design Spec §10: Notification Handler Integration

| Requirement | Status | Notes |
|---|---|---|
| PF_KEY handler integration | Preserved | Existing `pfkey.c` handler unchanged; routed through `kernelpaws_pfkeyv2.c` |
| XFRM notification handler | **Not implemented** | Blocked on XFRM backend implementation |

### Design Spec §12: Build System

| Requirement | Status | Notes |
|---|---|---|
| `--enable-xfrm` configure option | Compliant | |
| Conditional compilation of XFRM backend | Compliant | `AM_CONDITIONAL([HAVE_XFRM])` guards `kernelpaws_xfrm.c` |
| Both backends compile into binary | Compliant | PF_KEY always compiled; XFRM conditionally |
| `libipsec` removed from racoon linkage | Compliant | `libipsec.la` removed from `racoon_LDADD` |

---

## Gaps Against Design Spec

### Omitted vtable entries (present in design spec, not in prototype)

The design spec §5.1 defines a superset of operations compared to what racoon's actual call sites require. The following entries from the design spec are **not** in the prototype vtable because no racoon call site uses them:

1. **`send_delete`** — `pk_senddelete()` exists in `pfkey.c` but is not called from any racoon source file (it was historically called from `backupsa.c` for SA fixup, but the current code path uses `fixup_sa_addresses` instead).
2. **`spd_flush`** — The design spec lists `spd_flush` (SPD flush), but racoon uses `pfkey_flush_sadb()` with `SADB_X_SPD_FLUSH` satype, which is covered by the existing `flush_sadb` entry.
3. **`spi_flush`** — Same as above: covered by `flush_sadb` with `SADB_SATYPE_UNSPEC`.
4. **`shutdown`** — No explicit shutdown path in racoon's current lifecycle.

**Recommendation**: Add `send_delete`, `spd_flush`, `spi_flush`, and `shutdown` to the vtable for design spec compliance, even if not all are called today. They may be needed for the XFRM backend's different semantics.

### Omitted config fields (present in design spec, not in prototype)

The design spec §5.1 includes `name`, `replay_window`, `esn`, and `mark` fields in `struct kernelpaws_ops`. These are not present in the prototype:

1. **`name`** — Useful for logging/debugging which backend is active. Low cost to add.
2. **`replay_window`** — Needed for XFRM to encode `XFRMA_REPLAY_ESN_VAL`. Not needed for PF_KEY path.
3. **`esn`** — Extended Sequence Number flag. Needed for XFRM `XFRMA_REPLAY_ESN_VAL`.
4. **`mark`** — Policy mark for VRF/namespace isolation. Not needed for baseline functionality.

**Recommendation**: Add `name` now (trivial). Defer `replay_window`, `esn`, and `mark` until Phase 2 XFRM implementation, when they become实际需要.

### XFRM Backend (Blocked)

Full XFRM implementation is blocked pending Linux kernel team review of the design spec. The stub skeleton is in place with all 18 vtable entries wired up, returning safe defaults (-1/NULL/0/"").

---

## Build Verification

| Configuration | Result | Notes |
|---|---|---|
| Default (`./configure`) | PASS | PF_KEY backend selected |
| `--enable-xfrm` | PASS | XFRM backend selected |
| `-Wall -Werror` | PASS | No warnings or errors |
| No `libipsec.so` dep | PASS | `ldd` confirms no libipsec linkage |

Build environment: Ubuntu 22.04 (Jammy), Kernel 5.15.0-181-generic, Bison 3.8.2, Flex 2.6.4.

---

## Blockers

1. **Linux kernel maintainer review** — PF_KEYv2 removal placed on hold pending review of Racoon's migration design. Full XFRM implementation (Phase 2) cannot proceed until review is complete.

## Next Actions (Unblocked)

1. Add omitted vtable entries: `send_delete`, `shutdown`, `spd_flush`, `spi_flush` for design spec compliance.
2. Add `name` field to `struct kernelpaws_ops`.
3. Run existing Racoon test suite against PF_KEY backend to verify behavioral equivalence.
4. Submit design spec for kernel maintainer review.

## Next Actions (Blocked on Review)

1. Implement `kernelpaws_xfrm.c`: 3-socket model, request/response correlation, notification handlers.
2. Register XFRM FDs with `monitor_fd()` in `kernelpaws_init()`.
3. Implement algorithm mapping, address conversion, policy index tracking.
4. End-to-end IKEv1 testing with XFRM backend.