# Racoon PF_KEYv2 -> XFRM Migration: Session Summary

## Goal
- Design a migration strategy and "kernelpaws" kernel abstraction layer for Racoon IKEv1 to migrate from PF_KEYv2 to XFRM netlink, including a comprehensive test-driven development proposal and integration testing annex.

## Constraints & Preferences
- Target migration is from PF_KEYv2 to XFRM.
- Reference architecture is LibreSwan's `pluto` daemon.
- Scope is limited to IKEv1; IKEv2 is out of scope.
- Racoon is single-threaded, `select()`-driven; no mutexes or condvars.
- Implementation is a static library within the daemon (no external ABI contract).
- Compile-time backend selection is preferred (`--enable-xfrm` in `configure.ac`) over runtime switching.
- Project codename for the abstraction layer is "kernelpaws".
- Apply test-driven software development policy for kernelpaws development.
- Integration testing annex must detail required test tools (valgrind, mocks) and infrastructure (Incus/LXC containers).
- Racoon currently lacks integration tests; these must be manually implemented using containers running roadwarrior gateway and clients.
- Racoon is very lightweight, has a small footprint — code extensions must be focused, footprint-minimized, but powerful.

## Progress
### Done
- Analyzed LibreSwan's kernel abstraction layer, socket model, and notification handling.
- Reviewed and finalized kernelpaws design review document (`kernelpaws_review.md`).
- Analyzed LibreSwan's test infrastructure (VPP tests, sanitizers, impairment framework) to inform the TDD proposal.
- Drafted and wrote `kernelpaws_testing.md`: comprehensive 77-test unit/integration/failure/notification proposal and end-to-end integration testing annex using Incus/LXC containers.

### Pending (Awaiting Design Finalization)
- Racoon expert to address review comments and provide v2 of `kernelpaws_design.md`.
- Publish finalized design spec on GitHub (wiki or similar).
- Send message to Linux kernel netdev mailing list to inform them that Racoon IPSec Tools is still maintained and will continue using PF_KEYv2 on NetBSD (which has not deprecated this API).
- Request Linux kernel experts to provide review and feedback on the migration approach (no official migration guide exists from the kernel side).
- Once all external feedback is incorporated, define the final implementation strategy and plan.

### Not Yet Started (After Design Finalization)
- Implement Phase 0: Merge `libipsec` into Racoon daemon and add `--enable-tests` to `configure.ac`.
- Implement Phase 1: `kernelpaws_pfkeyv2.c` wrapper around existing code.
- Implement Phase 2: `kernelpaws_xfrm.c` with critical path (SPI -> SA -> Policy) driven by unit/integration tests.

## Key Decisions
- Use a structural adapter pattern (`struct kernelpaws_ops`) to abstract PF_KEYv2 and XFRM differences.
- Backend selection is compile-time (`--enable-xfrm`) for simplicity.
- XFRM correlation will use a dedicated send socket with synchronous blocking `recvmsg` (LibreSwan pattern).
- `libipsec` should be merged into the racoon daemon binary.
- `NETLINK_ROUTE` socket is required for address migration notifications.
- For kernelpaws testing, adopt a hybrid model: (1) Lightweight unit tests for netlink message construction/parsing (mocked sockets), and (2) Integration tests leveraging real kernel XFRM interfaces.
- Integration testing for Racoon migration will use Incus/LXC containers instead of LibreSwan's KVM guests, with manual setup of roadwarrior topology.
- 64-bit fields in XFRM netlink structures must be accessed via `memcpy()` (never directly dereferenced) to avoid alignment faults.

## Critical Context
- **Test Inventory**: 77 tests defined (36 unit, 19 integration, 12 failure path, 10 notification, 8 end-to-end). Unit tests use `socketpair()` mocks to capture raw netlink buffers; integration tests require `CAP_NET_ADMIN` and verify with `ip xfrm state/policy`.
- **Abstraction Layer**: `struct kernelpaws_ops` with function pointers for `init`, `shutdown`, `reload`, `send_add`, `send_update`, `send_delete`, `send_getspi`, `spd_add`, `spd_delete`, `spd_update`, `spd_flush`, `spi_flush`, `spd_dump`, `send_eacquire`, `fixup_addresses`.
- **LibreSwan XFRM Socket Model**: Three sockets. 1) `nl_send_fd` (SOCK_DGRAM, no bind to groups) for synchronous requests (`sendrecv_xfrm_msg`). 2) `netlink_xfrm_fd` (bind to `XFRMGRP_ACQUIRE`|`XFRMGRP_EXPIRE`) for async events. 3) `netlink_rtm_fd` (bind to `RTMGRP_*`) for address/route changes.
- **Correlation**: LibreSwan uses a static `seq` counter and blocks in `recvfrom` until `nlmsg_seq` and `nlmsg_type` match. Must handle `NLMSG_ERROR` responses.
- **Notifications**: XFRM multicast events (`XFRM_MSG_ACQUIRE`, `XFRM_MSG_EXPIRE`, `XFRM_MSG_POLEXPIRE`) arrive on the bound async socket. `xfrm_user_acquire` parsing has 32-bit alignment warnings (must use `memcpy` for 64-bit fields on strict architectures).
- **Integration Testing Infrastructure**: Uses Incus/LXC containers with `security.privileged: "true"`. Network topology: gateway (10.0.0.1) and roadwarrior (10.0.0.2) on shared LXD networks. Test execution via `testing/racoon/run-tests.sh` with adapted VPP-style declarative scripts.
- **Sanitizers**: Custom `sed` scripts (`spi-sanitize.sed`, `timestamp-sanitize.sed`, `ipsec-kernel-state.sed`) normalize output for golden-file comparison. `xfrmcheck.sh` verifies `/proc/net/xfrm_stat` for non-zero error counters.
- **Valgrind Integration**: Required for memory leak detection at both unit-test level and full-daemon end-to-end level (Test E8).

## Relevant Files
- `programs/pluto/kernel.h`: Defines `struct kernel_ops` and unified API (LibreSwan reference).
- `programs/pluto/kernel_xfrm.c`: XFRM backend implementation (`xfrm_kernel_ops`); contains `sendrecv_xfrm_msg`, `init_netlink_xfrm_fd`, `init_netlink_rtm_fd`, `netlink_process_xfrm_messages`, `netlink_acquire`.
- `programs/pluto/kernel_pfkeyv2.c`: PF_KEYv2 backend implementation (`pfkeyv2_kernel_ops`).
- `/home/i149635d/code/kernelpaws_testing.md`: Comprehensive 77-test proposal and Incus integration annex.
- `/home/i149635d/code/kernelpaws_design.md`: Full design document (updated with review feedback).
- `/home/i149635d/code/kernelpaws_review.md`: LibreSwan XFRM maintainer design review.
- `/home/i149635d/code/libreswan_xfrm_analysis.md`: Detailed PF_KEYv2 -> XFRM analysis document.
- `testing/pluto/ikev1-hostpair-01/`: Representative VPP test directory (init/run scripts, console expectations, final verification).
- `testing/pluto/ikev1-rw-multiple-subnets/`: Roadwarrior subnet VPP test.
- `testing/pluto/ikev1-expire-r1-01-main/`: State expiration VPP test.
- `testing/guestbin/xfrmcheck.sh`: Script to check `/proc/net/xfrm_stat` for errors.
- `src/racoon/pfkey.c`: Racoon's current PF_KEY implementation (to be wrapped/replaced).
- `src/racoon/isakmp_quick.c`: Key call site for SA operations.
- `src/racoon/session.c`: Key call site for init/reload/policy operations.