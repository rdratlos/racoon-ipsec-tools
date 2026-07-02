# kernelpaws Design Review

**Reviewer**: LibreSwan XFRM maintainer
**Date**: 2025-01-XX
**Subject**: Review of "kernelpaws" kernel abstraction layer for Racoon IKEv1 PF_KEY -> XFRM migration

---

## Executive Summary

The kernelpaws design is architecturally sound and correctly identifies the core
structural and semantic challenges in migrating Racoon IKEv1 from PF_KEYv2 to
XFRM netlink. The proposed `kernelpaws_ops` adapter pattern, compile-time
backend selection, and 3-socket netlink model are all well-founded.

This review provides feedback from LibreSwan's operational XFRM backend
(`kernel_xfrm.c`, ~3400 lines), covering correlation, notifications, semantic
differences, and edge cases encountered in production.

---

## §8.2 — XFRM Request/Response Correlation

### Assessment: Sound, with implementation caveats

The blocking `recvmsg` loop on a dedicated send socket (`NL_SEND_FD`) is the
correct approach for a single-threaded daemon and matches LibreSwan's
`sendrecv_xfrm_msg()` exactly.

### Implementation notes from LibreSwan

**Sequence number management**: LibreSwan uses a single static `seq` counter
across all netlink requests. This is sufficient because:
- The send socket is dedicated to request/response only (no multicast groups).
- The single-threaded model guarantees that only one request is in-flight at a
  time.

**Correlation loop** (`kernel_xfrm.c:440-570`):
```c
static int sendrecv_xfrm_msg(struct nlmsghdr *n, struct nlm_resp *resp, ...)
{
    resp->reqid = n->nlmsg_seq = ++seq;
    resp->expected_resp_type = ...;

    sendmsg(NL_SEND_FD, ...);

    do {
        r = recvfrom(NL_SEND_FD, &resp->n, ..., MSG_DONTWAIT);
        // Skip NLMSG_ERROR with NLMSG_ERROR_TYPE != expected
        // Skip unrelated messages
        break when nlmsg_seq == reqid && nlmsg_type == expected_resp_type
    } while (1);
}
```

Key detail: The loop must handle `NLMSG_ERROR` responses. XFRM returns these
for invalid requests (e.g., `XFRM_MSG_UPDSA` for a nonexistent SPI). The error
payload contains the errno.

**Recommended Racoon adaptation**: The `kernelpaws_xfrm_wait()` concept is
correct. Name it `kernelpaws_xfrm_recv_response()` to match the send/recv
semantics. Must filter:
1. `nlmsg_seq` matches the request sequence number.
2. `nlmsg_type` is the expected response type (e.g., `XFRM_MSG_NEWSA` for
   `XFRM_MSG_UPDSA`).
3. `NLMSG_ERROR` indicates failure; extract errno from payload.

---

## §10 — Notification Handler Semantics

### Critical Finding: PF_KEY and XFRM have different notification coverage

The semantic mapping of PF_KEY notifications to XFRM multicast events is
generally correct, but there are important differences:

**PF_KEY notifications Racoon currently handles** (via `pfkey.c`):
- `SADB_X_ACQUIRE`: Trigger new SA negotiation.
- `SADB_X_EXPIRE`: SA lifetime expiry (soft/hard).
- `SADB_X_POLICY_EXPIRE`: Policy lifetime expiry.
- `SADB_X_EACQUIRE`: Extended acquire with more selector data.

**XFRM multicast equivalents**:
- `SADB_X_ACQUIRE` → `XFRM_MSG_ACQUIRE` (group `XFRMGRP_ACQUIRE`)
- `SADB_X_EXPIRE` → `XFRM_MSG_EXPIRE` (group `XFRMGRP_EXPIRE`)
- `SADB_X_POLICY_EXPIRE` → `XFRM_MSG_POLEXPIRE` (group `XFRMGRP_EXPIRE`)

### Key difference: XFRM acquire includes the policy lookup result

In PF_KEY, `SADB_X_ACQUIRE` carries the policy selector. In XFRM,
`XFRM_MSG_ACQUIRE` carries `struct xfrm_user_acquire`, which includes:
- `struct xfrm_usersa_info state`: The partial SA (with proto, mode, addresses).
- `struct xfrm_userpolicy_id policy`: The policy ID that triggered the acquire.
- `struct xfrm_lifetime_cur curlft`: Current lifetime counters.

**Important**: The `xfrm_user_acquire` struct has 32-bit alignment issues
(see `kernel_xfrm.c:2570-2584`). On strict architectures (SPARC, some ARM),
64-bit fields within the struct may be misaligned. The kernelpaws design should
note this and use `memcpy` to copy fields out rather than direct pointer
dereference for 64-bit members.

### PF_KEY EXPIRE handling note

In LibreSwan, the PF_KEY backend (`kernel_pfkeyv2.c`) does NOT handle EXPIRE
notifications directly. Instead, SA expiration is handled by userland timers
(`handle_sa_expire` is called from the XFRM backend's
`netlink_process_xfrm_messages`, not from the PF_KEY backend). This is because
on many PF_KEY implementations, EXPIRE semantics vary widely.

For XFRM, EXPIRE notifications are reliable and should be processed. The
`xfrm_kernel_sa_expire()` function (`kernel_xfrm.c:2490-2565`) handles both
soft and hard expire, converts to IKE protocol IDs, and calls
`handle_sa_expire()`. Racoon's equivalent should do the same.

### Distinguishing unicast responses from multicast events

The kernelpaws design correctly identifies that unicast responses (to requests
sent on `NL_SEND_FD`) and multicast events (arriving on `NL_XFRM_FD`) use
separate sockets. This is the clean approach and avoids the complexity of
distinguishing by `nlmsg_flags & NLM_F_MULTI` or source port.

---

## §8.1 — Dual Socket Necessity (NETLINK_ROUTE)

### Assessment: Correct, with additional context

The `NETLINK_ROUTE` socket for `RTMGRP_IPV4_ADDR_LABEL` and
`RTMGRP_IPV6_ADDR_LABEL` is necessary because:

1. `XFRM_MSG_MIGRATE` from the XFRM subsystem handles **peer address** changes
   (when the remote endpoint's IP changes). It does NOT handle **local address**
   changes (when the local interface IP changes).

2. Local address changes arrive as `RTM_NEWADDR`/`RTM_DELADDR` on the
   `NETLINK_ROUTE` socket. Without listening for these, SA binding to a local
   address that is removed would silently break.

### Implementation note

LibreSwan's `netlink_rtm_fd` also binds to:
- `RTMGRP_IPV4_ADDR_LABEL` (v4 address events)
- `RTMGRP_IPV6_ADDR_LABEL` (v6 address events)
- `RTMGRP_IPV4_ROUTE` (route events, for policy recalculation)
- `RTMGRP_IPV6_ROUTE` (route events)

For the minimum viable kernelpaws, binding only to `RTMGRP_*_ADDR_LABEL` is
sufficient. Route monitoring can be added later.

---

## Open Questions — Answers from LibreSwan Experience

### Q1: Should `libipsec` be replaced by a merged daemon module?

**Recommendation: Merge.** LibreSwan merged PF_KEY code directly into
`kernel_pfkeyv2.c` to avoid ABI burden. The kernelpaws layer is internal to the
daemon binary — there's no external consumer of `libipsec`'s ABI. Merging
simplifies the build, eliminates the shared library dependency, and aligns with
the "single binary" model of Racoon.

### Q2: Independent SAD cache?

**Recommendation: No.** The kernel IS the authoritative record of SAs and
policies. Userland (Racoon/pluto) tracks only what is needed for the IKE state
machine (which SA belongs to which Quick Mode SA, lifetime tracking, rekeying
scheduling). LibreSwan does NOT maintain an independent SAD cache. When the
kernel sends `XFRM_MSG_EXPIRE`, the userland daemon correlates it to the
existing IKE SA using (SPI, protocol, destination). No full SAD replay or
reconciliation loop is needed.

### Q3: `XFRM_MSG_GETSA` support?

**Assessment: Rarely needed for IKEv1.** LibreSwan uses `XFRM_MSG_GETSA`
(`kernel_xfrm.c:2851`) only in limited diagnostic contexts. For the initial
kernelpaws migration, this can be deferred. The critical path is:
1. `send_getspi` (SPI allocation via `XFRM_MSG_GETAE` or kernel-assigned).
2. `send_add` (SA installation via `XFRM_MSG_UPDSA`).
3. `send_delete` (SA removal via `XFRM_MSG_DELSA`).

`XFRM_MSG_GETSA` can be a follow-up for `setkey`-like debugging functionality.

### Q4: Policy dump and restore?

**Recommendation: Flush + reinstall.** LibreSwan does NOT implement a policy
dump/restore cycle via `XFRM_MSG_GETPOLICY` dumps. The reason: XFRM policy dump
returns all policies (including those installed by other daemons, and the kernel
's default policies), making it difficult to isolate "our" policies. Additionally,
the XFRM policy structures don't map 1:1 to Racoon's internal `secpolicy`
structures.

The correct approach for SIGHUP/reload is:
1. Flush all policies installed by the Racoon instance.
2. Reinstall from Racoon's internal `secpolicy` list (which persists across
   reload).

This is simpler, more reliable, and avoids parsing complex netlink dumps.

### Q5: IPCOMP support?

**Status: Supported, but kernel-dependent.** LibreSwan handles IPCOMP via
`XFRMA_ALG_COMP` (`kernel_xfrm.c:1835-1857`). The compression algorithm name
must be resolvable to a kernel-supported name. Not all kernels support IPCOMP;
it was deprecated in kernel 5.x. Racoon's XFRM backend should:
1. Support `XFRMA_ALG_COMP` for the `XFRM_MSG_UPDSA` path.
2. Verify kernel support at init time (optional probe).
3. Log an error if the kernel rejects the IPCOMP SA (will come back as
   `NLMSG_ERROR` from `XFRM_MSG_UPDSA`).

---

## Additional Considerations from LibreSwan's Migration

These are items not explicitly covered in the kernelpaws v1 design but are
important based on LibreSwan's operational experience:

### 1. NETLINK_CAP_ACK and NETLINK_EXT_ACK

Set `NETLINK_CAP_ACK` and `NETLINK_EXT_ACK` socket options on `NL_SEND_FD`
during initialization. This provides:
- **CAP_ACK**: Ensures that a successful `NLMSG_ERROR` response is sent for
  each request, even when there's no error. This eliminates ambiguity about
  whether a response was received.
- **EXT_ACK**: Provides human-readable error messages from the kernel in
  `struct nlmsgerr`'s extended attributes. Extremely valuable for debugging
  SA installation failures.

Without `CAP_ACK`, a successful `XFRM_MSG_UPDSA` may not generate any response
at all, causing the correlation loop to block indefinitely.

### 2. xfrm_acq_expires

The kernel parameter `net.ipv4.xfrm_acq_expires` controls whether acquire
messages are deduplicated (the kernel will not send duplicate acquires for the
same policy within the expiration window). Racoon should check this setting at
init and log a warning if it's set to 0 (the default), as this can cause
excessive acquire storms. Recommend setting it to 1 via
`sysctl net.ipv4.xfrm_acq_expires=1`.

### 3. 32-bit Alignment Warnings (Critical for strict architectures)

The XFRM netlink structures have fields that are only 32-bit aligned by the
netlink protocol, but contain 64-bit members (`curlft.bytes`, `curlft.packets`,
`curlft.add_time`). Direct pointer access to these fields violates C aliasing
rules on strict architectures (SPARC, S390x, some ARM configurations).

LibreSwan uses a helper `nlmsg_data()` (`kernel_xfrm.c`) that validates message
length and documents the alignment issue. The kernelpaws implementation should
use `memcpy` to extract 64-bit fields from netlink payloads on all platforms,
not just on known problematic architectures. This is a silent correctness issue
that manifests as data corruption.

### 4. Replay Window and ESN Complexity

XFRM's replay window handling is more complex than PF_KEY's:
- For replay window ≤ 32 without ESN: Use `req.p.replay_window` directly.
- For replay window > 32 or with ESN: Use `XFRMA_REPLAY_ESN_VAL` with
  `struct xfrm_replay_state_esn` and a bitmap.
- Kernel 6.10+ requires `replay_window = 0` for outbound SAs.

This complexity should be encapsulated in the XFRM backend's SA add function.
The abstraction layer should expose a simple `replay_window` and `esn` boolean
to the caller.

### 5. Mark and IF_ID Support

XFRM supports flow marks (`XFRMA_MARK`, `XFRMA_SET_MARK`,
`XFRMA_SET_MARK_MASK`) and interface binding (`XFRMA_IF_ID`). These have no
PF_KEY equivalent. The kernelpaws_ops interface should include mark fields in
the SA and policy structures, with a default of 0 (unset). Racoon's call sites
can pass 0 for mark until mark support is needed.

### 6. XFRM Policy Priority Handling

XFRM policies have a priority field (uint32_t, lower = higher priority).
PF_KEY policies also have priority, but the semantics may differ. The
kernelpaws abstraction should normalize priority to a single integer type and
let each backend handle the conversion.

---

## Summary of Feedback

| Area | Status | Action |
|------|--------|--------|
| §8.2 Correlation | Sound | Document `NLMSG_ERROR` handling requirement |
| §8.1 Dual socket | Correct | Note that `RTMGRP_*_ROUTE` can be deferred |
| §10 Notifications | Correct with caveats | Document 32-bit alignment issue for `xfrm_user_acquire` |
| PF_KEY vs XFRM semantics | Gap identified | PF_KEY EXPIRE is userland-driven; XFRM EXPIRE is kernel-driven |
| SAD cache | Correct (no cache) | No action needed |
| XFRM GETSA | Correct (deferrable) | No action needed |
| Policy dump/restore | Correct (flush+reinstall) | No action needed |
| IPCOMP | Correct | Verify kernel support at init time |
| CAP_ACK/EXT_ACK | **Missing** | Add to v2 design |
| xfrm_acq_expires | **Missing** | Add to v2 design |
| 32-bit alignment | **Missing** | Add to v2 design as critical warning |
| Replay/ESN complexity | **Partial** | Document in v2 as backend-internal concern |