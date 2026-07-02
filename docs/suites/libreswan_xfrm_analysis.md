# PF_KEYv2 → XFRM Migration Analysis (LibreSwan Reference Architecture)

## Overview

This document analyzes how LibreSwan implements dual-kernel-interface support (PF_KEYv2 and XFRM) to inform a migration strategy for Racoon IPSec Tools from the deprecated PF_KEYv2 interface to the maintained XFRM netlink interface. Scope is limited to IKEv1.

## 1. Architecture: Structural Adapter Pattern

### 1.1 Unified Interface

`struct kernel_ops` in `programs/pluto/kernel.h:206-315` defines the unified abstraction:

| Category | Function Pointers |
|---|---|
| **Init/Shutdown** | `init`, `flush`, `poke_holes`, `plug_holes`, `shutdown` |
| **SA Management** | `add_sa`, `get_kernel_state`, `get_ipsec_spi`, `del_ipsec_spi` |
| **Policy Management** | `policy_add`, `policy_del` |
| **Features** | `migrate_ipsec_sa`, `iptfs_ipsec_sa`, `directional_ipsec_sa`, `poke_ipsec_policy_hole`, `detect_nic_offload`, `poke_ipsec_offload_policy_hole` |
| **Extensions** | `ipsec_interface` (sub-adapter) |
| **Metadata** | `protostack_names`, `updown_name`, `interface_name`, `sha2_truncbug_support`, `esn_supported`, `max_replay_window` |

### 1.2 Backend Implementations

| Backend | Source | Exported Symbol |
|---|---|---|
| XFRM | `programs/pluto/kernel_xfrm.c:3383` | `xfrm_kernel_ops` |
| PF_KEYv2 | `programs/pluto/kernel_pfkeyv2.c:1899` | `pfkeyv2_kernel_ops` |

### 1.3 Backend Selection

**Compile-time** (`programs/pluto/Makefile:144-159`):
- `USE_PFKEYV2=true` → `kernel_pfkeyv2.o`
- `USE_XFRM=true` → `kernel_xfrm.o` (+ optional `kernel_xfrm_interface.o`)

**Runtime** (`programs/pluto/plutomain.c:1034-1057`):
1. Read `protostack=` from config
2. Iterate `kernel_stacks[]` for matching `protostack_names`
3. Fall back to `kernel_stacks[0]` if unset
4. Assign global `const struct kernel_ops *kernel_ops`

## 2. PF_KEYv2 → XFRM API Mapping

| Operation | PF_KEYv2 (SADB Message + Extensions) | XFRM (Netlink Message + Struct + Attrs) |
|---|---|---|
| **Probe capabilities** | `SADB_REGISTER` + `SADB_EXT_SUPPORTED_ENCRYPT/AUTH/COMP` | Test sends; no direct equivalent |
| **Allocate SPI** | `SADB_GETSPI` + `SADB_EXT_SPIRANGE` + `SADB_EXT_ADDRESS_SRC/DST` | `XFRM_MSG_ALLOCSPI` + `xfrm_userspi_info` + `XFRMA_SA_DIR` |
| **Add SA** | `SADB_ADD` + `SADB_EXT_SA` + `SADB_EXT_ADDRESS`×2-3 + `SADB_EXT_KEY_AUTH` + `SADB_EXT_KEY_ENCRYPT` + `SADB_EXT_LIFETIME_HARD/SOFT/CURRENT` + `SADB_X_EXT_SA` + `SADB_X_EXT_SA_REPLAY` | `XFRM_MSG_NEWSA` + `xfrm_usersa_info` + `XFRMA_ALG_AUTH`/`XFRMA_ALG_CRYPT`/`XFRMA_ALG_AEAD`/`XFRMA_ALG_COMP` + `XFRMA_ENCAP` + `XFRMA_MARK`/`XFRMA_SET_MARK`/`XFRMA_SET_MARK_MASK` + `XFRMA_REPLAY_ESN_VAL` + `XFRMA_SA_DIR` + `XFRMA_SEC_CTX` + `XFRMA_TFCPAD` |
| **Update SA** | `SADB_UPDATE` (+ same extensions as ADD, + `SADB_EXT_LIFETIME_CURRENT`) | `XFRM_MSG_UPDSA` (+ same attrs as NEWSA) |
| **Delete SA** | `SADB_DELETE` + `SADB_EXT_SA` (spi) + `SADB_EXT_ADDRESS_SRC/DST` | `XFRM_MSG_DELSA` + `xfrm_usersa_id` |
| **Query SA state** | `SADB_GET` + `SADB_EXT_SA` | `XFRM_MSG_GETSA` + `xfrm_usersa_id` → `XFRMA_LASTUSED` |
| **Flush SAs** | `SADB_FLUSH` | `XFRM_MSG_FLUSHSA` + `xfrm_usersa_flush` |
| **Add Policy (non-OpenBSD)** | `SADB_X_SPDADD` / `SADB_X_SPDUPDATE` + `SADB_X_EXT_POLICY` + `SADB_X_EXT_IPSECREQUEST` + `SADB_EXT_ADDRESS_SRC/DST` | `XFRM_MSG_NEWPOLICY` / `XFRM_MSG_UPDPOLICY` + `xfrm_userpolicy_info` + `XFRMA_TMPL` + `XFRMA_MARK` + `XFRMA_SEC_CTX` + `XFRMA_IF_ID` |
| **Add Policy (OpenBSD)** | `SADB_X_ADDFLOW` + flow type/addr/mask/protocol extensions | (same XFRM as above) |
| **Delete Policy** | `SADB_X_SPDDELETE` + `SADB_X_EXT_POLICY` + `SADB_EXT_ADDRESS` | `XFRM_MSG_DELPOLICY` + `xfrm_userpolicy_id` |
| **Flush Policies** | `SADB_X_SPDFLUSH` | `XFRM_MSG_FLUSHPOLICY` |
| **Kernel→User: Acquire** | `SADB_ACQUIRE` (PF_KEY socket) | `XFRM_MSG_ACQUIRE` (netlink multicast, `xfrm_user_acquire`) |
| **Kernel→User: SA Expire** | (passive) | `XFRM_MSG_EXPIRE` (`xfrm_user_expire`) |
| **Kernel→User: Policy Expire** | (passive) | `XFRM_MSG_POLEXPIRE` (`xfrm_user_polexpire`) |
| **SA Migrate** | Not supported natively | `XFRM_MSG_MIGRATE` + `xfrm_user_migrate` + `XFRMA_MIGRATE` |

## 3. Communication Model Comparison

| Aspect | PF_KEYv2 | XFRM |
|---|---|---|
| **Socket** | `socket(PF_KEY, SOCK_RAW, SADB_PROTO)` | `socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM)` |
| **Message format** | `sadb_msg` header + linked `sadb_ext` extensions (ordered, fixed-size) | `nlmsghdr` + fixed data struct (`xfrm_usersa_info`/`xfrm_userpolicy_info`) + `rtattr` netlink attributes (TLV, ordered by type) |
| **Request/Reply** | Synchronous: send → read on same socket | Synchronous: custom `sendrecv_xfrm_msg()`. Async: `bind()` + multicast listeners |
| **Address representation** | `sadb_address` (portable addr/mask/protocol) | `xfrm_address_t` (union: `struct in6_addr a6` / `struct in_addr a4`) |
| **Selectors** | `SADB_X_EXT_SRC/DST_FLOW` + `SADB_X_EXT_SRC/DST_MASK` (separate extensions) | `xfrm_selector` (inline in info struct) |
| **Crypto** | `SADB_EXT_KEY_AUTH`, `SADB_EXT_KEY_ENCRYPT` | `XFRMA_ALG_AUTH`/`XFRMA_ALG_CRYPT`/`XFRMA_ALG_AEAD` (rtattr, contains `xfrm_algo`) |
| **Lifetimes** | `SADB_EXT_LIFETIME_HARD/SOFT/CURRENT` (separate extensions) | `xfrm_lifetime_cfg`/`xfrm_lifetime_cur` (inline) |
| **Encoding** | `put_sadb_ext()` / `get_sadb_ext()` | `nl_addattr_*/RTA_DATA/RTA_NEXT` |
| **PID/Seq** | `sadb_msg_pid`, `sadb_msg_seq` | `nlmsghdr.nlmsg_pid`, `nlmsghdr.nlmsg_seq` |

## 4. Object/State Management

### PF_KEYv2 (`kernel_pfkeyv2.c:49-51`)
- `pfkeyv2_fd` — single PF_KEY socket
- `pfkeyv2_pid` — session PID
- `pfkeyv2_seq` — sequence counter

### XFRM (`kernel_xfrm.c:133-146`)
- `netlink_xfrm_fd` — NETLINK_XFRM socket (SA/policy ops + notifications)
- `netlink_rtm_fd` — NETLINK_ROUTE socket (interface/offload detection)
- `xfrm_direction_supported` — feature detection cache
- Async: `netlink_process_xfrm_messages()`, `netlink_process_rtm_messages()`

## 5. Key Implementation Patterns

### 5.1 SA Add (PF_KEYv2 vs XFRM)
- **PF_KEYv2** (`kernel_pfkeyv2.c:904-1179`): Construct fixed-size request buffer, append extensions in order via `put_sadb_*()`, send, read response
- **XFRM** (`kernel_xfrm.c:1611-2099`): Build `nlmsghdr` + `xfrm_usersa_info`, append netlink attributes via `nl_addattr_*()`, send/receive via `sendrecv_xfrm_msg()`

### 5.2 SPI Allocation
- **PF_KEYv2** (`kernel_pfkeyv2.c:770-857`): `SADB_GETSPI` with `SADB_EXT_SPIRANGE`, parse response `SADB_EXT_SA` for returned SPI
- **XFRM** (`kernel_xfrm.c:2777-2828`): `XFRM_MSG_ALLOCSPI` with `xfrm_userspi_info`, response is `XFRM_MSG_NEWSA` containing `xfrm_usersa_info.id.spi`

### 5.3 Policy Add
- **PF_KEYv2** (`kernel_pfkeyv2.c:1407-1855`): Two code paths — OpenBSD (`SADB_X_ADDFLOW`) vs others (`SADB_X_SPDADD`/`SPDUPDATE`), using `sadb_x_policy` + `sadb_x_ipsecrequest` extensions
- **XFRM** (`kernel_xfrm.c:910-1143`): `XFRM_MSG_UPDPOLICY` with `xfrm_userpolicy_info` + `XFRMA_TMPL` array for encapsulation templates

## 6. Design Recommendations for Racoon Migration

1. **Define `kernel_ops` interface struct** — mirror LibreSwan's pattern with function pointers for SA and policy lifecycle
2. **XFRM backend** — implement netlink message construction, attribute encoding, and response parsing
3. **Socket abstraction** — replace PF_KEY socket init with dual netlink sockets (XFRM + ROUTE)
4. **Async notifications** — implement netlink multicast listener for `XFRM_MSG_ACQUIRE`/`EXPIRE`/`POLEXPIRE`
5. **Feature detection** — probe kernel capabilities at init (directional SA, IPTFS, migrate)
6. **Backend selection** — runtime config-driven selection via `kernel_stacks[]` array pattern