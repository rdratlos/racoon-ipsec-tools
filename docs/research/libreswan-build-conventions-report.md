# LibreSwan Build Conventions & XFRM Header Analysis Report

**Date:** 2026-07-08
**Purpose:** Inform racoon-ipsec-tools packaging modernization (RFC-0002 / kernelpaws)
**Scope:** LibreSwan build system, config conventions, systemd integration, and XFRM kernel header compatibility

---

## 1. Configuration File Templates

### Template Files

- `configs/ipsec.conf.in` — Canonical default IPsec configuration
- `configs/ipsec.secrets.in` — Canonical default secrets file

### Installation Logic (`configs/Makefile`)

Two-tier installation model:

1. **Example files:** Always installed as `.example` or `.sample` to `EXAMPLE_IPSEC_SYSCONFDIR` (read-only reference)
2. **Active configs:** Installed to `SYSCONFDIR` only when user explicitly passes `INSTALL_CONFIGS=true`
3. **Secrets file:** `ipsec.secrets` is installed with mode `0600` (root-only read/write)

### Key Paths

| Variable | Purpose | Default |
|---|---|---|
| `EXAMPLE_IPSEC_SYSCONFDIR` | Read-only examples | distro-specific |
| `SYSCONFDIR` | Active config directory | `/etc` |

**Relevance to racoon:** Racoon can adopt the two-tier model — ship example configs always, install active configs conditionally.

---

## 2. Kernel Headers: Detailed Analysis

### 2.1 Vendored Headers

**Location:** `external/linux-xfrm-headers/linux/xfrm.h`
**Source:** Copied from Linux kernel source tree, `include/uapi/linux/`
**Latest version:** Linux 6.0.0rc5 (`external/linux-xfrm-headers/linux/README:7`)

**Rationale** (`external/linux-xfrm-headers/linux/README:5`):
> This assumes that the xfrm.h file always retains backwards compatibility

**Also vendored:**
- `external/linux-if-link-headers/if_link_extra.h` — Provides `IFLA_XFRM_LINK` and `IFLA_XFRM_IF_ID` enums (not in `linux/if_link.h` before kernel 4.19)
- `external/pfkeyv2/` — PFKEYv2 headers for BSD platforms
- `external/nss/` — NSS workaround headers

### 2.2 Activation Mechanism

Controlled by `USE_XFRM_HEADER_COPY`:

- **Global default:** `false` (`mk/config.mk:643`)
- **Distro overrides:** `mk/defaults/linux.mk` sets `true` for specific distros

When enabled, pluto's include path is prepended with `$(top_srcdir)/external/linux-xfrm-headers`:
```makefile
# programs/pluto/Makefile:122-124
ifeq ($(USE_XFRM_HEADER_COPY),true)
USERLAND_INCLUDES += -I$(top_srcdir)/external/linux-xfrm-headers
endif
```

### 2.3 Distro-Specific Defaults — Why Headers Are "Too Old"

The following distros have `USE_XFRM_HEADER_COPY ?= true` in `mk/defaults/linux.mk`:

| Distro | Codename | Kernel | Reason |
|---|---|---|---|
| Debian 11 | bullseye | 5.10 | System `xfrm.h` lacks 6.x constants |
| Debian 12 | bookworm | 6.1 | System `xfrm.h` lacks 6.x constants |
| Debian 13 | trixie | 6.12 | System `xfrm.h` may be incomplete |
| Ubuntu 20.04 | focal | 5.4 | System `xfrm.h` lacks 6.x constants |
| Ubuntu 22.04 | jammy | 5.15 | System `xfrm.h` lacks 6.x constants |
| Ubuntu 24.04 | noble | 6.8 | System `xfrm.h` may be incomplete |

#### What Makes System Headers "Too Old" — The Critical Issue

**The problem is not about runtime kernel capability. It's about compile-time identifier availability.**

LibreSwan's `programs/pluto/kernel_xfrm.c` references these constants **unconditionally** (no `#ifdef` guards):

| Constant | Kernel Version Added | Used In | IKEv1 Relevant? |
|---|---|---|---|
| `XFRMA_SA_DIR` | 6.8 | `kernel_xfrm.c:2050-2054` (`xfrm_add_ipsec_spi`) | **Yes — compiled unconditionally** |
| `XFRM_SA_DIR_IN` | 6.8 | `kernel_xfrm.c:2054` | **Yes — compiled unconditionally** |
| `XFRM_SA_DIR_OUT` | 6.8 | `kernel_xfrm.c:2809` (`xfrm_alloc_spi`) | **Yes — compiled unconditionally** |
| `XFRM_MODE_IPTFS` | 6.8 | `kernel_xfrm.c:1024,1038` (policy add) | **Yes — compiled unconditionally** |
| `XFRMA_IPTFS_IPSEC_IF_ID` | 6.8 | `kernel_xfrm.c:2064-2078` | **Yes — compiled unconditionally** |
| `XFRMA_IPTFS_IPSEC_DIR` | 6.8 | `kernel_xfrm.c:2064-2078` | **Yes — compiled unconditionally** |
| `XFRMA_IPTFS_IPSEC_DIR_MAX` | 6.8 | `kernel_xfrm.c:2064-2078` | **Yes — compiled unconditionally** |
| `XFRMA_IF_ID` | 4.17 | `kernel_xfrm.c:872,1973,3307` | Under `USE_XFRM_INTERFACE` |
| `XFRMA_SET_MARK` | 4.20 | `kernel_xfrm.c:875-879,1976-1982` | Under `USE_XFRM_INTERFACE` |
| `XFRMA_SET_MARK_MASK` | 4.20 | `kernel_xfrm.c:875-879,1976-1982` | Under `USE_XFRM_INTERFACE` |

**Key finding:** The 6.8 constants (`XFRMA_SA_DIR`, `XFRM_SA_DIR_IN/OUT`, `XFRM_MODE_IPTFS`, `XFRMA_IPTFS_*`) are referenced unconditionally in the code. Even though there are **runtime** feature checks that prevent these from being used on older kernels, the **identifiers must still be defined at compile time**. Without them, compilation fails.

**Example from `kernel_xfrm.c` (directional SA code):**
```c
/* Runtime check prevents execution on old kernels, but compile-time definition is still needed */
if (xfrm_direction_supported != XFRM_DIR_SUP_NO) {
    add_xfrm_attr(msg, add, XFRMA_SA_DIR, sizeof(dir), &dir);
}
```

Without `USE_XFRM_HEADER_COPY=true`, `XFRMA_SA_DIR` is undefined in system headers before kernel 6.8, and the compiler errors out.

**Constants that are vendored but NOT used by LibreSwan:**
- `XFRM_SA_XFLAG_OSEQ_MAY_WRAP` (kernel 5.16) — not referenced anywhere in source
- `XFRM_POLICY_CPU_ACQUIRE` (kernel 5.17) — not referenced anywhere in source
- `XFRMA_MTIMER_THRESH` (kernel 6.14) — not referenced anywhere in source
- `XFRMA_SA_PCPU` (kernel 6.14) — not referenced anywhere in source
- `XFRM_MSG_SETDEFAULT` / `XFRM_MSG_GETDEFAULT` (kernel 6.8) — not referenced anywhere in source

### 2.4 The 2025 SNAFU That Flipped the Default

**Commit:** `bd9de77cba` (Sep 14, 2025)

**Comment from `mk/config.mk:694-704`:**
> DO NOT ENABLE IT HERE - in 2025/5.1 there was a SNAFU where the bundled header contained experimental constants breaking systems that did have up-to-date and correct headers.

The bundled vendored `xfrm.h` had picked up experimental constants that weren't in the kernel yet, causing build failures on systems with correct, up-to-date system headers. The fix was to flip the default to `false` and selectively enable it for older distros.

**Related issues:** #2431 (default to system headers), #2396, #2501

### 2.5 Historical Timeline

| Date | Commit | Change |
|---|---|---|
| 2009 | `e4fca4cef5` | Added `kernel-headers` as build dependency |
| 2017-08 | `60ff0368a9` | Introduced `USE_XFRM_HEADER_COPY` (default `true`); reason: NIC HW offload code from `ipsec-next` not yet in mainline |
| 2022-10 | v4.8 | Updated vendored `xfrm.h` copy |
| 2025-09 | `bd9de77cba` | Flipped default to `false`; selectively enabled for Debian 11/12/13 |
| 2025-10 | `9b146ac901` | Added Ubuntu 20.04/22.04/24.04 to the `true` list |

### 2.6 BSD Fallback

BSDs don't use XFRM at all. They use PFKEYv2:

- FreeBSD: `mk/defaults/freebsd.mk:20` — `USE_PFKEYV2 = true`
- NetBSD: `mk/defaults/netbsd.mk:20` — `USE_PFKEYV2 = true`

---

## 3. Build Options (Kconfig-style, Not Autotools)

### Configuration Method

**Not autotools.** LibreSwan uses a Kconfig-style configuration system:
- `make menuconfig` — Interactive configuration
- `make oldconfig` — Update existing config
- `make` — Build

### Defaults Location

| File | Purpose |
|---|---|
| `mk/config.mk` | Global feature toggles |
| `mk/defaults/linux.mk` | Linux-specific defaults and distro detection |

### Key Toggles

| Option | Default (Linux) | Purpose |
|---|---|---|
| `USE_NATT` | `true` | NAT-Traversal support |
| `USE_XAUTH` | `true` | Extensible Authentication (IKEv1) |
| `USE_GSSAPI` | conditional | Kerberos/GSSAPI |
| `USE_NFTABLES` | `true` | nftables integration |
| `USE_XFRM` | `true` | XFRM kernel interface |
| `USE_XFRM_HEADER_COPY` | `false` | Use vendored `xfrm.h` |
| `USE_DNSSEC` | `true` | DNSSEC support |
| `USE_LINUX_AUDIT` | Fedora only | Linux audit subsystem |
| `USE_SECCOMP` | Fedora only | seccomp sandboxing |
| `USE_LABELED_IPSEC` | Fedora only | SELinux labeled IPsec |

### Distro Detection (`mk/defaults/linux.mk:7-30`)

Uses `/etc/os-release` to detect distro:
```makefile
export LINUX_VARIANT := $(sort $(shell sed -n -e 's/"//g' -e 's/^ID_LIKE=//p' -e 's/^ID=//p' /etc/os-release))
export LINUX_VERSION_CODENAME := $(sort $(shell sed -n -e 's/^VERSION_CODENAME=//p' -e 's/^UBUNTU_CODENAME=//p' /etc/os-release))
export LINUX_VERSION_ID := $(shell sed -n -e 's/^VERSION_ID=//p' /etc/os-release)
```

---

## 4. Systemd Integration

### Template Files (`initsystems/systemd/`)

| File | Purpose |
|---|---|
| `ipsec.service.in` | systemd service unit template |
| `libreswan.conf.in` | tmpfiles.d configuration template |

### Service Unit Template

**`initsystems/systemd/ipsec.service.in`:**
```ini
[Unit]
Description=Internet Key Exchange (IKE) Protocol Daemon for IPsec
Documentation=man:libreswan(7) man:ipsec(8) man:pluto(8) man:ipsec.conf(5)
Wants=network-online.target
After=network-online.target

[Service]
Type=@@SD_TYPE@@
NotifyAccess=all
Restart=@@SD_RESTART_TYPE@@
TimeoutStopSec=90s
WatchdogSec=@@SD_WATCHDOGSEC@@
ExecStartPre=@@SBINDIR@@/ipsec checknss
ExecStartPre=@@SBINDIR@@/ipsec checknflog
ExecStart=@@LIBEXECDIR@@/pluto @@SD_PLUTO_OPTIONS@@ --config @@IPSEC_CONF@@ --nofork
ExecStop=@@LIBEXECDIR@@/whack --shutdown
ExecStopPost=@@SBINDIR@@/ipsec stopnflog

[Install]
WantedBy=multi-user.target
```

Placeholders are substituted via `TRANSFORMS` during build.

### tmpfiles.d Template

**`initsystems/systemd/libreswan.conf.in`:**
```
d @@RUNDIR@@ 755 root root -
d @@IPSEC_NSSDIR@@ 700 root root -
```

### pkg-config Detection (`mk/config.mk:420-489`)

Not autotools `PKG_CHECK_MODULES`. Uses direct `pkg-config` invocation:
```makefile
PKG_CONFIG ?= pkg-config
SYSTEMUNITDIR ?= $(shell $(PKG_CONFIG) systemd --variable=systemdsystemunitdir)
SYSTEMTMPFILESDIR ?= $(shell $(PKG_CONFIG) systemd --variable=tmpfilesdir)
```

### Installation (`initsystems/systemd/Makefile`)

Key behaviors:
1. **Template substitution:** `local-base` target transforms `.in` files using `TRANSFORMS`
2. **Direct install:** `systemctl --system daemon-reload` runs when not using DESTDIR (`initsystems/systemd/Makefile:32-35`)
3. **Tmpfiles creation:** `systemd-tmpfiles --create` runs for tmpfiles.d (`initsystems/systemd/Makefile:25-28`)
4. **Old init cleanup:** Warns about and removes old SYSV init.d scripts (`oldinitdcheck` target, lines 47-58)
5. **Service status warnings:** Warns if service is disabled or needs restart after install (`postcheck` target, lines 60-77)

### Distro-Specific Init Systems (`mk/defaults/linux.mk:160`)

| Distro | Init System |
|---|---|
| Default (most) | `systemd` |
| Alpine | `openrc` |
| OpenWRT | `sysvinit` |

---

## 5. "5 Commands" Autotools Build Cycle — Result

**LibreSwan does NOT support the standard 5-command autotools flow.** The project uses a custom Makefile-based build system with Kconfig-style configuration.

| Step | Autotools Command | LibreSwan Equivalent | Result |
|---|---|---|---|
| 1 | `autoreconf -fi` | N/A | **Fails** — no `configure.ac` exists |
| 2 | `./configure --prefix=...` | `make menuconfig` / `make oldconfig` | **N/A** |
| 3 | `make` | `make` | Works |
| 4 | `make check` | `make check` | Works |
| 5 | `make install DESTDIR=...` | `make install DESTDIR=...` | Works |

### Correct LibreSwan Build Cycle

```bash
make menuconfig            # Interactive configuration (or edit Makefile.inc.local)
make                       # Build
make check                 # Tests
make install DESTDIR=/tmp/foo   # Staged install
```

### Local Overrides

User-local settings go in `Makefile.inc.local` (not committed to repo).

---

## 6. XFRM Headers & IKEv1: Implications for Racoon/Kernelpaws

### 6.1 What Kernel 4.15 Provides (Ubuntu Bionic)

Ubuntu Bionic (kernel 4.15) system headers contain all **core XFRM structures and constants** needed for basic IKEv1 ESP/AH:

| Requirement | Available in 4.15? | Notes |
|---|---|---|
| `xfrm_usersa_info` | Yes | Byte-identical to modern kernels |
| `xfrm_userpolicy_info` | Yes | Byte-identical |
| `xfrm_selector` | Yes | Byte-identical |
| `xfrm_id` | Yes | Byte-identical |
| `xfrm_userspi_info` | Yes | Byte-identical |
| `xfrm_user_tmpl` | Yes | Byte-identical |
| `xfrm_algo` / `xfrm_algo_aead` / `xfrm_algo_auth` | Yes | Byte-identical |
| `xfrm_encap_tmpl` | Yes | Byte-identical (NAT-T support) |
| `xfrm_lifetime_cfg` | Yes | Byte-identical |
| `XFRM_MSG_UPDSA` / `XFRM_MSG_DELSA` | Yes | Core SA operations |
| `XFRM_MSG_ALLOCSPI` | Yes | SPI allocation |
| `XFRM_MSG_NEWPOLICY` / `XFRM_MSG_UPDPOLICY` / `XFRM_MSG_DELPOLICY` | Yes | SPD operations |
| `XFRM_MSG_ACQUIRE` / `XFRM_MSG_EXPIRE` | Yes | Kernel notifications |
| `XFRMA_ALG_AUTH` / `XFRMA_ALG_CRYPT` / `XFRMA_ALG_AEAD` / `XFRMA_ALG_AUTH_TRUNC` | Yes | Algorithm attributes |
| `XFRMA_ENCAP` | Yes | UDP encapsulation (NAT-T) |
| `XFRMA_TMPL` | Yes | SA template list |
| `XFRMA_MARK` | Yes (kernel 3.15+) | Flow marks |
| `XFRMA_REPLAY_ESN_VAL` | Yes (kernel 2.6.39+) | Extended sequence numbers |
| `XFRMA_LTIME_VAL` | Yes | Lifetime current values |

### 6.2 What's Missing in 4.15 vs Modern Kernels

| Feature | Kernel Added | Needed for IKEv1? |
|---|---|---|
| `XFRMA_IF_ID` | 4.17 | No — only for xfrm interface binding |
| `XFRMA_SET_MARK` / `XFRMA_SET_MARK_MASK` | 4.20 | No — only for output marks |
| `XFRMA_SA_DIR` / `XFRM_SA_DIR_IN` / `XFRM_SA_DIR_OUT` | 6.8 | **No** — only for directional SA (IPTFS feature) |
| `XFRM_MODE_IPTFS` | 6.8 | **No** — only for IP-TFS (RFC 9347) |
| `XFRMA_IPTFS_*` | 6.8 | **No** — only for IP-TFS |
| `XFRM_MSG_SETDEFAULT` / `XFRM_MSG_GETDEFAULT` | 6.8 | No — not used by LibreSwan either |

### 6.3 The LibreSwan Problem (Not a Racoon Problem)

LibreSwan's `kernel_xfrm.c` references 6.8 constants unconditionally, requiring the vendored header. **Racoon doesn't have this problem** because:

1. Racoon's XFRM backend (`kernelpaws_xfrm.c`) is currently a stub — it references **no XFRM structures at all**
2. When implemented, racoon can implement these features **progressively**, only using what's available
3. Racoon can gate 6.8+ features behind runtime checks AND compile-time `#ifdef` guards, avoiding the LibreSwan problem entirely

### 6.4 Minimum Viable Kernel for IKEv1 XFRM

| Feature Set | Minimum Kernel | Notes |
|---|---|---|
| **Basic IKEv1 (ESP/AH, transport/tunnel, no marks)** | 2.6.25 | Core XFRM API stabilized |
| **IKEv1 + AEAD** | 2.6.27 | `xfrm_algo_aead`, `XFRMA_ALG_AEAD` |
| **IKEv1 + Auth Truncation** | 2.6.31 | `xfrm_algo_auth`, `XFRMA_ALG_AUTH_TRUNC` |
| **IKEv1 + ESN** | 2.6.39 | `XFRM_STATE_ESN`, `XFRMA_REPLAY_ESN_VAL` |
| **IKEv1 + Flow Marks** | 3.15 | `xfrm_mark`, `XFRMA_MARK` |
| **IKEv1 + Labeled IPsec** | 3.0 | `xfrm_sec_ctx`, `XFRMA_SEC_CTX` |
| **IKEv1 + NIC Offload** | 4.12 | `xfrm_user_offload`, `XFRMA_OFFLOAD_DEV` |
| **IKEv1 + XFRM Interface** | 4.17 | `XFRMA_IF_ID` |
| **IKEv1 + IPTFS** | 6.8 | `XFRMA_SA_DIR`, `XFRM_MODE_IPTFS`, `XFRMA_IPTFS_*` |

**Conclusion for racoon-ipsec-tools:** Ubuntu Bionic (kernel 4.15) headers are **fully sufficient** for implementing the IKEv1 XFRM backend. The kernelpaws abstraction layer only needs the structures that have been ABI-stable since kernel 2.6.25. No vendored headers are required.

### 6.5 Recommendations for Racoon

1. **Do NOT vendor xfrm.h.** Rely on system headers. The core XFRM API has been ABI-stable since kernel 2.6.25.
2. **Use `#ifdef` guards** for any post-4.15 features (marks, ESN, AEAD). Gate 6.8+ features (directional SA, IPTFS) behind both compile-time and runtime checks.
3. **Minimum target:** Kernel 4.15 (Ubuntu Bionic) provides everything needed for IKEv1 ESP/AH with NAT-T, marks, AEAD, and ESN.
4. **Consider a `pkg-config` probe** for xfrm features at configure time, analogous to how LibreSwan detects systemd:
   ```autoconf
   # Detect XFRM header version via feature macros
   AC_CHECK_DECLS([XFRMA_IF_ID, XFRMA_SET_MARK, XFRMA_SA_DIR],
                   [], [], [#include <linux/xfrm.h>])
   ```

---

## 7. Summary Table: Conventions Worth Emulating for Racoon

| Convention | LibreSwan Approach | Racoon Applicable? | Notes |
|---|---|---|---|
| Config templates (`.in` files) | `configs/ipsec.conf.in`, `configs/ipsec.secrets.in` | Yes | Already done in racoon |
| Two-tier config install | `.example` always, real configs conditional | Yes | Good packaging hygiene |
| Secrets file mode `0600` | `configs/Makefile` | Yes | Security best practice |
| Vendored kernel headers | `external/linux-xfrm-headers/` | **No** | Racoon targets 4.15+ |
| Distro detection via `/etc/os-release` | `mk/defaults/linux.mk` | Maybe | Could inform configure options |
| `pkg-config` for systemd | `mk/config.mk:488-489` | Yes | Already using `PKG_CHECK_MODULES` |
| tmpfiles.d integration | `libreswan.conf.in` | Yes | `initsystems/systemd/` |
| Old init cleanup | `oldinitdcheck` target | Yes | Warn about conflicting configs |
| Service status warnings | `postcheck` target | Yes | Post-install guidance |
| `INSTALL_CONFIGS` flag | `configs/Makefile` | Yes | Avoid overwriting user configs |

---

*Report generated from analysis of LibreSwan v5.4 (unreleased) source tree at `/home/i149635d/code/libreswan`.*