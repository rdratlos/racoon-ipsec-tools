# Racoon / ipsec-tools in Embedded Networking: A Software-Archaeology Report

**Date:** 2026-07-09
**Purpose:** Document the historical adoption, propagation, and current status of the KAME Racoon IKE daemon / ipsec-tools within embedded networking products (router SDKs, OEM firmware, ISP CPE), for citation in racoon-ipsec-tools project documentation.
**Scope:** Public evidence only — vendor GPL portals, GitHub/SourceForge mirrors of vendor GPL releases, upstream project history, and direct source-level diffing of two primary trees.
**Method:** Four-phase study — (1) discovery via targeted web/GitHub search, (2) evidence collection into a structured SQLite database, (3) source-level diffing of downloaded GPL-release files against each other and against this repository's own git history, (4) this narrative synthesis. Raw evidence is in `racoon_evidence.db` (4 tables, 55 sources, 55 findings, 10 file comparisons, 14 cataloged patches) and is available on request; this report cites specific rows/URLs inline rather than reproducing the whole database.
**Status:** First draft. Confidence levels are stated per claim; see §7 for the measured/estimated distinction and §8.5 for explicit gaps.

---

## 1. Executive Summary

Racoon originated inside the KAME project (WIDE Project, Japan) as a BSD-licensed IKEv1 keying daemon, ported to Linux by Derek Atkins and formalized as the SourceForge project **ipsec-tools** after KAME stepped back from maintaining it. Ipsec-tools shipped six tagged releases between 2007 and 2014 (0.7 → 0.8.2), was formally marked **ABANDONED** by its own maintainers on its SourceForge landing page, and development continued only inside NetBSD's CVS tree and in scattered independent forks (this repository among them).

Despite that abandonment, this study finds direct, source-level evidence that racoon/ipsec-tools shipped in embedded networking products spanning at least **2005 through 2014** in original-vendor form, plus continued packaging/patching activity in at least one Intel-maintained embedded Linux build system and this project's own fork through the 2020s. The clearest evidence comes from two independently-derived GPL source trees that were downloaded and diffed line-by-line in this study:

- **ASUS** (Ralink AP SDK lineage) shipped **unmodified, stock ipsec-tools 0.8.0**, matching the official 2011-03-18 release almost to the day.
- **Actiontec** (Broadcom bcm963xx DSL SoC SDK lineage) shipped an **unmodified, pre-release CVS snapshot from mid-2005 to mid-2006** — a full year or more before ipsec-tools' first tagged release — apparently frozen at that point and never rebased.

The single most consequential finding of this study is negative: **neither tree contains vendor-authored patches to racoon's source.** Features the original research brief expected to find as "downstream vendor modifications" — XAUTH, Cisco Unity/Hybrid-auth, NAT-T — are stock upstream ipsec-tools features present in both trees by 2006, not vendor patches. Hardware crypto offload, also expected, architecturally cannot appear in racoon's source at all: racoon only negotiates keys over PF_KEY, and encryption happens in the kernel. The one genuine vendor-authored source patch found in this study belongs to **Apple** (a Darwin/macOS-specific `auto_exit_delay` config directive, for GUI-driven on-demand VPN control), not to any router/gateway OEM.

Where this study *does* find real, verifiable convergent modification is in **post-abandonment maintenance**: this repository's own git history independently fixed the same two CVEs (CVE-2015-4047, CVE-2016-10396) and two of the same portability defects found in Intel's `luv-yocto` Yocto-layer patch set — evidence that multiple unrelated maintainers have kept patching the same abandoned codebase against the same finite pool of known defects, not evidence of patch-sharing between trees.

Adoption breadth beyond the two directly-diffed trees rests on weaker evidence: of 22 OEM vendors investigated, only 2 (ASUS, Actiontec) have direct, high-confidence, product-specific source-tree confirmation; a further 2 (Linksys/WRT54G-era, via the DD-WRT/Tomato/OpenWrt lineage) have medium-confidence historical confirmation. Seven vendor/product findings are **confirmed absent** — most notably two independently-checked Zyxel GPL trees, which contain no ipsec-tools/racoon package at all. For the remaining ~15 named vendors, this study found an active GPL-compliance portal and circumstantial plausibility (Linux-based firmware, ipsec-tools being a standard ecosystem package) but no product-specific artifact — these should be read as **open questions**, not as adoption.

---

## 2. Historical Timeline

| Date | Event | Evidence |
|---|---|---|
| 1995–1998 | WIDE Project (KAME) begins racoon development as part of its BSD IPsec stack; original copyright headers in racoon source read "Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project." | Copyright headers, all racoon source files inspected in this study |
| ~2000–2001 | Racoon reaches usable maturity on NetBSD/FreeBSD/BSD/Mac OS X; ported to Linux by Derek Atkins. | [kame.net/racoon](https://www.kame.net/racoon/), [FreshPorts](https://www.freshports.org/security/ipsec-tools/) |
| mid-2005 – mid-2006 | A CVS snapshot of racoon from this window (confirmed via RCS `$Id$` tags: `2005-07-01` through `2006-06-12` across `Makefile.am`, `crypto_openssl.c`, `grabmyaddr.c`, `isakmp.c`, `isakmp_cfg.c`, `cfparse.y`, `isakmp_xauth.c`, `pfkey.c`) is captured — apparently by, or for, the Broadcom bcm963xx DSL SoC reference SDK — and later ships unmodified in Actiontec's V1000H GPL release. | This study, §5 below; `scratchpad/phase3/actiontec/*.c` RCS tags |
| KAME announces it will stop maintaining racoon | KAME hands racoon's release process to a new formal team. | [KAME project — Wikipedia](https://en.wikipedia.org/wiki/KAME_project) |
| 2006-09-15 | ipsec-tools CVS is imported into NetBSD's own source tree (`crypto/dist/ipsec-tools`), which becomes the long-term upstream-of-record after SourceForge development stalls. | [ipsec-tools.sourceforge.net](https://ipsec-tools.sourceforge.net/) |
| 2007-08-29 | **ipsec-tools 0.7** — first tracked SourceForge release. | SourceForge release table (this study, Phase 2) |
| 2008-06-24 | ipsec-tools 0.7.1 | ibid. |
| 2009-04-22 | ipsec-tools 0.7.2 | ibid. |
| 2011-03-18 | **ipsec-tools 0.8.0** — confirmed shipped essentially unmodified in ASUS's Ralink-SDK-based DSL-N series GPL release (RCS tags dated 2011-03-14/15). | This study, §5; [smx-smx/asuswrt-rt](https://github.com/smx-smx/asuswrt-rt) |
| 2013-01-08 | ipsec-tools 0.8.1 | SourceForge release table |
| 2014-02-27 | **ipsec-tools 0.8.2 — final upstream release.** SourceForge page subsequently marked the project **[PROJECT ABANDONED]**, stating "ipsec-tools has security issues, and you should not use it." | [ipsec-tools.sourceforge.net](https://ipsec-tools.sourceforge.net/) |
| 2015 | CVE-2015-4047 (null pointer dereference crash in racoon) disclosed. | Patch catalogue (this study); independently fixed in this repo (`23a56f8`) and in Intel's `luv-yocto` (`fix-CVE-2015-4047.patch`) |
| 2016 | CVE-2016-10396 (remotely exploitable DoS via ISAKMP fragmentation) disclosed. | Independently fixed in this repo (`b1fea9b`, with a follow-up correction at `7fc4152`) and in Intel's `luv-yocto` (`fix-CVE-2016-10396.patch`) |
| post-2016 | Multiple unrelated parties continue patching the abandoned 0.8.2 codebase for modern toolchains (OpenSSL 1.1, GCC 8, clang, musl libc, glibc 2.20) and residual defects — this is packaging-level maintenance, not upstream development. | Intel `luv-yocto` recipe (14 patches cataloged); this repository's own git history |
| 2018 | LEDE merges back into OpenWrt; no separate ipsec-tools lineage to track thereafter. | Inference from OpenWrt/LEDE merger history (not separately verified in this study) |
| 2026 (this study) | No evidence found of active upstream ipsec-tools development; racoon/ipsec-tools survives as (a) a still-installable OpenWrt/DD-WRT feed package of uncertain current-default status, (b) community forks including this repository, and (c) whatever already-deployed embedded devices from the 2005–2014 window remain in service and unpatched. | This study, §6 |

---

## 3. Adoption Matrix

Confidence and presence values are taken directly from `racoon_evidence.db`. **"Confirmed" here means a specific artifact was directly opened and inspected in this study** (source file, directory listing, or explicit release-page statement) — not that the claim is false otherwise. Absence of a row's confirmation is an open question, not a negative finding, unless the Presence column says `confirmed_absent`.

| Vendor | Product Family | Years (evidence-derived) | SDK | Presence | Confidence | Evidence |
|---|---|---|---|---|---|---|
| **ASUS** | DSL-N10/12/14/16/17/55/66U (Ralink-based DSL modems) | ~2011 (matches 0.8.0 release) | Ralink AP SDK | confirmed_present | **High** | [smx-smx/asuswrt-rt](https://github.com/smx-smx/asuswrt-rt/blob/master/apps/public/ipsec-tools-0.8.0/src/racoon/plainrsa-gen.c) — full source, diffed in this study |
| **Actiontec** | V1000H DSL Gateway (firmware 31.121L.11) | Racoon vintage 2005–2006; product firmware era ~2011–2013 | Broadcom bcm963xx GPL SDK | confirmed_present | **High** | [vicgarin/Actiontec-V1000H](https://github.com/vicgarin/Actiontec-V1000H) — full source, diffed in this study |
| **Linksys** | WRT54G (and the DD-WRT/Tomato/OpenWrt lineage it seeded) | 2003 GPL-compliance episode; DD-WRT/Tomato IPsec support documented through 2020s | Broadcom (historical) | confirmed_present (indirect — third-party derivative firmware, not confirmed in stock Linksys firmware) | **Medium** | [LinuxInsider](https://www.linuxinsider.com/story/43996.html); OpenWrt/DD-WRT/Tomato secondary anchors (§4) |
| **Google (Android/AOSP)** | Built-in L2TP/IPsec VPN client | Eclair (2009) → KitKat (2013)+ | AOSP `external/ipsec-tools` | confirmed_present | **High** | [android.googlesource.com](https://android.googlesource.com/platform/external/ipsec-tools/) |
| **Apple** | macOS/Darwin IPsec/L2TP VPN client | ongoing (exact end date not established) | Darwin (`aosm/ipsec`) | confirmed_present, **plus a verified vendor-authored patch** (`auto_exit_delay`) | **High** | [Apple-FOSS-Mirror/ipsec](https://github.com/Apple-FOSS-Mirror/ipsec); this study §5 |
| **Intel** | LUV (Linux Utilities for Verification) Yocto validation layer — not a shipping product | patches applied post-2016 (CVE-2015-4047/2016-10396 fixes present) | Yocto/OpenEmbedded | confirmed_present | **High** | [intel/luv-yocto](https://github.com/intel/luv-yocto) |
| **Zyxel** | PMG5617GA (OPAL, OpenWrt-14.07-derived GPON ONT) | n/a | OpenWrt 14.07-derived | **confirmed_absent** | **High** | Full `package/` directory enumerated (54 entries) — no ipsec-tools/racoon | 
| **Zyxel** | EX5601-T0 (OpenWrt-21.02-derived, MediaTek MT7986) | n/a | OpenWrt 21.02-derived | **confirmed_absent** (at vendored-package level; feeds/ mechanism not fully expanded) | **Medium** | Top-level `package/` directory enumerated (18 entries) — no vendored ipsec-tools/racoon |
| **Realtek** | 11nRouter/Jungle SDK v3.4.9.3 | n/a | Realtek SDK | **confirmed_absent** (at inspection depth reached) | **Medium** | [vankel/rtl819x-SDK](https://github.com/vankel/rtl819x-SDK) — top-level tree/README show no reference |
| **Buffalo** | LinkStation (NAS) | n/a | — | **confirmed_absent** (stock kernel; IPsec documented as a user addition) | **Medium** | [NAS-Central Buffalo wiki](http://buffalo.nas-central.org/wiki/IPSec-VPN_on_Stock_Kernel) |
| **DrayTek** | Vigor 2500 / 2820Vn | n/a | proprietary | **confirmed_absent** (DrayTek uses a proprietary IKE stack; documented interop friction with racoon, not adoption) | **Medium** | [rigacci.org](https://www.rigacci.org/wiki/doku.php/doc/appunti/linux/sa/ipsec_draytek); [FedoraForum](https://forums.fedoraforum.org/archive/index.php/t-258048.html) |
| **AVM** | FRITZ!Box | n/a | — | **confirmed_absent** as current guidance (community interop tooling has shifted to strongSwan; internal AVM implementation never confirmed to be racoon in the first place) | **Low–Medium** | [xinux.net Racoon-fritz](https://www.xinux.net/index.php/Racoon-fritz) (historical), current community strongSwan-first guidance |
| TP-Link | (unspecified — portal only) | — | — | plausible | Low | [GPL Code Center](https://www.tp-link.com/us/support/gpl-code/) confirmed active; no product artifact opened |
| D-Link | (unspecified — portal only) | — | — | plausible | Low | [GPL Source Code Support](https://tsd.dlink.com.tw/gpl2008.asp) confirmed active; no product artifact opened |
| NETGEAR | (unspecified — portal + bulk archive) | — | — | plausible / unresolved | Low | [GPL portal](https://kb.netgear.com/2649/NETGEAR-Open-Source-Code-for-Programmers-GPL); [archive.org bulk mirror](https://archive.org/details/netgear-gpl-source) not yet searched |
| Belkin | (unspecified — portal only) | — | — | plausible | Low | [Open Source Code Center](https://www.belkin.com/support-article/?articleNum=51238) |
| Trendnet | (unspecified — portal only) | — | — | plausible | Low | [GPL Source Code](https://www.trendnet.com/support/gpl-source-codes.asp) |
| Qualcomm/Qualcomm Atheros | QSDK products | — | QSDK (OpenWrt-derived) | plausible (inherited via OpenWrt lineage, not confirmed shipping) | Low | [CodeLinaro QSDK wiki](https://wiki.codelinaro.org/en/clo/qsdk/overview) |
| Sercomm / Arcadyan | ISP 5G/FTTH gateways (e.g. T-Mobile Home Internet) | 2023 hardware, software stack unconfirmed | iopsys (plausible) | unresolved | Low | [Senki.org ISP CPE supply chain](https://www.senki.org/us-isp-cpe-supply-chain/); [tmo.report](https://tmo.report/2023/08/its-here-the-new-t-mobile-home-internet-gateway/) |
| MikroTik | RouterOS | — | closed-source | unresolved (likely to remain so absent binary analysis) | Low | [MikroTik IPsec docs](https://help.mikrotik.com/docs/spaces/ROS/pages/11993097/IPsec) — generic "IKE daemon" language only |
| Ubiquiti | EdgeRouter/EdgeOS | — | Debian-based | unresolved (current docs point to strongSwan) | Low | [Ubiquiti Community](https://community.ui.com/questions/EdgeRouter-Lite-1-6-0-Firmware-and-Source-and-Kernel-Module-Woes/1049dd3a-60f7-4151-931d-1836269f58d0) |
| Teltonika | RUT9xx cellular routers | — | — | unresolved | Low | [xvaara/tlt_rut9xx](https://github.com/xvaara/tlt_rut9xx) GPL mirror identified, package/ contents not resolved |
| Cavium | OCTEON-based platforms (incl. some MikroTik hardware) | — | Cavium OCTEON SDK | plausible | Medium | [Springer academic paper](https://link.springer.com/chapter/10.1007/978-3-642-25283-9_3) pairs racoon with OCTEON HW crypto in a research implementation, not a confirmed shipping product |
| Marvell, Lantiq/MaxLinear, Planet, Gemtek, Sagemcom | — | — | — | **no evidence found** | — | Explicit gap; see §8.4 |

---

## 4. SDK Genealogy

```
KAME (racoon, BSD-licensed, WIDE Project, 1995-1998 origin)
  │
  ├── CVS/SourceForge lineage ──────────────────────────────┐
  │                                                           │
  ▼                                                           ▼
ipsec-tools (SourceForge, formal successor,          [Untagged CVS snapshot, 2005-07-01 .. 2006-06-12]
 tagged releases 0.7 .. 0.8.2, 2007-2014,                     │   captured for/by the Broadcom bcm963xx
 marked ABANDONED after 0.8.2)                                │   DSL/PON reference SDK
  │                                                            │
  ├─▶ NetBSD CVS (crypto/dist/ipsec-tools) ── still the       ▼
  │    nominal upstream-of-record today                Broadcom bcm963xx DSL SoC GPL SDK
  │                                                            │   (frozen at this snapshot in every
  ├─▶ Apple/Darwin (aosm/ipsec) ──▶ macOS IPsec/L2TP client    │    file checked; no evidence of ever
  │    + auto_exit_delay patch (verified vendor addition,      │    rebasing to a later tagged release)
  │      GUI/on-demand VPN control integration)                │
  │                                                             ▼
  ├─▶ Android AOSP (external/ipsec-tools) ──▶ built-in       Actiontec V1000H DSL Gateway
  │    L2TP/IPsec VPN client, Eclair (2009) → KitKat (2013)+  (VERIFIED: same racoon snapshot, unmodified)
  │                                                             │
  ├─▶ ipsec-tools 0.8.0 (tagged, 2011-03-18) ──▶              ⋮ (untested hypothesis: other bcm963xx-
  │    Ralink AP SDK ──▶ ASUS Ralink-based DSL-N series          licensee ODM/ISP gateways may carry the
  │    (VERIFIED: unmodified stock 0.8.0, no vendor patches)     identical frozen snapshot — bcm963xx was
  │                                                                a long-lived, widely-relicensed reference
  ├─▶ OpenWrt feeds/packages net/ipsec-tools                     design; not directly tested in this study)
  │    (Makefile + racoon.init/racoon.conf, corroborated
  │    across 3 independent mirrors: kismetwireless,
  │    dragino, iopsys)
  │      ├──▶ QSDK (OpenWrt-derived) ──▶ Qualcomm Atheros products (plausible, unconfirmed)
  │      ├──▶ iopsys (ISP-CPE OpenWrt fork) ──▶ Sercomm/Arcadyan-built gateways (plausible, unconfirmed)
  │      └──▶ DD-WRT (installable via ipkg from OpenWrt feeds; not shown to be default-compiled)
  │      Note: Zyxel's own OpenWrt-14.07- and OpenWrt-21.02-derived GPL trees do NOT carry
  │      ipsec-tools as a vendored package — inheriting from OpenWrt is not automatic.
  │
  ├─▶ Tomato / TomatoUSB / FreshTomato ──▶ community-patched racoon+xl2tpd L2TP/IPsec
  │    (stock Tomato ships no IPsec by default; this is a third-party addition, not vendor-shipped)
  │
  └─▶ Post-abandonment (2014+) independent forks, all patching the same finite set of
       known defects without evidence of sharing patches with each other:
         - this repository (rdratlos/racoon-ipsec-tools): CVE-2015-4047, CVE-2016-10396,
           libfl linkage cleanup, packed-struct pointer-alignment fix
         - intel/luv-yocto: same two CVEs, plus OpenSSL 1.1/clang/musl/gcc8/glibc-2.20
           portability patches
         - opencoff/ipsec-tools, pld-linux/ipsec-tools: mirrors/repackagings, not
           independently diffed for patch content in this study
```

**Reading this diagram:** there are two structurally different propagation mechanisms visible in the verified evidence. (1) **Snapshot-and-freeze**, exemplified by the Broadcom bcm963xx lineage: a chipset/SoC vendor takes one CVS/release snapshot into a reference SDK, and that exact snapshot then propagates to every OEM/ODM that licenses the SDK, indefinitely, because userspace VPN daemons are not something SoC reference-design maintainers routinely revisit. (2) **Ecosystem inheritance**, exemplified by OpenWrt: ipsec-tools is a standing feed package that any OpenWrt-derived SDK (QSDK, iopsys, vendor GPL trees "based on openwrt-NN.NN") *could* inherit by simply not removing it — but, as the two directly-checked Zyxel trees show, this inheritance is **not automatic**: a vendor can build on top of OpenWrt and still ship zero trace of ipsec-tools if they never enable/vendor the package.

---

## 5. Downstream Patch Catalogue

### 5.1 What was *not* found (correcting the study's own starting assumptions)

The original research brief expected to catalogue vendor patches for Cisco Hybrid Authentication, XAUTH, NAT-T, certificates, GUI integration, watchdog integration, logging changes, and hardware crypto support. Direct source diffing of the two available primary trees (ASUS/Ralink, Actiontec/Broadcom) found:

- **Zero vendor-authored modifications** to `isakmp.c`, `pfkey.c`, `crypto_openssl.c`, `localconf.c`, `isakmp_xauth.c`, `isakmp_cfg.c`, `cfparse.y`, `grabmyaddr.c`, or `Makefile.am` in either tree (grep for vendor/hardware tokens returned no matches in any file).
- **XAUTH, Cisco Unity, and Hybrid-mode support are stock upstream features**, present by upstream filename (`isakmp_xauth.c`, `isakmp_unity.c`, `isakmp_cfg.c`) in the *2006* Actiontec snapshot already — i.e., merged into mainline racoon well before any of the OEM trees studied here branched off. Any vendor claiming "we added Cisco VPN compatibility" was, at most, choosing to bundle a codebase that already had it.
- **NAT-T** (`nattraversal.c`, `isakmp_frag.c`) is likewise stock-and-unmodified in both trees.
- **Hardware crypto offload cannot appear in racoon's own source** as a matter of architecture: racoon negotiates Security Associations over PF_KEY; ESP/AH encryption executes in the kernel. Any hardware-crypto integration for a Broadcom bcm963xx or similar SoC would live in the kernel IPsec/crypto driver, not in racoon — a scope correction relevant to any future phase that goes looking for it in the wrong layer.

### 5.2 What *was* found: Apple's `auto_exit_delay`

Apple's `Sample/Embedded/racoon.conf` (`aosm/ipsec`) defines an `auto_exit_delay` timer directive, commented "for use when controlled by VPN socket." This token is verified **present** in Apple's own `cfparse.y` grammar (wired through to `lcconf->auto_exit_delay`) and verified **absent** from both independent stock grammars checked (ASUS 2011, Actiontec 2006). This is the one directly-confirmed vendor-authored racoon source patch in this study, and it is OS-integration-specific (macOS's on-demand/GUI-driven VPN control), not a router/gateway-vendor pattern.

Separately, Apple's use of the stock `include "/var/run/racoon/*.conf"` directive — to let the macOS System Configuration framework inject per-connection config snippets without restarting racoon — is a distinctive **deployment pattern**, though the `include` mechanism itself is a stock upstream token (confirmed present in both router-SDK grammars, so it is not an Apple invention).

### 5.3 Post-abandonment maintenance patch catalogue (Intel `luv-yocto`, 14 patches)

| Patch | Addresses | Also found in this repo's git history? |
|---|---|---|
| `fix-CVE-2015-4047.patch` | Null pointer dereference crash in racoon | **Yes** — `23a56f8` |
| `fix-CVE-2016-10396.patch` | Remotely exploitable DoS via ISAKMP fragmentation | **Yes** — `b1fea9b`, with a follow-up correction at `7fc4152` |
| `0002-Don-t-link-against-libfl.patch` | Removes unnecessary flex-library link dependency | **Yes** — `a0557aa` |
| `racoon-check-invalid-pointers.patch` | Guards against unaligned/invalid pointer access on packed structs | **Yes** — `b1513b4` |
| `0001-ipsec-tools-add-openssl-1.1-support.patch` | OpenSSL 1.1 opaque-struct API compatibility | Not matched in a targeted search |
| `0001-Fix-build-with-clang.patch` | Clang compiler compatibility | Not matched |
| `0001-Fix-header-issues-found-with-musl-libc.patch` | musl libc header compatibility | Not matched |
| `0001-Disable-gcc8-specific-warnings.patch` | GCC 8 warnings-as-errors suppression | Not matched |
| `0002-cfparse-clear-memory-equal-to-size-of-array.patch` | memset/array-size mismatch in config parser | Not matched |
| `glibc-2.20.patch` | glibc 2.20 compatibility | Not matched |
| `configure.patch` | Build configuration adjustments (scope unspecified) | Not matched |
| `racoon-pfkey-avoid-potential-null-pointer-dereferenc.patch` | Null-pointer guard in PF_KEY handling | Not matched (may overlap conceptually with CVE-2015-4047 fix; not confirmed as a separate defect) |
| `racoon-Resend-UPDATE-message-when-received-EINTR-message.patch` | Retransmit logic fix for EINTR-interrupted sends | Not matched |
| `racoon-check-invalid-ivm.patch` | Validates IV material before use | Not matched |

**4 of 14 patches (29%) are independently corroborated** by this repository's own unrelated maintenance history — real evidence that the abandoned codebase has drawn convergent, independent fixes from at least two unconnected parties for the same defects, most notably both publicly-disclosed CVEs. This is the strongest, most directly falsifiable evidence this study obtained for "identical [problem, if not identical patch] appearing in multiple independent trees" (Research Question 5). It says more about the shared, finite set of known defects in an abandoned C codebase than about any patch-sharing relationship between Intel and this project.

---

## 6. Current Ecosystem (2026)

Distinguishing carefully between categories, per the original brief's requirement:

- **Actively maintained:** No evidence found of active *upstream* ipsec-tools/racoon development (SourceForge project explicitly abandoned since 2014). This repository (`rdratlos/racoon-ipsec-tools`) and `intel/luv-yocto` both show maintenance activity (CVE fixes, portability patches) into the post-2016 era, which qualifies as **actively maintained forks**, not an actively maintained upstream project.
- **Legacy but shipping:** Any device built on the ASUS Ralink DSL-N-series or Actiontec bcm963xx firmware lineages documented in §3 that remains in field service is, by definition, running racoon/ipsec-tools today, with no upstream security fixes applied since at minimum 2011–2014 (ASUS) or 2005–2006 (Actiontec) — the Actiontec case in particular predates both cataloged CVEs. This is an inference from the confirmed firmware-vintage evidence, not a device-census claim; this study did not attempt to estimate how many such devices remain deployed.
- **Abandoned:** The upstream ipsec-tools project itself (SourceForge, 2014). Racoon2 (the distinct WIDE-Project successor codebase) showed no evidence of recent activity in this study, though it was not investigated in depth.
- **Confirmed non-adopters / migrated away:** DrayTek (proprietary IKE stack throughout), and — based on current community/vendor documentation rather than historical usage — AVM FRITZ!Box and Ubiquiti EdgeOS interoperability guidance now centers on **strongSwan**, not racoon. MikroTik RouterOS's IKE daemon identity remains unresolved (closed-source).
- **Migration paths (Research Question 7):** The pattern that emerges from this study's incidental findings — not a dedicated investigation — is a broad shift toward **strongSwan** as racoon/ipsec-tools' successor across the contexts touched by this study (AVM/FRITZ!Box community tooling, Ubiquiti EdgeOS current docs). This is consistent with strongSwan's active upstream maintenance versus ipsec-tools' 2014 abandonment, but a proper treatment of "competing implementations" (Research Question 7) was out of scope for this phase and would need its own evidence pass — this study's own sibling documents (`docs/research/strongswan-build-conventions-report.md`, `docs/research/libreswan-build-conventions-report.md`) are relevant prior art for that follow-up.

---

## 7. Statistical Summary

Values marked **[measured]** come directly from `racoon_evidence.db` query results in this study. Values marked **[estimated]** are the report author's inference and should not be cited as measured facts.

- Sources catalogued: **55** [measured]
- Findings catalogued: **55** [measured], of which 29 confirmed_present, 11 plausible, 8 unresolved, 7 confirmed_absent [measured]
- Confidence distribution: 20 High, 16 Medium, 19 Low [measured, from Phase 2]
- Distinct named vendors investigated: **22** [measured, count of distinct `vendor` values in `findings`]
- Distinct SDKs/platforms investigated: **~19** [measured, count of distinct `sdk` values in `findings`; some entries are near-duplicates of the same SDK named slightly differently across sources]
- Vendors with **direct, product-specific, high-confidence source-tree confirmation**: **2** (ASUS, Actiontec) [measured]
- Vendors with **confirmed absence** of ipsec-tools/racoon in an inspected GPL tree: **4** (Realtek, Buffalo, Zyxel ×2 products) [measured]
- Files diffed at content level across independent trees: **10** [measured, `file_comparisons` table]
- Patches catalogued from a single post-abandonment maintenance tree (Intel `luv-yocto`): **14**, of which **4 (29%)** independently corroborated in this repository's own history [measured]
- Years of confirmed embedded deployment (earliest confirmed racoon snapshot vintage to latest confirmed release use): **~2005–2014** [measured, from RCS tags and release dates directly inspected]
- Years of any embedded deployment activity, including circumstantial/plausible evidence: **~2003 (Linksys WRT54G GPL episode) – present** [estimated — the upper bound assumes some fraction of "plausible" vendor rows are real and unretired, which this study did not verify]
- Estimated number of vendors that plausibly used ipsec-tools somewhere in their product history, if every "plausible"-confidence row in the adoption matrix is real: **on the order of 15–20** [estimated, explicitly unverified — see §8.5]

---

## 8. Conclusions

### 8.1 Historical significance

Racoon/ipsec-tools was, for roughly a decade (mid-2000s to 2014), a default-available, GPL/BSD-licensed IKEv1 implementation that any Linux- or BSD-based embedded network device could bundle essentially for free, with Cisco-interoperable XAUTH/Hybrid-mode support already built in. That combination — free, GPL-compatible, functionally complete for the era's common VPN use cases (site-to-site PSK, Cisco-client remote access, L2TP/IPsec) — plausibly explains its reach into at least two structurally different SDK ecosystems (Ralink/MediaTek AP SDK, Broadcom bcm963xx DSL SDK) and two very different classes of vendor (a mainstream consumer router brand and a telco-channel DSL gateway ODM), as directly confirmed in this study, on top of its confirmed presence in Apple's Darwin/macOS stack and Google's Android/AOSP stack — arguably its largest-scale deployment by device count, though this study did not attempt to quantify that.

### 8.2 Reasons for adoption (inferred, not separately evidenced)

No source in this study explicitly states *why* a given vendor chose racoon/ipsec-tools over alternatives (FreeS/WAN, Openswan, or a proprietary stack). The plausible explanation supported by the surrounding evidence — GPL/BSD licensing compatible with GPL Linux kernels, completeness of feature set for the era, and its bundling into widely-relicensed chipset reference SDKs — is an inference, not a documented vendor decision.

### 8.3 Reasons for decline

Directly evidenced: upstream abandonment in 2014, an explicit "you should not use it" warning from the project's own maintainers, and at least two significant CVEs (2015, 2016) disclosed after that abandonment. Plausibly contributing, but not directly evidenced in this study: IKEv2's rise as the modern standard (racoon/ipsec-tools is IKEv1-only), and the availability of actively-maintained alternatives (strongSwan, Libreswan) that this study's sibling reports already document as having stronger, ongoing upstream investment.

### 8.4 Evidence supporting continued relevance in 2026

Continued relevance is real but narrow, per the evidence gathered:
- **Legacy deployment risk**: any never-updated device built on the confirmed 2005–2014 firmware lineages in §3 is a live, unpatched attack surface today — a security-relevant fact even without a device census.
- **Continued fork maintenance**: this project and Intel's `luv-yocto` both show real, independent maintenance activity well past 2016, which is direct evidence the codebase is not purely a historical artifact.
- **No evidence of new adoption**: nothing in this study suggests any vendor is *newly* adopting racoon/ipsec-tools today; all confirmed adoption evidence is historical (2005–2014).

### 8.5 Explicit gaps and recommended next steps

This study directly diffed only **two** OEM trees at the source-content level; the "no vendor patches" and "frozen snapshot" findings are demonstrated for those two, not proven industry-wide. Specific, actionable follow-ups:
1. Pull a **second, unrelated bcm963xx-based GPL release** (different OEM, different year) and check whether its racoon RCS tags match Actiontec's exactly — this would convert the "long-lived frozen snapshot propagated broadly" hypothesis from plausible to confirmed (or falsify it).
2. Directly inspect the **NETGEAR bulk GPL archive** on Internet Archive and the **iopsys feed** (blocked by a 403 in this study's tooling; needs an alternate access method) — both are flagged as high-value, not-yet-opened targets.
3. Close the **15 "plausible"-confidence vendor rows** (TP-Link, D-Link, Netgear, Belkin, Trendnet, Buffalo, and others) by pulling actual per-model GPL archives, following the same method used successfully for ASUS/Actiontec/Zyxel in this study.
4. A dedicated **Research Question 7 pass** (competing implementations / migration reasons) — this study's strongSwan/AVM/Ubiquiti observations were incidental, not a systematic investigation, and this project's own existing `strongswan-build-conventions-report.md` / `libreswan-build-conventions-report.md` are a natural starting point.
5. Realtek, Marvell, Lantiq/MaxLinear, Qualcomm QSDK, Planet, Gemtek, Sercomm, Arcadyan, and Sagemcom remain **no-evidence-either-way** gaps, not confirmed negatives — worth flagging clearly in any downstream citation of this report so silence isn't misread as "did not adopt."

---

## Appendix: Source data

Full evidence backing every claim above is in `racoon_evidence.db` (SQLite, 4 tables) and its CSV/JSON exports, produced during Phases 2–3 of this study. Raw diffed source files are preserved under the study's working directory (`scratchpad/phase3/{upstream,asus,actiontec}/`) for reproducibility but are not part of this repository's tracked history.
