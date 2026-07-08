# strongSwan Build Conventions & XFRM Header Analysis Report

**Date:** 2026-07-08
**Purpose:** Inform racoon-ipsec-tools packaging modernization (issue #60) and cross-check the LibreSwan survey's kernel-header conclusions against a real autotools-based IPsec daemon
**Scope:** strongSwan `configure.ac`/autotools conventions, default config file installation, systemd integration mechanics, and a literal "5 commands" build attempt
**Source:** `git clone --depth 1 https://github.com/strongswan/strongswan.git` at commit `3ef0918` (2026-07-06), built in-container

---

## 1. Default /etc configuration files

**Summary:** strongSwan installs `strongswan.conf`, `ipsec.conf`, and `ipsec.secrets` as *active* configs unconditionally on `make install` — there is no LibreSwan-style `.example`/`INSTALL_CONFIGS=true` two-tier gate. The only safety net is an idempotent `test -e ... || install` guard that refuses to clobber a file that already exists (upgrade-safe, not fresh-install-cautious). Paths are fully `--sysconfdir`-driven and `make install` genuinely stages them (verified below), not left to packaging.

- Canonical sources: `conf/strongswan.conf` (`conf/strongswan.conf`), `src/starter/ipsec.conf`, `src/starter/ipsec.secrets` — plain files, not `.in` templates (no `@VAR@` placeholders inside).
- Install rule for the classic files, `src/starter/Makefile.am:59-70`:
  ```
  install-exec-local :
      test -e "$(DESTDIR)${sysconfdir}/ipsec.d" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)/ipsec.d" || true
      ...
      test -e "$(DESTDIR)$(sysconfdir)/ipsec.conf" || $(INSTALL) -m 644 $(srcdir)/ipsec.conf $(DESTDIR)$(sysconfdir)/ipsec.conf || true
      test -e "$(DESTDIR)$(sysconfdir)/ipsec.secrets" || $(INSTALL) -m 600 $(srcdir)/ipsec.secrets $(DESTDIR)$(sysconfdir)/ipsec.secrets || true
  ```
  Note the `0600` mode on secrets — matches the LibreSwan convention exactly.
- Install rule for `strongswan.conf`, `conf/Makefile.am:188-194` — same `test -e || install` idiom, targeting `$(strongswan_conf)` which defaults to `${sysconfdir}/strongswan.conf` (`configure.ac:44`, `ARG_WITH_SUBST([strongswan-conf], [${sysconfdir}/strongswan.conf], ...)`).
- **strongSwan additionally installs read-only *template* copies** of every config to `$(pkgdatadir)/templates/config/...` (`conf/Makefile.am:9-11`, `templatesdir = $(pkgdatadir)/templates/config`) — this is the closest strongSwan gets to LibreSwan's `.example` tier, but it runs in parallel with (not instead of) installing the live file, and there is no flag to suppress the live-file install.
- Confirmed empirically: a zero-flag `make install DESTDIR=...` staged `usr/local/etc/strongswan.conf` *and* `usr/local/share/strongswan/templates/config/strongswan.conf` in the same run (see §5). With `--enable-stroke` it also staged `usr/local/etc/ipsec.conf` and `usr/local/etc/ipsec.secrets`.

**Applicability to racoon-ipsec-tools:** strongSwan does **not** give us a stronger precedent than LibreSwan here — if anything it's a weaker packaging-hygiene model (unconditional live-file install, no opt-out flag). Racoon's own two-tier plan (informed by the LibreSwan survey) remains the better convention to adopt. The one genuinely reusable idea is the parallel "install a read-only template *and* the live file" pattern, and the `test -e || install` idempotent-install guard so re-running `make install` on upgrade never clobbers an edited config.

---

## 2. Kernel header handling — cross-check against LibreSwan's findings

**Summary: strongSwan does the opposite of what the task's framing assumed.** It does **not** rely on system headers by default — it vendors `linux/xfrm.h` (and four other `linux/*.h` files) in-tree at `src/include/linux/`, and a `-I${linux_headers}` compiler flag defaulting to that in-tree copy is prepended *ahead of* every other include path in every plugin that touches XFRM. This is long-standing, deliberate policy (documented back to strongSwan 4.1.2, ~2007), not a recent workaround, and it structurally resembles LibreSwan's *pre-SNAFU* default (`USE_XFRM_HEADER_COPY=true`) rather than its current one.

### 2.1 The vendored headers exist and are the default

`src/include/Makefile.am:1`:
```
EXTRA_DIST = linux/if_alg.h linux/ipsec.h linux/netlink.h linux/rtnetlink.h \
             linux/pfkeyv2.h linux/udp.h linux/socket.h linux/xfrm.h sys/queue.h
```
`src/include/linux/xfrm.h` is 583 lines, structurally a full copy of the kernel UAPI header (`#ifndef _LINUX_XFRM_H`, byte-for-byte kernel struct/enum layout).

The directory is selected via a real `--with-` option, `configure.ac:59`:
```
ARG_WITH_SUBST([linux-headers],      [\${top_srcdir}/src/include], [set directory of linux header files to use])
```
This *is* strongSwan's answer to racoon's `--with-kernel-headers=PATH` (see §2.4) — except the **default value is strongSwan's own bundled copy**, not the system's `/usr/include`.

That default is then wired into the compiler flags of every module that includes `<linux/xfrm.h>`, e.g. `src/libcharon/plugins/kernel_netlink/Makefile.am:1-2`:
```
AM_CPPFLAGS = \
	-I${linux_headers} \
	-I$(top_srcdir)/src/libstrongswan \
	...
```
`-I${linux_headers}` is listed *first*, so on a stock `./configure` (no `--with-linux-headers=...` override) it shadows whatever `/usr/include/linux/xfrm.h` the build host actually has, for every one of the eight files that use it: `src/starter/Makefile.am:15`, `src/libstrongswan/plugins/af_alg/Makefile.am:2`, `src/libcharon/Makefile.am:159`, `kernel_netlink/Makefile.am:2`, `kernel_pfroute/Makefile.am:2`, `socket_default/Makefile.am:2`, `socket_dynamic/Makefile.am:2`, `kernel_pfkey/Makefile.am:2`.

### 2.2 Rationale, on the record since 2007

`NEWS` (strongswan-4.1.2 entry):
```
- Removed the dependencies from the /usr/include/linux/ headers by
  including xfrm.h, ipsec.h, and pfkeyv2.h in the distribution.
```
This is an explicit, ~19-year-old design decision to *eliminate* the system-header dependency entirely, for portability across distros/cross-compilation targets whose installed kernel-headers package might be old, missing, or absent (Android, embedded cross-builds — see `Android.mk` at repo root).

### 2.3 The bundled header does contain "future" constants used unconditionally — same shape as the LibreSwan SNAFU, mitigated differently

`src/include/linux/xfrm.h` already defines kernel-6.8/6.14-era identifiers: `XFRM_SA_DIR_IN`/`XFRM_SA_DIR_OUT` (line 141-142), `XFRM_MODE_IPTFS` (line 157), `XFRMA_SET_MARK`/`XFRMA_IF_ID`/`XFRMA_SA_DIR`/`XFRMA_SA_PCPU`/`XFRMA_IPTFS_*` (lines 316-328). `src/libcharon/plugins/kernel_netlink/kernel_netlink_ipsec.c` references these **unconditionally at compile time** — e.g. `XFRMA_SA_DIR` at line 1386, `XFRMA_IF_ID` at lines 2124/2339/2455/2568/2650/3175/3396/3590, `XFRM_MODE_IPTFS` at line 804 — exactly the "identifier must exist at compile time even though runtime use is gated" pattern that caused LibreSwan's 2025 SNAFU (`bd9de77cba`).

strongSwan avoids that specific failure mode not by gating the constants but by controlling *both sides*: because its own header is the default and takes include-path priority, there's no scenario (absent an explicit `--with-linux-headers=/usr/include` override) where the compiled binary's idea of these constants and the header's idea of them diverge. The risk LibreSwan hit — "distro's real headers were up to date and correct, but ours were experimental/wrong" — can't arise unless a user deliberately points `--with-linux-headers` at system headers older than what the code needs. That is a real residual risk of the *override* path, but it is opt-in, whereas LibreSwan's SNAFU was in the (accidentally wrong) default.

### 2.4 No `AC_CHECK_DECLS`/`AC_CHECK_HEADERS` gating for XFRM constants — only for unrelated things

Contrary to the task's premise, strongSwan's **only** `AC_CHECK_DECLS` invocation in the entire `configure.ac` (`configure.ac:1334-1338`) is for `libbfd` backtrace symbols, not XFRM/netlink:
```
AC_CHECK_DECLS(
	[bfd_section_flags, bfd_get_section_flags,
	 bfd_section_vma, bfd_get_section_vma,
	 bfd_section_size, bfd_get_section_size], [], [],
	[[#include <bfd.h>]])
```
For kernel/netlink feature probing, strongSwan instead uses hand-rolled `AC_COMPILE_IFELSE` snippets that compile a tiny test program and `AC_DEFINE` a `HAVE_*` macro on success — e.g. `configure.ac:795-810` (`IPSEC_MODE_BEET`), `:814-829` (`IPSEC_DIR_FWD`), and `:833-842` (`RTA_TABLE`):
```
AC_MSG_CHECKING([for RTA_TABLE])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <sys/socket.h>
		  #include <linux/netlink.h>
		  #include <linux/rtnetlink.h>]],
		[[int rta_type = RTA_TABLE;
		  return rta_type;]])],
	[AC_MSG_RESULT([yes]);
	 AC_DEFINE([HAVE_RTA_TABLE], [], [have netlink RTA_TABLE defined])],
	[AC_MSG_RESULT([no])]
)
```
These three checks exist precisely *because* those particular headers (BSD `netipsec/ipsec.h`/`netinet6/ipsec.h`, or `linux/rtnetlink.h` on old glibc) are **not** in strongSwan's bundled set — they're the genuine "we don't control this header, probe for it" cases, and they use `AC_COMPILE_IFELSE` rather than `AC_CHECK_DECLS`. Functionally this is the same idea the LibreSwan report recommended (`AC_CHECK_DECLS([XFRMA_IF_ID, ...])`), just a more verbose, older autoconf idiom. Both are directly adaptable to racoon's `configure.ac`; `AC_CHECK_DECLS` is the more concise of the two and is what we'd recommend racoon actually use.

### 2.5 Minimum kernel version

No explicit "minimum kernel X.Y" statement exists anywhere (`INSTALL`, `README.md`, `configure.ac` comments all searched). `INSTALL:121-136` ("4. Kernel configuration") only lists required modules (`esp4`, `esp6`, `xfrm_user`) and notes `xfrm4_tunnel`/`xfrm4_mode_tunnel` "for older kernels" — consistent with, but not a precise corroboration of, the LibreSwan report's 2.6.25 ABI-stability claim. `NEWS` has scattered version-gated feature notes going back to kernel 2.6.16/2.6.17/2.6.20/2.6.21 (AES-XCBC, IPv4-in-IPv6 tunnels, MOBIKE), which is broadly consistent with "core XFRM has been usable and stable since the mid-2.6 series."

**Applicability to racoon-ipsec-tools:**
1. **Do not adopt strongSwan's vendoring-by-default model.** It works for strongSwan because bundling is unconditional and universal (no per-distro toggle to get wrong), but it means every strongSwan build ships a header that can silently drift from the running kernel's actual capabilities — acceptable for strongSwan's XFRM feature breadth, unnecessary for racoon's narrower IKEv1 ESP/AH/NAT-T/AEAD/ESN surface, all ABI-stable since 2.6.25 per the LibreSwan report. That conclusion is **not contradicted** by anything found here — strongSwan vendors for portability/cross-compilation reasons unrelated to ABI stability, not because system headers are unreliable for the constructs racoon needs.
2. **Use `AC_CHECK_DECLS`** (not `AC_COMPILE_IFELSE` snippets) for any post-4.15 optional XFRM constant racoon might reference — this is more concise than strongSwan's own idiom and was already the LibreSwan report's recommendation; nothing here should change that.
3. strongSwan's `--with-linux-headers` is a real precedent for an override-style flag, but note it defaults to strongSwan's *own tree*, not the system — so it is not actually analogous to racoon's `--with-kernel-headers=PATH` (which points at an external headers directory with no vendored fallback). Racoon dropping `--with-kernel-headers` post-migration remains a reasonable simplification; strongSwan's option doesn't argue for keeping an equivalent, since racoon has no vendored copy for it to fall back to.

---

## 3. Default build-time option set

**Summary:** strongSwan's `./configure` with zero flags builds a comparatively minimal plugin set — modern `vici`/`swanctl` control plane, `kernel-netlink`, OpenSSL crypto, no EAP methods, no `stroke`/`ipsec.conf` classic config path, no systemd unit. Plugins are individually registered in `configure.ac` (no directory auto-discovery); adding one is a `configure.ac` + `Makefile.am` change, not a drop-in.

### 3.1 The two enable/disable macros and their default polarity

`m4/macros/enable-disable.m4:5-20` (`ARG_ENABL_SET`) creates `--enable-X`, defaulting the feature to **false**; `ARG_DISBL_SET` (same file, second half) creates `--disable-X`, defaulting to **true**. This polarity is the entire story for "what's on by default":

- **On by default** (`ARG_DISBL_SET`): `kernel-netlink` (`:224`), `socket-default` (`:230`), `vici` (`:237`), `updown` (`:249` region), `xauth-generic`, `openssl` crypto plugin (`:153`), `revocation`, `resolve`, `attr`, `pki`.
- **Off by default** (`ARG_ENABL_SET`, i.e. opt-in): every EAP method (`eap-identity`, `eap-md5`, `eap-gtc`, `eap-mschapv2`, `eap-tls`, `eap-ttls`, `eap-peap`, `eap-tnc`, `eap-dynamic`, `eap-radius`, all listed `:200-212`), `stroke` (`:234`), `systemd` (`:301`), `nm`, `svc`, `cert-enroll`, TNC plugins, most attribute/misc plugins.

Confirmed empirically (§5): a zero-flag build reports
```
libstrongswan: random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pgp dnskey sshkey pem openssl pkcs8 xcbc cmac kdf drbg
libcharon:     attr kernel-netlink resolve socket-default vici updown xauth-generic counters
```
No `stroke`, no EAP plugin, no `swanctl`/`starter` classic config path enabled by name (it does build `swanctl` — the modern CLI — since `swanctl` itself is a separate, on-by-default component, distinct from the `stroke` plugin).

### 3.2 NAT-T is not a plugin at all

There is no `--enable-natt`/`--disable-natt` switch. NAT-T support is unconditional core `charon` behavior; the only configurable knobs are the UDP port numbers (`configure.ac:108-121`, `--with-charon-natt-port=port`, default 4500). This is a structural difference worth naming plainly: strongSwan doesn't treat NAT-T as optional the way racoon's `--enable-natt` does — it's baked into the one IKE daemon core, not a pluggable unit.

### 3.3 Plugin registration is static, not discovered

`m4/macros/add-plugin.m4:4-10` (`ADD_PLUGIN`) is an m4 macro invoked once per plugin, statically listing which components (`s`/`charon`/`swanctl`/`pki`/...) get it, e.g. `configure.ac:1581`:
```
ADD_PLUGIN([openssl],              [s charon swanctl pki scripts manager medsrv attest nm cmd aikgen fd])
```
There is no directory-scan of `src/libcharon/plugins/*` at configure time — every plugin needs (a) an `ARG_ENABL_SET`/`ARG_DISBL_SET` line, (b) an `ADD_PLUGIN` line, (c) a `src/.../plugins/<name>/Makefile.am`, and (d) an entry in the relevant `AC_CONFIG_FILES` list (`configure.ac:1997-2150`, ~150 individual `Makefile` paths). This is real, non-trivial ceremony per plugin.

**Applicability to racoon-ipsec-tools — architecture note, not a recommendation to adopt it:** strongSwan's plugin architecture is powerful (compile-time-selectable feature set at fine granularity) but its cost is exactly this per-plugin registration ceremony across four files. Racoon's monolithic `--enable-natt`/`--enable-frag` style is structurally simpler for a codebase of racoon's size and feature count, and nothing here suggests racoon should move toward a plugin model — that would be a rewrite of racoon's module boundaries, not an incremental packaging change, and is out of scope for the packaging-modernization issue. The one thing racoon's `configure.ac` legitimately *can* borrow is the disable/enable default-polarity convention itself (`ARG_ENABL_SET`-style macros) if it wants a consistent, self-documenting pattern for its existing individually-optional deps (krb5/ldap/pam) — a naming/structure convention, not a plugin system.

---

## 4. systemd integration — mechanics

**Summary: the task's assumption that strongSwan uses `config.status`/`AC_CONFIG_FILES` (real autoconf substitution) for `.service` templates is contradicted by the source.** `.service.in` → `.service` substitution happens via a hand-rolled `sed` recipe **inside `Makefile.am`, at `make` time** — mechanically the same category of thing as LibreSwan's `TRANSFORMS`/Makefile-sed approach, not a `configure`-time substitution. Systemd unit-directory *detection*, similarly, is a raw `pkg-config --variable` shell call, not `PKG_CHECK_VAR` — though `PKG_CHECK_VAR` does exist and is genuinely used elsewhere (for D-Bus), proving the macro is available and working in this codebase. There is no sysusers.d/tmpfiles.d integration anywhere in strongSwan. There is no non-systemd init fallback (no SysV/OpenRC scripts) — disabling/lacking systemd means no init integration ships at all.

### 4.1 Where the units live, and how substitution actually happens

Three service files exist, all `.in`:
- `init/systemd/strongswan.service.in` — modern `charon-systemd`/`swanctl` daemon unit.
- `init/systemd-starter/strongswan-starter.service.in` — classic `ipsec.conf`/`starter`-based unit (the one structurally analogous to what racoon would want).
- `src/cert-enroll/cert-enroll.service.in` (+ a `.timer`) — unrelated cert-enrollment helper.

`init/systemd-starter/Makefile.am` (full file):
```
EXTRA_DIST = strongswan-starter.service.in
CLEANFILES = strongswan-starter.service

systemdsystemunit_DATA = strongswan-starter.service

strongswan-starter.service : strongswan-starter.service.in
	$(AM_V_GEN) \
	sed \
	-e "s:@SBINDIR@:$(sbindir):" \
	-e "s:@IPSEC_SCRIPT@:$(ipsec_script):" \
	$(srcdir)/$@.in > $@
```
This is a plain Makefile rule invoking `sed` — it runs during `make`, driven by `automake`'s `_DATA` install-list mechanism, **not** by `AC_CONFIG_FILES`/`config.status` at `./configure` time. Confirmed by checking every `AC_CONFIG_FILES` block in `configure.ac` (`:1997-2032` and `:2211-2241`, two blocks, ~150 files total): every single entry is either a `Makefile` or a man-page (`.5`, `.8`, `.1`) — **zero** `.service` or `.timer` files appear in either list. Man pages *do* go through real configure-time substitution; systemd units deliberately do not. This is a genuine, verifiable nuance the task specifically asked us to check, and it comes out the opposite of what was assumed.

### 4.2 systemd unit directory detection: raw pkg-config call, not `PKG_CHECK_VAR`

`configure.ac:74-77`:
```
if test -n "$PKG_CONFIG"; then
	systemdsystemunitdir_default=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
fi
ARG_WITH_SET([systemdsystemunitdir], [$systemdsystemunitdir_default], [directory for systemd service files])
AC_SUBST(systemdsystemunitdir)
```
This is a direct shell capture of `pkg-config --variable=...`, wrapped only in autoconf's `$PKG_CONFIG` variable (itself set up by the `PKG_PROG_PKG_CONFIG` macro elsewhere) rather than autoconf's dedicated `PKG_CHECK_VAR` macro. It's then fed as the *default* for a normal `ARG_WITH_SET` option, so `--with-systemdsystemunitdir=PATH` overrides it.

`PKG_CHECK_VAR` **is** used correctly elsewhere in the same file, proving it's available and idiomatic in this codebase — just applied to D-Bus, not systemd (`configure.ac:83`):
```
[PKG_CHECK_VAR([dbusdatadir], [dbus-1], [datadir], , [dbusdatadir="${datarootdir}"])
 dbuspolicydir="${dbusdatadir}/dbus-1/system.d"]
```
**For racoon:** `PKG_CHECK_VAR([systemdsystemunitdir], [systemd], [systemdsystemunitdir], [], [systemdsystemunitdir="${prefix}/lib/systemd/system"])` is the more modern, more idiomatic equivalent of what strongSwan does with the raw shell call — worth using `PKG_CHECK_VAR` directly rather than copying strongSwan's shell-capture idiom verbatim, since strongSwan itself proves the macro works fine for exactly this kind of variable lookup.

### 4.3 `--enable-systemd`/`--disable-systemd`, and what "disabled" actually means

`configure.ac:301`: `ARG_ENABL_SET([systemd], [enable systemd specific IKE daemon charon-systemd.])` — **off by default**, opt-in. This flag gates only the *modern* `charon-systemd` daemon + its unit (`AM_CONDITIONAL(USE_SYSTEMD, test x$systemd = xtrue)`, `configure.ac:1914`).

The *classic* unit's install is gated independently, by whether `pkg-config` found systemd at all — **not** by `--enable-systemd**:
```
AM_CONDITIONAL(USE_LEGACY_SYSTEMD, test -n "$systemdsystemunitdir" -a "x$systemdsystemunitdir" != xno)   # configure.ac:1915
AM_CONDITIONAL(USE_FILE_CONFIG, test x$stroke = xtrue)                                                    # configure.ac:1893
```
and `init/Makefile.am`:
```
if USE_LEGACY_SYSTEMD
if USE_FILE_CONFIG
if USE_CHARON
  SUBDIRS += systemd-starter
endif
endif
endif

if USE_SYSTEMD
if USE_SWANCTL
  SUBDIRS += systemd
endif
endif
```
So: the ipsec.conf-style unit needs `systemd.pc` present on the build host **and** `--enable-stroke** (not `--enable-systemd`); the swanctl-style unit needs `--enable-systemd` **and** `--enable-swanctl` (on by default). Confirmed empirically in §5: a zero-flag build with systemd.pc present installed *neither* unit (because `stroke` defaults off); rebuilding with `--enable-stroke` alone (still no `--enable-systemd`) installed `usr/lib/systemd/system/strongswan-starter.service` plus `ipsec.conf`/`ipsec.secrets`.

**No fallback when systemd is unavailable.** If `pkg-config systemd` finds nothing, `configure.ac:1059-1064` hard `AC_MSG_ERROR`s only when `$systemd = xtrue` or `$cert_enroll_timer = xtrue` was explicitly requested; otherwise `USE_LEGACY_SYSTEMD` is simply false and `init/`'s `SUBDIRS` stays empty — no SysV init script, no OpenRC service, nothing is installed. This is a real, notable difference from LibreSwan, which has distro-specific SysV/OpenRC fallbacks in `mk/defaults/linux.mk`.

### 4.4 No sysusers.d / tmpfiles.d anywhere

An exhaustive search (`grep -rn "sysusers\|tmpfiles" configure.ac Makefile.am init/ src/`) returns nothing. strongSwan has no fragment, template, or configure-time detection for either mechanism — it manages any needed runtime directories (e.g. PID/socket dirs) through its own C code and installer scripts, not systemd's declarative helpers.

**Applicability to racoon-ipsec-tools:**
1. Racoon's own instinct to use `AC_CONFIG_FILES`/`config.status` for real configure-time `.service.in` substitution, if that's the current plan, is **more rigorous than either LibreSwan or strongSwan** — neither project actually does this for systemd units; both use Makefile-time `sed`. This is not a reason to abandon the more rigorous approach; if anything it's a reason to document that racoon is choosing a cleaner mechanism than either precedent.
2. Use `PKG_CHECK_VAR` for `systemdsystemunitdir` detection — it's the correct, idiomatic macro, and strongSwan's own (different) use of it for D-Bus confirms it's the intended tool for exactly this kind of pkg-config-variable-into-configure-default pattern.
3. Gating the systemd unit behind whether `systemd.pc` is found (à la strongSwan's `USE_LEGACY_SYSTEMD`), independent of a separate `--enable-systemd` opt-in flag, is a reasonable, low-friction pattern: it means "if your build host has systemd's pkg-config data, you get the unit for free," which matches how most users actually want packaging to behave.
4. No sysusers.d/tmpfiles.d precedent exists in strongSwan to borrow from; racoon is on its own here (or should look to a project that actually does this, which is out of scope for this survey).
5. There is no SysV/OpenRC fallback precedent worth copying — if racoon wants to support non-systemd inits, strongSwan offers nothing to adapt.

---

## 5. "5 Commands" cleanliness check — actually run

**Summary:** strongSwan supports the literal 5-command flow, but **not "for free" on a bare build host** — it silently requires `flex` and `gperf` that are neither checked for gracefully nor documented as prerequisites, and `./configure` failing over to a no-op `LEX=:` when `flex` is absent produces a confusing downstream compile error rather than a clear configure-time failure. Once those two tools are present, all 5 commands succeed cleanly with zero extra flags. `make check` passed 47/48 suites; the one failure is a socket/stream test that looks like a sandboxed-container networking restriction, not a strongSwan defect.

| Step | Command run | Result |
|---|---|---|
| 1 | `./autogen.sh` (= `autoreconf -i` per `autogen.sh:3`) | **Clean, zero flags.** No warnings besides normal libtoolize/automake file-install chatter. |
| 2 | `./configure` (zero flags) | **Clean on the first attempt** — exit 0, no errors, no missing-dependency messages, in ~1s. Enabled plugin set: `libstrongswan: random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pgp dnskey sshkey pem openssl pkcs8 xcbc cmac kdf drbg` / `libcharon: attr kernel-netlink resolve socket-default vici updown xauth-generic counters`. |
| 3 | `make -j$(nproc)` | **Failed** on first attempt: `cc1: fatal error: settings/settings_lexer.c: No such file or directory` (`make[5]: *** [Makefile:2294: settings/settings_lexer.lo] Error 1`). Root cause: `flex` was not installed; `configure` silently set `LEX = :` (a no-op) in the generated Makefile instead of erroring — confirmed via `grep '^LEX = ' src/libstrongswan/Makefile` → `LEX = :`. After `apt-get install -y flex` and **re-running `./configure`** (`LEX` then correctly resolved to `flex`), `make -j$(nproc)` succeeded, exit 0. `gperf` was also missing up front (`apt-get install -y gperf` before the first `./configure` run) — this one *is* caught, but only as `AC_MSG_ERROR` at build/generation time, not a hard configure-time requirement, per `configure.ac:388-414` (`# because gperf is not needed by end-users we only abort if generated files don't exist`). |
| 4 | `make check` | **47 of 48 'libstrongswan' suites passed.** The one failure: `Running suite 'stream'` → `Failure in 'test_sync': service != NULL (suites/test_stream.c:65, i = 2)` (and same for `test_async`/`test_all`/`test_concurrency`). This is a loopback/socket-service test iterating multiple transport types (`i = 2` selects one specific `services[]` entry in `test_stream.c`); the failure pattern (service creation returning `NULL` only for one specific transport index) is consistent with a sandboxed container lacking some socket/address-family capability (e.g. restricted IPv6 or abstract-namespace sockets) rather than a strongSwan logic bug — 47/48 suites, including all crypto/ASN.1/threading suites, passed outright. |
| 5 | `make install DESTDIR=/tmp/strongswan-test-install` | **Clean, exit 0**, zero flags beyond `DESTDIR`. Staged 151 files under `usr/{bin,sbin,lib,libexec,etc,share}`. With the default (`--enable-stroke` **not** passed) configuration, `usr/local/etc/{ipsec.conf,ipsec.secrets}` and any systemd unit were **absent** — because `stroke` and `systemd` both default off (§3, §4). Rebuilding with `--enable-stroke` (still zero systemd flag) and reinstalling to a fresh `DESTDIR` staged `usr/local/etc/ipsec.conf`, `usr/local/etc/ipsec.secrets`, **and** `usr/lib/systemd/system/strongswan-starter.service` automatically (§4.3) — confirming the racoon-relevant build is `./configure --enable-stroke`, not the bare default. |

**Honest comparison to racoon's own `-Wno-old-style-definition` wart:** strongSwan's `configure.ac` builds with `-Werror -Wall -Wextra` plus a long list of `-Wno-*` suppressions baked into every Makefile.am (`-Wno-format -Wno-format-security -Wno-implicit-fallthrough -Wno-missing-field-initializers -Wno-pointer-sign -Wno-sign-compare -Wno-type-limits -Wno-unused-parameter`, visible in every compile line in the build log) — i.e., strongSwan carries a comparable (in fact longer) list of warning suppressions than racoon's single `-Wno-old-style-definition`. This is not a point in favor of "strongSwan is cleaner"; it's the same category of accumulated-warning-suppression debt, just spread across more flags.

**Applicability to racoon-ipsec-tools:** The real, portable lesson is **document (and ideally `AC_CHECK_PROG`-gate) `flex`/`gperf`-class build-time code generators explicitly and fail loudly at configure time**, rather than letting `LEX=:` silently defer the failure to a confusing `make`-time "file not found" error deep in a build log. If racoon's build ever grows a generated-source step (parser, lexer, gperf-based table), this is a concrete anti-pattern to avoid, learned from watching strongSwan's own configure hit it. Otherwise, the "5 commands" flow for strongSwan (with `--enable-stroke` for the racoon-comparable feature set) is genuinely clean — a much better precedent than LibreSwan's non-existent autotools flow, and a validation that this flow is realistic to hold racoon to.

---

## 6. Agreement/disagreement with the LibreSwan report

| Topic | LibreSwan report conclusion | strongSwan finding | Verdict |
|---|---|---|---|
| **Kernel-header ABI stability (2.6.25) for IKEv1 XFRM** | Core XFRM structs/messages stable since 2.6.25; racoon shouldn't vendor headers | strongSwan states no specific minimum kernel version, but its NEWS/module list is consistent with very old-kernel support; its **own** rationale for vendoring is portability/cross-compilation (Android, missing headers), not "system headers are ABI-unreliable" | **Confirmed, no contradiction.** Neither project's reasons for touching kernel headers relate to ABI instability in the 2.6.25+ core racoon needs. |
| **Vendor headers or not** | LibreSwan: vendoring is opt-in per-distro, default `false`, and got it *wrong* once (2025 SNAFU) by bundling experimental constants | strongSwan: vendoring is **unconditional and default-on** for a wider set of headers, has done so since 2007, and *also* unconditionally references not-yet-universal constants (`XFRMA_SA_DIR`, `XFRM_MODE_IPTFS`) compile-time — same shape of risk as LibreSwan's SNAFU, but insulated because the vendored copy is always authoritative unless a user explicitly overrides `--with-linux-headers` | **Adds nuance, does not contradict.** Two different mature IPsec daemons independently arrived at "vendor our own copy" for reasons unrelated to racoon's actual requirement (basic IKEv1 ESP/AH ABI stability). This is a mild *counterpoint* to "just don't vendor" as a blanket rule — but the counterpoint applies to daemons with XFRM feature surfaces reaching into 6.8+/6.14+ territory (IPTFS, directional SAs), which racoon's kernelpaws IKEv1 backend does not need. Racoon's narrower target keeps the LibreSwan report's "don't vendor, gate optional features" recommendation intact. |
| **`AC_CHECK_DECLS` for post-4.15 features** | Recommended as the mechanism racoon should use (LibreSwan report's own suggestion, since LibreSwan itself has no autoconf) | strongSwan uses `AC_CHECK_DECLS` exactly once, for `libbfd`, not for XFRM; its XFRM/netlink-adjacent probes use the older `AC_COMPILE_IFELSE` + `AC_DEFINE(HAVE_X)` idiom instead | **Confirms the mechanism is sound and idiomatic** (a real autotools project uses this exact pattern-family for exactly this purpose), but the **specific macro** LibreSwan's report guessed (`AC_CHECK_DECLS`) is not what strongSwan happens to use for XFRM. Recommend racoon still prefer `AC_CHECK_DECLS` — it's more concise and equally proven within the same codebase (for `bfd.h`). |
| **`--with-kernel-headers=PATH`-style option — keep or drop?** | Not addressed (LibreSwan has no such flag; not autotools) | strongSwan **does** have `--with-linux-headers=PATH` (`configure.ac:59`), but its default points at strongSwan's *own* vendored tree, not the system — so it's not a precedent for "point at an external headers dir with no bundled fallback," which is what racoon's current flag does | **New information, mild disagreement with a naive reading.** A superficial glance says "see, a mature autotools daemon keeps this flag, racoon should too." The substance says the opposite: strongSwan's flag exists *because* it vendors by default and needs an escape hatch from its own bundle; racoon (per the LibreSwan-report conclusion, unchanged here) shouldn't vendor at all, so it has no bundle to need an escape hatch from, and the flag becomes pure surface area with no default it's protecting. Recommend racoon still drop it post-migration. |
| **systemd unit substitution: `config.status`/autoconf vs. Makefile-time `sed`** | Not addressed (LibreSwan uses a bespoke `TRANSFORMS` Makefile mechanism, not autoconf) | strongSwan — despite being genuinely autotools-based — **also** uses Makefile-time `sed` for `.service.in` files, not `AC_CONFIG_FILES`/`config.status` | **Important correction to an assumption in this task's own framing.** The task described strongSwan's mechanism as "real autoconf substitution... rather than LibreSwan's custom TRANSFORMS mechanism" — that is not what the source shows. Both projects use the same *category* of mechanism (Makefile-driven `sed`/text substitution at build time); strongSwan's version is just a plainer, one-off `sed` invocation instead of a named `TRANSFORMS` abstraction. If racoon's plan is to use genuine `AC_CONFIG_FILES` substitution for its `.service.in`, that would be **more rigorous than both precedents**, not merely "matching strongSwan" — worth stating explicitly rather than assuming parity. |
| **`PKG_CHECK_VAR` for systemd variables** | Not addressed | strongSwan uses a raw `$PKG_CONFIG --variable=...` shell capture for `systemdsystemunitdir` (`configure.ac:74`), but genuinely uses `PKG_CHECK_VAR` elsewhere for `dbusdatadir` (`configure.ac:83`) | **Partial confirmation.** The macro is real, present, and correctly used in this exact codebase — just not for the systemd variable the task most wanted an example of. Recommend racoon use `PKG_CHECK_VAR` for `systemdsystemunitdir`/`sysusersdir`/`tmpfilesdir` directly; it is more idiomatic than the shell-capture pattern strongSwan happens to use for that one variable, and strongSwan's own D-Bus usage proves it works fine for this exact kind of lookup. |
| **sysusers.d/tmpfiles.d** | Recommended as something LibreSwan does and racoon could adopt | strongSwan has **none** of this — no sysusers.d, no tmpfiles.d, anywhere | **No new precedent, no contradiction.** LibreSwan remains the only one of the two surveyed projects with anything to borrow here. |
| **Config file two-tier model** | LibreSwan: `.example` always + `INSTALL_CONFIGS=true` gate for active configs | strongSwan installs active configs unconditionally (idempotent `test -e || install` only), plus a parallel always-installed template copy under `pkgdatadir` | **Weaker precedent than LibreSwan, no contradiction of the recommendation.** Racoon should keep following LibreSwan's two-tier model over strongSwan's unconditional-install approach. |

**Bottom line:** strongSwan corroborates the LibreSwan report's core kernel-ABI conclusion (nothing here suggests kernel 2.6.25+ XFRM structures are unstable, and strongSwan's own vendoring is driven by portability/cross-compilation concerns, not ABI risk) while **correcting** two specific mechanical assumptions this task's framing carried in — that strongSwan uses real autoconf substitution for systemd units (it doesn't; same Makefile-`sed` category as LibreSwan) and that it uses `PKG_CHECK_VAR` for systemd detection specifically (it doesn't; that macro is used, but for D-Bus). Both corrections still leave racoon's likely intended design (genuine `AC_CONFIG_FILES`/`PKG_CHECK_VAR` usage) as the *more* rigorous choice among all three projects surveyed, not a step down to parity with precedent.
