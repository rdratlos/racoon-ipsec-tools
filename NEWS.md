# NEWS

## 0.9.1 (unreleased)

This release closes a hardening phase that ran for about five weeks after
`0.9.0`: a security/availability fix for IKE fragmentation, a privilege-
separation hardening pass, a large expansion of unit-test coverage, and
the split-DNS roadwarrior hooks reaching production maturity through a
live field test and two external reviews. Full technical detail for
everything below lives in `doc/dev/v0.9.1-hardening-spec.md`.

### Security fix: IKE fragment reassembly regression (CVE-2016-10396 follow-up)

Versions up to and including 0.9.0, when configured with `ike_frag on` or
`ike_frag force`, could fail to complete a VPN connection with peers whose
IKE payload was large enough to fragment (modern DH groups, certificate
chains) whenever a fragment was lost or reordered on the wire — logging
`Repeated last fragment index mismatch` and timing out the negotiation.
The root cause was a follow-up defect in this fork's inherited
CVE-2016-10396 patch: a legitimate retransmission of the last fragment was
misclassified as a replay attack. This shipped as hotfix `0.9.0.1` and is
also merged to `develop` here. The original DoS protection is preserved
and strengthened, not weakened. If you worked around this with `ike_frag
off`, you can safely re-enable fragmentation after upgrading. See
`docs/security/2016-10396-fragment-reassembly-followup.md` for the full
advisory.

### Pre-authentication hardening

A focused security audit found and fixed several out-of-bounds reads
reachable by any peer that can send an ISAKMP packet to UDP/500, before
authentication completes — in SA transform attribute parsing, Vendor ID
handling, and IKE fragmentation cleanup — plus a handful of related
issues from an OpenSSL 3.x migration audit (timing side-channels, error
queue handling, key-material lifetime). All are fixed; no configuration
changes are needed.

### Privilege separation hardening

The privileged helper process used to exit the whole daemon on almost any
unexpected failure in a single client request. It now contains failures
per-request wherever safely possible — a malformed or refused request
fails only itself, with every wait now bounded so a stuck request can no
longer hang the daemon. This pass also fixed a PF_KEY policy gate that
had been silently blocking `racoonctl vd`/`show-sa`/DPD under privilege
separation, an `EPERM`-handling bug that could mask a real failure as
success, and a credential-handling memory leak on the admin socket that
a malformed or unmatched request could trigger repeatedly. Privilege
separation is now the packaging-documented default configuration.

### Split-DNS / roadwarrior hooks hardening

The `phase1-up.sh`/`phase1-down.sh` split-DNS and routing hooks (introduced
in 0.9.0) went through a live field test on a real roadwarrior deployment
and two rounds of external review, closing several real-world issues:
a race that could leave two concurrent connections fighting over the same
dummy network interface, additional validation for gateway-supplied DNS
servers and split-include networks, a fix for a DNS-health check that
could falsely report failure and trigger an unnecessary reconnect loop,
and a fix for the daemon occasionally not running the teardown hook at
all during shutdown. Also fixed: unreliable foreground log output under
systemd, a harmless but noisy warning logged during every phase 2
negotiation, and a case where `racoonctl vpn-disconnect` could exit
non-zero with no explanation.

### Unit test coverage

Substantially expanded unit-test coverage across the privilege-separation
code, the admin socket and session-management code, certificate-name
handling, and `racoonctl`. This is mentioned here because of what it
found along the way: six previously-unknown bugs in `racoonctl` alone
(a rejected valid connection syntax, a couple of memory leaks, an
out-of-bounds read in event/SA-dump formatting, and an uninitialized-
memory read affecting piped output), plus several smaller issues in the
privilege-separation layer — all now fixed. See the new consolidated
spec for the full list and the testing methodology behind it.

### CI and build

`develop` now has its own CI workflow, runs with AddressSanitizer/
UndefinedBehaviorSanitizer on by default on the NetBSD job, and fixed a
gap where the privilege-separation code and several wrapper-based test
modules were invisible to coverage reporting.

### K&R to ANSI C: the last old-style function definitions are gone

The entire codebase — daemon, libraries, and test suite alike — now
uses ANSI C prototypes exclusively. This matters beyond tidiness: GCC 15
(shipping on Ubuntu 25.10 "Resolute" and newer) defaults to `-std=gnu23`,
under which old-style (K&R) function definitions are no longer just a
warning but a hard compile error. Every packaging path (Debian, Arch,
and this project's own CI) that previously carried a
`-Wno-old-style-definition` workaround to route around this had that
workaround removed once it stopped being needed, and
`-Wold-style-definition` is now enabled as a hard error by default so
the codebase can't regress. Converting mechanically across roughly a
thousand function definitions also surfaced a couple of genuine, if
narrow, latent bugs — a mismatched pointer type in the admin-event
broadcast path and another in the BSD routing-socket address parser
used on NetBSD — both fixed as part of this pass. No configuration or
behavior changes for anyone already building successfully; this
primarily unblocks building on newer toolchains and distributions.

### Packaging: roadwarrior templates moved out of /usr/share/doc

Some distributions configure their package manager to silently strip
`/usr/share/doc/*` on minimal/container base images (common since
Ubuntu Jammy), keeping only `copyright`/`changelog.*`. The roadwarrior
client/server configuration templates -- the documented "which example
should I start from?" onboarding path in `racoon.conf.default` -- used
to live under `/usr/share/doc/racoon/examples/roadwarrior/`, which such
installs would delete without any error or warning, leaving that
onboarding path pointing at nothing.

They now install to their own directory,
`/usr/share/racoon/templates/roadwarrior/` by default (configurable via
the new `--with-templatesdir` to `configure`), independent of whatever
a given install does with `/usr/share/doc`. The narrower single-feature
samples (NAT-T, PlainRSA, GSSAPI, `inherit`) and the admin guide remain
under `/usr/share/doc/racoon` -- genuinely optional reading, not
something any documented workflow depends on being present.

If you have existing tooling, scripts, or documentation of your own
referencing the old
`/usr/share/doc/racoon/examples/roadwarrior/` path, update it to
`/usr/share/racoon/templates/roadwarrior/` (or your distribution's
equivalent).

## 0.9.0

Changes since `code-freeze/0.8.2+20140711-13`, the last upstream
state to reach Ubuntu Bionic and Focal. This release carries the
project forward under continued community maintenance, with a focus
on building cleanly against current OpenSSL releases and toolchains.

### OpenSSL compatibility

- Reworked `crypto_openssl.c/h` to drop the OpenSSL 0.9.8 baseline,
  require OpenSSL >= 1.1.0, and replace direct use of low-level
  RSA/DH/DES APIs with EVP-based equivalents
  (`eay_pkey_sign`/`eay_pkey_verify`), so the code no longer touches
  structures OpenSSL 3.0 hides behind deprecation warnings.
- Added `openssl_compat.c/h`, a compatibility shim covering the
  EVP_PKEY fromdata/OSSL_PARAM_BLD API
  (`EVP_PKEY_CTX_new_from_name`, `EVP_PKEY_fromdata{,_init}`,
  `EVP_PKEY_get_bn_param`, `OSSL_PARAM_BLD_*`, `EVP_PKEY_get_id`) plus
  `compat_RSA_has_private()`, `compat_RSA_dup()`,
  `compat_RSA_print_fp()`, `compat_RSA_get0_params()`,
  `compat_DES_is_weak_key()`, `compat_EVP_PKEY_get1_RSA()`, and
  `compat_EVP_PKEY_CTX_free()`, giving a single set of entry points
  that behave the same under OpenSSL 1.1.x and 3.x.
- Introduced `eayRSA`, an opaque RSA key handle backed by an
  `EVP_PKEY` (`src/racoon/eay_rsa.[ch]`), and migrated every RSA
  caller in racoon — `ph1handle`, `rsalist`, `crypto_openssl`,
  `prsa_par.y`, and `plainrsa-gen.c` — onto it, so the deprecated
  `RSA` type is no longer named anywhere in production code. On
  OpenSSL >= 3.0 construction goes through OSSL_PARAM/EVP_PKEY_fromdata,
  which stays non-deprecated through OpenSSL 4.0.
- Gated the legacy `RSA*`-based `compat_RSA_*` helpers behind
  `!OPENSSL_NO_DEPRECATED`, and added `COMPAT_RSA_KEYGEN_PUBEXP()` to
  normalize the differing BIGNUM ownership rules between
  `EVP_PKEY_CTX_set1_rsa_keygen_pubexp()` (3.0+, copies) and
  `EVP_PKEY_CTX_set_rsa_keygen_pubexp()` (pre-3.0, consumes).
- Added tooling to detect and report OpenSSL deprecation warnings
  during the build (`tools/gen_deprecation_report.py`).

### Build system

- Modernized autotools: replaced deprecated Autoconf/Automake macros
  (`AC_TRY_COMPILE`, `AC_HELP_STRING`, `AC_REPLACE_FUNCS`,
  `AC_HEADER_STDC/TIME/SYS_WAIT`, `AC_PROG_LIBTOOL`) with their
  current equivalents, bumped `AC_PREREQ` to 2.69, and moved macros
  to `m4/` via `AC_CONFIG_MACRO_DIRS`, fixing builds across GCC
  7.5–16.
- Added OS-aware rpath flag detection and an `AC_SEARCH_LIBS`-based
  `crypt(3)` lookup instead of hardcoding `-lcrypt`; added a
  configure-time check for `DES_is_weak_key`.
- Modernized the flex/bison grammar files (`policy_parse.y`,
  `cfparse.y`, `prsa_par.y`, `parse.y`) to declare token types inline,
  avoiding "ambiguous type" errors with modern bison; renamed
  setkey's `parse()` to `parse_file()` to avoid colliding with a
  bison-generated symbol.
- Stopped tracking generated files (configure, `aclocal.m4`,
  `config.h.in`, `Makefile.in`, autotools helper scripts, generated
  spec file, and flex/bison-produced lexers/parsers); building from
  git now requires autoconf/automake/libtool/flex/bison. Added a
  top-level `.gitignore` and `MAINTAINERCLEANFILES` for the affected
  Makefiles.
- Moved the ChangeLog/NEWS generation targets and `EXTRA_DIST` entries
  to `docs/history/`, where the legacy ChangeLog, ChangeLog.old, and
  NEWS files now live.
- Modified the init script's Makefile target to create `/var/run`
  on install.
- Added Valgrind test infrastructure with cross-distro suppressions,
  and unit tests covering the OpenSSL 3.0 migration code.
- Added a configure-time check that catches OpenSSL header/runtime
  library version mismatches, comparing `OPENSSL_VERSION_NUMBER` from
  the headers against `OpenSSL_version_num()` from the linked
  libcrypto; skipped when cross-compiling.
- Set `ACLOCAL_AMFLAGS` so `autoreconf` finds `m4/` explicitly instead
  of relying on default search paths.
- Fixed `.gitignore` patterns for the generated RPM specs, which
  actually live under `packaging/rpm/` (and `packaging/rpm/suse/`),
  not `rpm/`; added coverage for compiled `test/test_*` binaries and
  automake's `*.log`/`*.trs`/`test-suite.log` test-driver output.

### Packaging

- Bumped the package version to 0.9.0, marking the start of
  continued maintenance of Racoon IPsec Tools upstream for Linux.
- Reorganized vendor packaging under `packaging/`: moved the RPM
  specs to `packaging/rpm/` and added an initial Arch Linux package
  (`packaging/arch`).
- Added Debian packaging (`debian/`): native 3.0 source format,
  `debhelper-compat` 13, no quilt, and `dh_installdocs`/
  `dh_installchangelogs` wiring for `README.md`, the admin guide, and
  `NEWS.md`; plus Git merge strategies so distro branches rebase
  cleanly onto `develop`.
- Fixed minor Debian packaging bugs: a spurious group-removal warning
  on purge, and `setkey.service` no longer auto-enabling at boot.
- Added a real, maintained phase1-up/phase1-down split-DNS and routing
  hook set for Mode Config road-warrior clients
  (`src/racoon/scripts/racoon-hook-lib.sh`, `phase1-up.sh`,
  `phase1-down.sh`, and the `racoon-dns-detect` diagnostic CLI):
  detects and drives systemd-resolved, NetworkManager, resolvconf, and
  dnsmasq; installs and owns exactly the routes and SPD entries a
  connection needs; whitelist-validates every value the gateway sends
  before using it; and journals a per-connection undo log so
  phase1-down.sh reverses precisely what phase1-up.sh applied.
  Superseding the minimal example hooks that have long sat under
  `src/racoon/samples/roadwarrior/client/` (kept there for reference,
  never installed), this is now a first-class build component wired
  into `src/racoon/scripts/Makefile.am` — `make install` places it at
  `$(sysconfdir)/scripts` (`/etc/racoon/scripts` under this project's
  own packaging) rather than requiring a manual copy. A commented
  `hooks.conf.sample` and the full admin/troubleshooting documentation
  (`doc/admin/split-dns.html`) ship alongside it as package
  examples/docs. See that document for installation and configuration.

### Bug fixes

- Fixed NAT-T encapsulation: replaced `UDP_ENCAP_ESPINUDP_NON_IKE`
  with `UDP_ENCAP_ESPINUDP` in `isakmp_open()` and
  `natt_fill_options()` so draft NAT-T encapsulation matches the RFC
  encap type, and dropped the now-default `"00"` entry from
  `natt_versions_default`.
- Guarded `admin_close()` and `evt_unsubscribe()` against
  double-closing already-invalidated socket fds, and improved the
  `FD_SETSIZE` overrun diagnostic in `unmonitor_fd()`.
- Plugged several OpenSSL-related memory leaks and unsafe frees
  across `crypto_openssl.c`, `openssl_compat.c`, and
  `plainrsa-gen.c`, including leaks in `eay_str2asn1dn`,
  `eay_dh_compute`, `OSSL_PARAM_BLD_free`/`_to_param`, and
  `EVP_PKEY_fromdata`, plus double-free fixes in
  `compat_RSA_new_from_params()` and `prsa_par.y`.
- Fixed a stack buffer overflow in `sockmisc.c`'s `naddr_score()` by
  using `union sockaddr_any` instead of a bare `struct sockaddr`.
- Removed a redundant signed-char pre-check in
  `base64_pubkey2rsa()`.
- Fixed pointer arithmetic and undefined-behavior `isprint()` calls
  in libipsec's `key_debug` (NetBSD).
- Fixed `ldap_sasl_bind_s` anonymous bind handling and protocol
  version checks, and added LDAP URI, timeout, and debug config
  options (NetBSD).
- Cast to `rt_msghdr` instead of `if_msghdr` in `grabmyaddr`'s
  kernel_sync (NetBSD).
- Fixed an unaligned pointer access from pointing directly to a
  packed struct member.
- Dropped the `ber_set_option()` LDAP debug call, since racoon only
  links against `-lldap`, not `-llber`; `ldap_set_option()` alone is
  sufficient.
- Deprecated the `--with-libradius` configure option with a warning.
- Removed a dead `NATT_00`/`NATT_01` branch in `isakmp_open()`'s NAT-T
  `setsockopt` handling, left over from when `"00"` was dropped from
  `natt_versions_default`; it duplicated the `UDP_ENCAP_ESPINUDP`
  assignment under unreachable conditionals.
- Fixed `eayRSA_get_params()` to report failure if any requested RSA
  component could not be fetched (e.g. private fields requested on a
  public-only key), instead of always returning success and leaving
  callers to dereference NULL `BIGNUM*` outputs.
- Added `_Alignas` to `struct throttle_entry`'s flexible array member
  to make its sockaddr alignment requirement explicit, and fixed a
  "REMOTEL_PORT" typo in an `isakmp.c` log message (now
  `REMOTE_PORT`).
- Loaded the IPsec NAT-T kernel modules (`esp4`, `esp6`,
  `udp_tunnel`, `xfrm4_tunnel`, `xfrm4_mode_tunnel`,
  `xfrm4_mode_transport`) from `racoon.postinst` via `modprobe`,
  fixing `WARNING: setsockopt(UDP_ENCAP_ESPINUDP): UDP_ENCAP
  Protocol not available` on Ubuntu Noble/Resolute, where they ship
  as loadable modules instead of being built into the kernel.
- Removed `debian/racoon.config` and `debian/racoon.templates`, a
  stale debconf prompt left over from the retired `racoon-tool`
  config mode that referenced a template deleted since the initial
  packaging commit; on Ubuntu Bionic's older debconf this blocked
  `dpkg` indefinitely, hanging the installing SSH session until
  killed manually.
- Fixed a per-session memory leak in `frag_handler()`: the `vchar_t*`
  buffer allocated by `isakmp_frag_reassembly()` was never freed after
  being passed to `isakmp_main()`, leaking ~3.5 KB per IKE session
  that uses fragmentation (e.g. every iOS connection, which advertises
  the FRAGMENTATION Vendor ID).
- Fixed an off-by-one in `xauth_ldap_init_conf()`: six `vmalloc()`
  calls allocated `strlen(x)` bytes without room for a NUL terminator,
  causing `strlen()` in `xauth_group_ldap()` to read one byte past the
  end of the allocated block (Valgrind: invalid read of size 1).

### Documentation

- Replaced the legacy README with a new upstream `README.md`.
- Added a Racoon Administration Guide under `docs/admin-guide`.
- Added and updated license headers across the source tree.
- Moved `ChangeLog`, `ChangeLog.old`, and `NEWS` to
  `docs/history/`, keeping this `NEWS.md` as the current,
  human-curated summary of changes per release.
- Added `CONTRIBUTING.md` with developer setup instructions.
- Expanded the admin guide's build dependency, configure flag, and
  packaging instructions.
- Self-hosted the IBM Plex Mono and Inter fonts used by the admin
  guide, with matching OFL-1.1 license documentation.
- Replaced dead SourceForge references with the current GitHub
  project across `configure.ac`, the RPM specs, `plainrsa-gen`, the
  FAQ, and the README/Debian metadata, and added a GPG
  release-verification section to the README.
- Added the Racoon IPsec Tools project logo to the README and the
  admin guide, with light/dark variants, inline `<svg>` embedding,
  and matching CSS custom properties.
- Updated `CONTRIBUTING.md` to acknowledge the project's use of
  AI-assisted development tooling.
