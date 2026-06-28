# NEWS

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
