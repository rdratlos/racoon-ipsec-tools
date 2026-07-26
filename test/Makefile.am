# test/Makefile.am
# Modern test suite for Racoon IPSec OpenSSL 3.0 migration
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

OPENSSL_VERSION_STR = @OPENSSL_VERSION_STR@

COVERAGE_TITLE     = "$(PACKAGE_STRING) - using $(OPENSSL_VERSION_STR)"
COVERAGE_MED_LIMIT  = 50
COVERAGE_HI_LIMIT = 70

# Include paths - racoon sources are in src/racoon only
AM_CPPFLAGS = \
	-I$(top_srcdir)/src/racoon \
	-I$(top_builddir)/src/racoon \
	-I$(top_srcdir)/src/racoon/missing

# Compiler flags - match src/racoon/Makefile.am
AM_CFLAGS = \
	-D_GNU_SOURCE \
	-DSYSCONFDIR=\"${sysconfdir}\" \
	-DADMINPORTDIR=\"${adminsockdir}\" \
	-Wall \
	-Wno-deprecated-declarations \
	@COVERAGE_FLAGS@

AM_LDFLAGS = @EXTRA_CRYPTO@ -lcrypto

# Reuse object files built in src/racoon as side-effects of the main racoon
# build; we reference them by path so automake does not try to rebuild them
# here.
#
# crypto_openssl_unittest.o is the NON-EAYDEBUG build of crypto_openssl.c
# (src/racoon/Makefile.am), deliberately used instead of eaytest's
# crypto_openssl_test.o (-DEAYDEBUG).  Under EAYDEBUG mem2x509() reads PEM
# while eay_get_x509cert() writes DER, so test_x509_cert's load/parse
# round-trip needs the production DER path; and building one shared
# non-EAYDEBUG object across the whole suite keeps crypto_openssl.c coverage
# consistent for `make coverage` (a single line structure lcov can merge).
# No test/ unit test depends on the EAYDEBUG PEM behaviour.
RACOON_OBJS = \
	$(top_builddir)/src/racoon/crypto_openssl_unittest.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/str2val.o \
	$(top_builddir)/src/racoon/misc_noplog.o \
	$(top_builddir)/src/racoon/strnames.o \
	$(top_builddir)/src/racoon/openssl_compat.o \
	$(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/eay_rsa.o

# $(CRYPTOBJS) from src/racoon covers optional SHA2/rijndael objects;
# we approximate it here with the same conditional logic used upstream.
CRYPTOOBJS = @CRYPTOBJS@

# Common LDADD for all test binaries
COMMON_LDADD = \
	$(RACOON_OBJS) \
	$(CRYPTOOBJS) \
	$(top_builddir)/src/libipsec/libipsec.la \
	@EXTRA_CRYPTO@ \
	-lcrypto

# Test programs
#
# test_ipsec_doi_sa and test_algorithm are added conditionally further
# down, alongside test_vendorid_bounds/test_nattraversal_natd/
# test_script_hook_leak: see the "SANITIZER_BUILD" comment above
# test_ipsec_doi_sa's rules below.
check_PROGRAMS = \
	test_dh_modp_groups \
	test_dh_buffer_overflow \
	test_rsa_comprehensive \
	test_crypto_coverage \
	test_cipher_shim \
	test_logger \
	test_str2val \
	test_vmbuf \
	test_sockmisc \
	test_genlist \
	test_eay_rsa \
	test_x509_cert \
	test_misc \
	test_strlcpy \
	test_strnames \
	test_rsalist \
	test_plog \
	test_splitdns

# Test 1: DH MODP Groups
test_dh_modp_groups_SOURCES  = test_dh_modp_groups.c
test_dh_modp_groups_LDADD    = $(COMMON_LDADD)
test_dh_modp_groups_LDFLAGS  = $(AM_LDFLAGS)

# Test 1b: DH Buffer Overflow Safety (ISSUE #5)
test_dh_buffer_overflow_SOURCES  = test_dh_buffer_overflow.c
test_dh_buffer_overflow_LDADD    = $(COMMON_LDADD)
test_dh_buffer_overflow_LDFLAGS  = $(AM_LDFLAGS)

# Test 2: RSA Comprehensive
#
# rsalist_test_stubs.c provides stand-in definitions for lcconf,
# monitor_fd(), script_exec(), getpsk() and the privsep_* API -- symbols
# pulled in transitively via rsalist.o -> sockmisc.o that are never
# exercised by the rsa_key_dup()/rsa_key_free() unit tests.
#
# privsep.o is deliberately NOT linked: on builds with XAUTH/CFG support
# enabled (e.g. with LDAP/PAM/Kerberos), privsep.o references
# isakmp_cfg_*/xauth_*/cleanup_pam symbols from isakmp_cfg.c/isakmp_xauth.c,
# which would pull in most of racoon.
test_rsa_comprehensive_SOURCES  = test_rsa_comprehensive.c rsalist_test_stubs.c
test_rsa_comprehensive_LDADD    = $(COMMON_LDADD) \
	$(top_builddir)/src/racoon/rsalist.o \
	$(top_builddir)/src/racoon/genlist.o \
	$(top_builddir)/src/racoon/sockmisc.o \
	$(top_builddir)/src/racoon/prsa_par.o \
	$(top_builddir)/src/racoon/prsa_tok.o
test_rsa_comprehensive_LDFLAGS  = $(AM_LDFLAGS)

# Test 3: Crypto Coverage
test_crypto_coverage_SOURCES  = test_crypto_coverage.c
test_crypto_coverage_LDADD    = $(COMMON_LDADD)
test_crypto_coverage_LDFLAGS  = $(AM_LDFLAGS)

# Test 4: Cipher Shim (legacy ciphers + evp_crypt)
test_cipher_shim_SOURCES  = test_cipher_shim.c
test_cipher_shim_LDADD    = $(COMMON_LDADD)
test_cipher_shim_LDFLAGS  = $(AM_LDFLAGS)

# Test 5: Logger (ring-buffer, no OpenSSL dependency)
test_logger_SOURCES  = test_logger.c
test_logger_LDADD    = $(top_builddir)/src/racoon/logger.o
test_logger_LDFLAGS  = $(AM_LDFLAGS)

# Test 6: str2val (hex string <-> value conversion)
test_str2val_SOURCES  = test_str2val.c
test_str2val_LDADD    = $(COMMON_LDADD)
test_str2val_LDFLAGS  = $(AM_LDFLAGS)

# Test 7: vmbuf (variable-length buffer operations)
test_vmbuf_SOURCES  = test_vmbuf.c
test_vmbuf_LDADD    = $(COMMON_LDADD)
test_vmbuf_LDFLAGS  = $(AM_LDFLAGS)

# Test 8: sockmisc (socket address utilities)
#
# Uses rsalist_test_stubs.c for privsep_* and lcconf/monitor_fd/script_exec/getpsk
# stubs — the same approach as test_rsa_comprehensive.  Linking privsep.o directly
# is not possible: it references isakmp_cfg_*/xauth_*/cleanup_pam/lcconf symbols
# from isakmp_cfg.c/isakmp_xauth.c, which would pull in most of racoon.
test_sockmisc_SOURCES  = test_sockmisc.c rsalist_test_stubs.c
test_sockmisc_CPPFLAGS = -I$(top_srcdir)/src/racoon
test_sockmisc_LDADD    = $(COMMON_LDADD) \
	$(top_builddir)/src/racoon/sockmisc.o
test_sockmisc_LDFLAGS  = $(AM_LDFLAGS) -lresolv

# Test 9: genlist (generic linked-list operations)
test_genlist_SOURCES   = test_genlist.c
test_genlist_LDADD     = $(top_builddir)/src/racoon/genlist.o
test_genlist_LDFLAGS   = $(AM_LDFLAGS)

# Test 10: eay_rsa (eayRSA opaque RSA object)
test_eay_rsa_SOURCES  = test_eay_rsa.c
test_eay_rsa_LDADD    = $(COMMON_LDADD)
test_eay_rsa_LDFLAGS  = $(AM_LDFLAGS)

# Test 11: ipsec_doi SA transform attribute bounds (ISSUE #37)
#
# t2isakmpsa() is static in ipsec_doi.c, so we compile that source here with
# -DENABLE_UNITTEST to expose the t2isakmpsa_unittest() wrapper.  The rest of
# ipsec_doi.c has a large dependency closure (oakley/isakmp/remoteconf/...),
# so the source is built with -ffunction-sections and linked with
# --gc-sections: the unused functions are discarded, leaving only
# t2isakmpsa()'s handful of always-built dependencies (vmbuf/plog/logger/
# strnames/misc).  This keeps the test independent of the configure feature
# set (frag/hybrid/natt/...).
#
# ipsec_doi.c itself is pulled in via ipsec_doi_unittest_src.c (a local
# wrapper that just #includes it) rather than referenced directly as a
# _SOURCES entry, so the compiled object and its dependency (.Po) file
# stay under test/.deps/ instead of $(top_builddir)/src/racoon/.deps/ --
# some automake versions (e.g. Ubuntu Bionic's 1.15.1) fail to track
# per-object dependency files for subdir-objects sources that live
# outside the current top-level directory.
#
# Excluded from sanitizer builds (SANITIZER_BUILD, set by configure.ac from
# --enable-sanitizers or autodetected -fsanitize= in CC/CFLAGS/LDFLAGS):
# AddressSanitizer instruments every static/global variable so it can poison
# redzones around it, which takes that variable's address and so keeps it
# (and anything it references) reachable -- defeating the dead-code
# elimination this target, test_vendorid_bounds, test_nattraversal_natd, and
# test_algorithm all rely on to avoid linking each source file's full
# dependency closure.  Concretely: ipsec_doi.c's check_attr_isakmp() et al.
# are unreachable from t2isakmpsa() and are normally discarded by
# --gc-sections, but ASan's global registration keeps the check_attributes[]
# function-pointer table (and thus check_attr_isakmp() et al.) alive, which
# then needs algorithm.c's alg_oakley_*_ok() -- never linked here -- causing
# an undefined-reference link failure.  These targets' memory-safety
# coverage is already provided by 'make check-valgrind'; the one accepted
# gap is UBSan-only checks (signed overflow, misaligned access, etc.) that
# valgrind's memcheck does not perform.
if !SANITIZER_BUILD
check_PROGRAMS += test_ipsec_doi_sa

test_ipsec_doi_sa_SOURCES  = test_ipsec_doi_sa.c ipsec_doi_test_stubs.c \
	ipsec_doi_unittest_src.c
test_ipsec_doi_sa_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_ipsec_doi_sa_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_ipsec_doi_sa_LDADD    = \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/strnames.o \
	$(top_builddir)/src/racoon/misc.o
test_ipsec_doi_sa_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test 13: X.509 certificate functions (ISSUE #52)
#
# eay_get_x509cert / eay_check_x509cert / eay_check_x509sign /
# eay_get_x509asn1subjectname / eay_get_x509asn1issuername /
# eay_get_x509subjectaltname / eay_get_x509text /
# eay_get_pkcs1privkey / eay_get_pkcs1pubkey / eay_get_x509sign.
#
# Links the shared non-EAYDEBUG crypto_openssl_unittest.o via COMMON_LDADD
# (see the RACOON_OBJS comment above): eay_get_x509cert() writes DER, which
# only round-trips through the production (non-EAYDEBUG) mem2x509().
#
# Fixtures are real PEM certificates/keys/CRLs produced at run time by
# gen-x509-fixtures.sh (which drives cert-framework/lib/ca.sh).  The test
# binary locates that script through X509_FIXTURE_SRCDIR, exported below via
# AM_TESTS_ENVIRONMENT.
test_x509_cert_SOURCES = test_x509_cert.c
test_x509_cert_LDADD    = $(COMMON_LDADD)
test_x509_cert_LDFLAGS  = $(AM_LDFLAGS)

# Test 12: Vendor ID bounds — vendorid_frag_cap() (#38) and check_vendorid()
# (#39).  Built only with --enable-frag, since vendorid_frag_cap() lives in
# isakmp_frag.c (compiled only then).  vendorid.c is compiled with
# -DENABLE_UNITTEST to expose check_vendorid_unittest(); both racoon sources
# are built with -ffunction-sections and linked with --gc-sections so their
# unused remainder is discarded.  ENABLE_FRAG comes from config.h, so it is
# not passed on the command line (which would redefine it).
#
# vendorid.c and isakmp_frag.c are pulled in via local wrapper sources
# (see the comment on test_ipsec_doi_sa_SOURCES above) so their .Po
# dependency files stay under test/.deps/.
#
# Also excluded from sanitizer builds, same reason as test_ipsec_doi_sa
# above (relies on --gc-sections dead-code elimination that ASan defeats).
if ENABLE_FRAG
if !SANITIZER_BUILD
check_PROGRAMS += test_vendorid_bounds

test_vendorid_bounds_SOURCES  = test_vendorid_bounds.c \
	vendorid_unittest_src.c \
	isakmp_frag_unittest_src.c
test_vendorid_bounds_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_vendorid_bounds_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_vendorid_bounds_LDADD    = $(COMMON_LDADD)
test_vendorid_bounds_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif
endif

# Test: racoonctl f_logoutusr() request-buffer sizing (#68) — a 1-byte heap
# overflow in the ADMIN_LOGOUT_USER request buffer: make_request() allocated
# exactly `userlen` payload bytes but the pre-fix code copied `userlen + 1`
# (username + NUL) into it. Built only with --enable-hybrid, since
# f_logoutusr() lives in racoonctl.c behind #ifdef ENABLE_HYBRID.
# ENABLE_HYBRID comes from config.h, so it is not passed on the command
# line (which would redefine it).
#
# racoonctl.c is pulled in via a local wrapper source (see the comment on
# test_ipsec_doi_sa_SOURCES above) so its .Po dependency file stays under
# test/.deps/; unlike the other wrapped sources, racoonctl.c defines its
# own main(), so the wrapper renames it out of the way first.
#
# Also excluded from sanitizer builds, same reason as test_ipsec_doi_sa
# above (relies on --gc-sections dead-code elimination that ASan defeats).
if ENABLE_HYBRID
if !SANITIZER_BUILD
check_PROGRAMS += test_racoonctl_logoutusr

test_racoonctl_logoutusr_SOURCES  = test_racoonctl_logoutusr.c \
	racoonctl_unittest_src.c \
	racoonctl_unittest_stubs.c
test_racoonctl_logoutusr_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_racoonctl_logoutusr_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
# f_logoutusr()/make_request()'s own logic only needs vmalloc()/vfree()
# (vmbuf.o), strlcpy() (header-only), and errx() (libc) -- deliberately
# NOT $(COMMON_LDADD): racoonctl.c defines its own global `char *pname`
# (a tentative definition of the single `extern char *pname` declared
# in plog.h), which collides at link time with plog.c's own `pname` if
# plog.o is pulled in directly on the link line (as COMMON_LDADD does
# for the crypto-heavy tests). The real racoonctl binary avoids this
# because it links plog.o only via libracoon.la's archive, pulled in
# on demand; nothing f_logoutusr() needs actually demands it.
#
# vmbuf.o itself is reused pre-built from src/racoon/ (not compiled
# with -ffunction-sections there), so --gc-sections cannot cherry-pick
# vmalloc()/vfree() out of it in isolation -- the whole object comes in
# as a unit, including vdup()'s plog(LLV_ERROR, LOCATION, ...) call
# (never reached from f_logoutusr()'s call graph, but still needs to
# resolve at link time). misc_noplog.o supplies the real
# debug_location() LOCATION expands to; racoonctl_unittest_stubs.c
# supplies bare-minimum stand-ins for loglevel/_plog() so plog.o itself
# is never linked.
test_racoonctl_logoutusr_LDADD    = $(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_racoonctl_logoutusr_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif
endif

# Test: kmpstat com_recv() short-read/EOF diagnostics (daemon-issues.md
# Issue 4) — com_recv()'s "sanity check" goto bad1 on a truncated header
# used to print nothing at all, so racoonctl (vpn-disconnect and any other
# admin-socket event wait) exited non-zero with zero output whenever the
# admin socket EOFed or delivered a short header before the expected
# event arrived, reproduced in 8/8 live Task F runs.
#
# com_recv() is not static, but the admin-socket fd it reads (`so`) is
# private to kmpstat.c; com_set_fd_unittest() is a thin -DENABLE_UNITTEST
# accessor kmpstat.c exposes so the test can point it at a socketpair()
# standing in for the real AF_UNIX admin socket.
#
# kmpstat.c is pulled in via a local wrapper source (see the comment on
# test_racoonctl_logoutusr_SOURCES above) so its .Po dependency file stays
# under test/.deps/. Unlike racoonctl.c, kmpstat.c defines no main() of
# its own, so no renaming is needed.
#
# Always built (com_recv()/com_init()/com_close() are unconditional, not
# behind ENABLE_HYBRID). Excluded from sanitizer builds for the same
# reason as test_racoonctl_logoutusr above: relies on --gc-sections
# dead-code elimination that ASan defeats.
if !SANITIZER_BUILD
check_PROGRAMS += test_kmpstat_com_recv

test_kmpstat_com_recv_SOURCES  = test_kmpstat_com_recv.c \
	kmpstat_unittest_src.c
test_kmpstat_com_recv_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_kmpstat_com_recv_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
# com_recv()'s own logic only needs vmalloc()/vfree() (vmbuf.o); see the
# test_racoonctl_logoutusr_LDADD comment above for why misc_noplog.o (not
# plog.o) supplies debug_location() without pulling in plog.c's `pname`.
test_kmpstat_com_recv_LDADD    = $(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_kmpstat_com_recv_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test 14: misc (close_on_exec, timedelta)
test_misc_SOURCES  = test_misc.c
test_misc_LDADD    = $(COMMON_LDADD)
test_misc_LDFLAGS  = $(AM_LDFLAGS) -lm

# Test 14b: strlcpy/strlcat fallbacks (src/racoon/missing/)
test_strlcpy_SOURCES  = test_strlcpy.c
test_strlcpy_LDADD    =
test_strlcpy_LDFLAGS  = $(AM_LDFLAGS)

# Test 15: strnames (all s_* string/value lookup functions)
test_strnames_SOURCES  = test_strnames.c
test_strnames_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc
test_strnames_LDADD    = $(COMMON_LDADD)
test_strnames_LDFLAGS  = $(AM_LDFLAGS)

# Test 16: rsalist (candidate-key scoring/selection and signature
# verification dispatch used by oakley.c's RSA-signature IKE auth path)
#
# Same link approach as test_rsa_comprehensive: rsalist_test_stubs.c stubs
# out the privsep_*/lcconf/monitor_fd/script_exec/getpsk symbols pulled in
# transitively via rsalist.o -> sockmisc.o, so privsep.o (and the
# isakmp_cfg_*/xauth_* symbols it would drag in) never needs to be linked.
test_rsalist_SOURCES  = test_rsalist.c rsalist_test_stubs.c
test_rsalist_LDADD    = $(COMMON_LDADD) \
	$(top_builddir)/src/racoon/rsalist.o \
	$(top_builddir)/src/racoon/genlist.o \
	$(top_builddir)/src/racoon/sockmisc.o \
	$(top_builddir)/src/racoon/prsa_par.o \
	$(top_builddir)/src/racoon/prsa_tok.o
test_rsalist_LDFLAGS  = $(AM_LDFLAGS) -lresolv

# Test 17: plog (logging/formatting: plog_common's buffer arithmetic,
# plogdump's hex-dump sizing, binsanitize, file- and syslog-backed
# dispatch)
test_plog_SOURCES  = test_plog.c
test_plog_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_plog_LDFLAGS  = $(AM_LDFLAGS)

# Test 18: split DNS (UNITY_SPLITDNS_NAME attribute, ISAKMP_CFG_GOT_SPLIT_DNS
# flag, INTERNAL_SPLITDNS_DOMAINS env var, resolver integration script logic)
test_splitdns_SOURCES  = test_splitdns.c
test_splitdns_LDADD    = $(COMMON_LDADD)
test_splitdns_LDFLAGS  = $(AM_LDFLAGS)

# Test 19: NAT-D CRYPTO_memcmp regression (issue #34) — natt_compare_addr_hash()
# in nattraversal.c is the one memcmp()->CRYPTO_memcmp() call site in this
# hardening pass cheap enough to drive through a real call rather than a
# synthetic buffer comparison.  Built only with --enable-natt, since
# nattraversal.c's struct ph1handle fields (natt_flags, natt_options) only
# exist under ENABLE_NATT.  natt_hash_addr() falls back to MD5 without a
# negotiated proposal, pulling in oakley_hash() from oakley.c; both sources
# have a much larger dependency closure than what this test needs, so they
# are built with -ffunction-sections and linked with --gc-sections (same
# technique as test_ipsec_doi_sa and test_vendorid_bounds) to discard the
# unused remainder.  rsalist_test_stubs.c supplies the privsep_* stubs
# sockmisc.o needs at link time (see the comment on test_rsalist_SOURCES).
#
# nattraversal.c and oakley.c are pulled in via local wrapper sources (see
# the comment on test_ipsec_doi_sa_SOURCES above) so their .Po dependency
# files stay under test/.deps/.
#
# Also excluded from sanitizer builds, same reason as test_ipsec_doi_sa
# above (relies on --gc-sections dead-code elimination that ASan defeats).
if ENABLE_NATT
if !SANITIZER_BUILD
check_PROGRAMS += test_nattraversal_natd

test_nattraversal_natd_SOURCES  = test_nattraversal_natd.c \
	nattraversal_unittest_src.c \
	oakley_unittest_src.c \
	rsalist_test_stubs.c
test_nattraversal_natd_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc
test_nattraversal_natd_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_nattraversal_natd_LDADD    = $(COMMON_LDADD) \
	$(top_builddir)/src/racoon/algorithm.o \
	$(top_builddir)/src/racoon/sockmisc.o
test_nattraversal_natd_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif
endif

# Test 19: algorithm.c DOI<->algorithm dispatch tables (issue #34 follow-up).
# algorithm.o is now pulled into every coverage build via test_nattraversal_natd
# (COMMON_LDADD there adds it for oakley_dhdef[]'s DH group pointers), which
# previously counted its ~950 uncovered lines against the suite's coverage
# percentage. algorithm.c is otherwise self-contained: its pure DOI/type
# lookups and *_one()/_encrypt()/_decrypt() dispatchers need nothing beyond
# what COMMON_LDADD already links (crypto_openssl_unittest.o for the
# underlying eay_* implementations). Only alg_oakley_dhdef_group() needs
# live data -- the dh_modp* globals declared in oakley.c, populated by
# oakley_dhinit() -- so oakley.c is pulled in via the same wrapper source
# and -ffunction-sections/--gc-sections technique as test_nattraversal_natd,
# to avoid oakley.c's much larger dependency closure elsewhere in the file.
#
# Unlike test_nattraversal_natd, algorithm.c has no feature-flag
# dependency, so this test always builds and always contributes to
# coverage regardless of --enable-natt/--enable-frag -- except in
# sanitizer builds, excluded for the same --gc-sections-vs-ASan reason as
# test_ipsec_doi_sa above.
if !SANITIZER_BUILD
check_PROGRAMS += test_algorithm

test_algorithm_SOURCES  = test_algorithm.c \
	oakley_unittest_src.c
test_algorithm_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc
test_algorithm_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_algorithm_LDADD    = $(COMMON_LDADD) \
	$(top_builddir)/src/racoon/algorithm.o
test_algorithm_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test 20: grabmyaddr.c Linux netlink route-attribute parsing (issue #73) —
# netlink_process_route() computed the RTM_NEWROUTE/RTM_DELROUTE attribute
# payload length with IFA_PAYLOAD(h) (sized for struct ifaddrmsg, 8 bytes)
# instead of RTM_PAYLOAD(h) (sized for struct rtmsg, 12 bytes), so
# parse_rtattr() walked 4 bytes past the real attribute data.
#
# netlink_parse_route_attrs() is static in grabmyaddr.c, so grabmyaddr.c is
# compiled here with -DENABLE_UNITTEST to expose the thin wrapper
# netlink_parse_route_attrs_unittest() (see the ENABLE_UNITTEST block next
# to netlink_process_route() in grabmyaddr.c), the same technique as
# test_ipsec_doi_sa's t2isakmpsa_unittest(). Built with
# -ffunction-sections/--gc-sections so the rest of grabmyaddr.c's address
# bookkeeping (which the two functions under test never call) is discarded
# rather than needing to be stubbed or linked.
#
# sockmisc.o (below) is reused pre-built from src/racoon/ and, unlike
# grabmyaddr.c above, is NOT compiled with -ffunction-sections -- it is one
# undivided translation unit, so --gc-sections can only keep or drop it as a
# whole, not function-by-function. Historically this test relied entirely on
# --gc-sections dropping it outright (nothing it calls reaches sockmisc.o's
# functions at runtime); that assumption broke under a coverage build
# (-fprofile-arcs/-ftest-coverage), which -- like the AddressSanitizer
# instrumentation already documented via SANITIZER_BUILD elsewhere in this
# file -- can keep the whole object linked, surfacing sockmisc.o's
# privsep_*()/ipsec_*() link-time dependencies (present whenever it is
# built without -DNOUSE_PRIVSEP, i.e. this exact reused copy) as undefined-
# reference errors. grabmyaddr_netlink_test_stubs.c stubs exactly those six
# symbols -- none of them reachable from what this test actually calls --
# so the link no longer depends on --gc-sections guessing right either way.
#
# Linux-only (USE_NETLINK in grabmyaddr.c is gated on __linux__, and
# test_grabmyaddr_netlink.c includes <linux/rtnetlink.h> directly to build
# the same message shapes). On platforms without those headers (NetBSD,
# ...) grabmyaddr.c itself falls back to the routing-socket (USE_ROUTE)
# path instead, so HAVE_LINUX_NETLINK (configure.ac, via
# AC_CHECK_HEADERS([linux/netlink.h linux/rtnetlink.h])) gates this test
# out of the build there rather than failing to compile.
if HAVE_LINUX_NETLINK
check_PROGRAMS += test_grabmyaddr_netlink

test_grabmyaddr_netlink_SOURCES  = test_grabmyaddr_netlink.c \
	grabmyaddr_unittest_src.c \
	grabmyaddr_netlink_test_stubs.c
test_grabmyaddr_netlink_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_grabmyaddr_netlink_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_grabmyaddr_netlink_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/misc_noplog.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/sockmisc.o
test_grabmyaddr_netlink_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections -lresolv
endif

# Test 21: isakmp.c script_hook() REMOTE_ID leak (issue #72) —
# ipsecdoi_id2str()'s racoon_malloc()'d return value was passed straight
# into script_env_append() without ever being captured/freed.
#
# script_hook() and script_env_append() are non-static, so no
# -DENABLE_UNITTEST wrapper is needed for visibility; isakmp.c is still
# compiled locally here (isakmp_unittest_src.c) with
# -ffunction-sections/--gc-sections, the same isolation technique used
# above, so its large ISAKMP-state-machine dependency closure is discarded
# down to just what script_hook()'s REMOTE_ID path calls.
# isakmp_script_hook_test_stubs.c substitutes test doubles for
# ipsecdoi_id2str(), privsep_script_exec() and isakmp_cfg_setenv() (the
# last only reachable under --enable-hybrid, this project's default) --
# see that file's header comment. script_names[] is also stubbed there:
# script_hook()'s failed-exec error path references it by name even though
# the stubbed privsep_script_exec() never takes that branch.
#
# -Wl,--wrap=free lets test_script_hook_leak.c's __wrap_free() observe
# every free() this binary makes, so the leak is detected deterministically
# under a plain `make check`, without depending on valgrind -- confirmed
# additionally live with `make check-valgrind`, the method that originally
# caught this bug.
#
# Also excluded from sanitizer builds, same reason as test_ipsec_doi_sa
# above (relies on --gc-sections dead-code elimination that ASan defeats):
# isakmp.c's static ph1exchange[]/ph2exchange[] state-machine dispatch
# tables reference quick_*/ident_*/agg_*/base_* handlers from
# isakmp_quick.c/isakmp_ident.c/isakmp_agg.c/isakmp_base.c (never linked
# here) that script_hook() itself never calls; under ASan those tables'
# global-variable instrumentation keeps them (and so those undefined
# references) alive despite --gc-sections. This target's memory-safety
# coverage is already provided by 'make check-valgrind'.
if !SANITIZER_BUILD
check_PROGRAMS += test_script_hook_leak

test_script_hook_leak_SOURCES  = test_script_hook_leak.c \
	isakmp_unittest_src.c \
	isakmp_script_hook_test_stubs.c
test_script_hook_leak_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_script_hook_leak_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_script_hook_leak_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/misc_noplog.o \
	$(top_builddir)/src/racoon/vmbuf.o
test_script_hook_leak_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections \
	-Wl,--wrap=free
endif

# Test: script_exec() bounded wait for RACOON_SCRIPT_WAIT-flagged hooks
# (daemon-issues.md Issue 1 / F2) -- close_session()'s shutdown path used
# to never wait for a SCRIPT_PHASE1_DOWN hook's forked child, routinely
# outracing phase1-down.sh and leaving its routes/DNS/SPD state behind.
#
# isakmp.c is pulled in the same way as test_script_hook_leak above
# (isakmp_unittest_src.c, -ffunction-sections/--gc-sections), but this
# test drives script_exec() directly with real throwaway shell scripts
# under /tmp rather than going through script_hook(), so it only needs
# isakmp_script_exec_test_stubs.c's script_names[] stub -- none of
# test_script_hook_leak's ipsecdoi_id2str()/privsep_script_exec()/
# isakmp_cfg_setenv() stubs are reachable from script_exec() itself.
#
# Also excluded from sanitizer builds, same reason as test_script_hook_leak
# above (relies on --gc-sections dead-code elimination that ASan defeats).
if !SANITIZER_BUILD
check_PROGRAMS += test_script_exec_wait

test_script_exec_wait_SOURCES  = test_script_exec_wait.c \
	isakmp_unittest_src.c \
	isakmp_script_exec_test_stubs.c
test_script_exec_wait_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_script_exec_wait_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_script_exec_wait_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/misc_noplog.o \
	$(top_builddir)/src/racoon/vmbuf.o
test_script_exec_wait_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: privsep_sigterm_forward() (daemon-issues.md Issue 1, privsep half)
# -- under privsep, the privileged process (privsep.c) used to leave
# SIGTERM at its default disposition (immediate termination) instead of
# forwarding it to the unprivileged child, so a `systemctl stop racoon`
# (which targets the privileged process's pid under the shipped
# Type=simple unit) killed it before the child's SCRIPT_PHASE1_DOWN
# request could ever arrive -- the down hook was never attempted, not
# just raced. Cannot exercise privsep_init()'s own fork() (needs a real
# PF_KEY/XFRM-capable kernel not every test host has), but drives the
# actual privsep_sigterm_forward() function with a real fork() and a
# real kernel-delivered SIGTERM.
#
# privsep.c is pulled in the same way as the other wrapped-static-function
# tests above (privsep_unittest_src.c, -ffunction-sections/--gc-sections);
# privsep_set_child_pid_unittest()/privsep_sigterm_forward_unittest() are
# new -DENABLE_UNITTEST-only accessors in privsep.c itself, so no separate
# stub file is needed here.
#
# plog.o/logger.o are linked in explicitly, matching test_script_exec_wait
# above, rather than left for --gc-sections to decide: vmbuf.o (reused raw
# from src/racoon's own build, never recompiled with -ffunction-sections
# itself) calls plog()/references loglevel unconditionally in some of its
# functions, and --gc-sections can only drop individual functions out of
# an object that was itself compiled with -ffunction-sections -- since
# vmbuf.o wasn't, its single, whole .text section is kept-or-dropped
# atomically. Whether that section (and so this test's need for plog/
# loglevel) survives came down to how aggressively a given linker/flag
# combination performed that whole-object GC, which a
# --enable-coverage + --with-libpam/--with-libldap/--enable-gssapi build
# on a different linker did differently than this project's own CI,
# leaving "undefined reference to loglevel/_plog" from vmbuf.o's vdup()
# (same root cause already fixed for test_grabmyaddr_netlink -- see
# grabmyaddr_netlink_test_stubs.c's comment).
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_privsep_sigterm_forward

test_privsep_sigterm_forward_SOURCES  = test_privsep_sigterm_forward.c \
	privsep_unittest_src.c
test_privsep_sigterm_forward_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_sigterm_forward_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_sigterm_forward_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_sigterm_forward_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: cmpsatrns() "authtype mismatched" log level (daemon-issues.md
# Issue 3) -- this line used to log at LLV_WARNING (the default visible
# level) once per rejected (peer, mine) transform-pair candidate a
# Phase 2 proposal search tries, so a peer legitimately offering more
# than one authtype alternative made it fire on every negotiation, not
# just a real mismatch.
#
# proposal.c is pulled in via a local wrapper source
# (proposal_unittest_src.c, -ffunction-sections/--gc-sections, same
# pattern as the other wrapped-static-function tests above) so only
# cmpsatrns()'s own reachable closure (strnames.o's
# s_ipsecdoi_trns()/s_ipsecdoi_attr_v()) is retained. _plog() is stubbed
# directly in the test driver to observe which priority (if any) a call
# was actually logged at.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_proposal_authtype_log

test_proposal_authtype_log_SOURCES  = test_proposal_authtype_log.c \
	proposal_unittest_src.c
test_proposal_authtype_log_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_proposal_authtype_log_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_proposal_authtype_log_LDADD    = $(top_builddir)/src/racoon/strnames.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_proposal_authtype_log_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Cert-framework unit tests (test/unit/cert-framework/) — plain Bash
# scripts, not compiled binaries, exercising test/cert-framework/lib/ca.sh.
# They follow automake's default "simple" test protocol (exit 0 = pass,
# nonzero = fail), same as the check_PROGRAMS binaries above, so they can
# sit directly in TESTS. See test/cert-framework/README.md.
CERT_FRAMEWORK_TESTS = \
	unit/cert-framework/test_ca_init.sh \
	unit/cert-framework/test_ca_create_root.sh \
	unit/cert-framework/test_ca_create_intermediate.sh \
	unit/cert-framework/test_issue_net2net.sh \
	unit/cert-framework/test_issue_roadwarrior.sh \
	unit/cert-framework/test_ca_issue_server.sh \
	unit/cert-framework/test_chain_validation.sh \
	unit/cert-framework/test_ca_revoke_cert.sh \
	unit/cert-framework/test_openssl_compat.sh

# Test 22: IKE fragment reassembly regression (CVE-2016-10396 follow-up).
#
# Only meaningful when IKE fragmentation support is compiled in, so it is
# guarded by the ENABLE_FRAG automake conditional (--enable-frag).  It links
# ONLY isakmp_frag.o and provides its own stubs for the daemon symbols that
# object references (plog, vmbuf, isakmp_send, set_isakmp_header1), so it does
# not pull in the rest of racoon and must NOT use COMMON_LDADD (which would
# collide with those stubs).
if ENABLE_FRAG
check_PROGRAMS += test_isakmp_frag
test_isakmp_frag_SOURCES  = test_isakmp_frag.c
test_isakmp_frag_LDADD    = $(top_builddir)/src/racoon/isakmp_frag.o
test_isakmp_frag_LDFLAGS  = $(AM_LDFLAGS)
endif

# Run these tests with 'make check'
TESTS = $(check_PROGRAMS) $(CERT_FRAMEWORK_TESTS)

# test_x509_cert locates gen-x509-fixtures.sh (and, through it,
# cert-framework/lib/ca.sh) via X509_FIXTURE_SRCDIR.  abs_srcdir keeps the
# path valid no matter which directory the harness runs the binary from.
AM_TESTS_ENVIRONMENT = X509_FIXTURE_SRCDIR='$(abs_srcdir)'; export X509_FIXTURE_SRCDIR;

# Extra files to distribute
#
# unit/cert-framework is itemized (not dist-shipped as a bare directory)
# because 'make dist' copies EXTRA_DIST directories verbatim from the
# working tree, .gitignore or not. Running the cert-framework tests
# in-tree drops test_*.sh.log/.trs right next to the scripts (see
# .gitignore); a bare directory reference would sweep those stray,
# already-generated logs into the tarball. Under distcheck's VPATH
# sub-build, a pre-existing .log found via VPATH is treated as already
# up to date and its recipe never runs, so its directory never gets
# created in the build tree -- and the test-suite.log aggregation step
# then fails to find it there.
EXTRA_DIST = README.md valgrind.supp cert-framework gen-x509-fixtures.sh \
	$(CERT_FRAMEWORK_TESTS) \
	unit/cert-framework/test_helper.sh \
	unit/cert-framework/run_tests.sh

# Clean generated files
CLEANFILES = *.log *.trs

# Clean coverage artifacts on 'make clean'
clean-local:
	@rm -f $(top_builddir)/coverage_raw.info $(top_builddir)/coverage_filtered.info
	@rm -rf $(top_builddir)/coverage
	@find $(top_builddir) -name '*.gcda' -delete 2>/dev/null; true
	@find $(top_builddir) -name '*.gcno' -delete 2>/dev/null; true
	@find $(top_builddir) -name 'libtestcrypto_la-*.c' -delete 2>/dev/null; true
	@find $(top_builddir) -name 'libtestcrypto_la-*.h' -delete 2>/dev/null; true

# Custom test targets
.PHONY: check-valgrind check-verbose check-dh check-rsa check-coverage check-shim check-logger check-quick coverage

# Run with valgrind.
#
# Only the compiled C binaries ($(check_PROGRAMS)) are run under valgrind --
# NOT $(TESTS), which also contains the cert-framework Bash scripts
# ($(CERT_FRAMEWORK_TESTS)).  Pointing valgrind at a "#!/usr/bin/env bash"
# script makes it resolve the shebang and instrument /usr/bin/env itself as
# the guest program; on distros whose coreutils is the uutils (Rust)
# reimplementation (e.g. Ubuntu 25.10 "Resolute") that env binary trips
# valgrind with a flood of spurious "Invalid read" errors and the bogus
# "coreutils: unknown program 'memcheck-amd64-linux'" line, failing the
# target on system code we do not own.  Valgrinding a shell script is
# meaningless anyway -- the cert-framework scripts are covered by the plain
# "make check" run.  test_x509_cert stays in the list: it is a real ELF
# binary, and its openssl/bash children (spawned via system()) run natively
# because --trace-children is off.
check-valgrind: $(check_PROGRAMS)
	@echo "Running tests with valgrind..."
	@for test in $(check_PROGRAMS); do \
		echo "Testing $$test..."; \
		valgrind --suppressions=$(srcdir)/valgrind.supp \
			--num-callers=40 \
			--leak-check=full --show-leak-kinds=all \
			--track-origins=yes --error-exitcode=1 \
			./$$test || exit 1; \
	done
	@echo "All tests passed valgrind!"

# Run with verbose output
check-verbose: $(check_PROGRAMS)
	@for test in $(TESTS); do \
		echo "========================================"; \
		echo "Running $$test..."; \
		echo "========================================"; \
		./$$test || exit 1; \
	done

# Run only DH tests
check-dh: test_dh_modp_groups
	./test_dh_modp_groups

# Run only RSA tests
check-rsa: test_rsa_comprehensive
	./test_rsa_comprehensive

# Run only coverage tests
check-coverage: test_crypto_coverage
	./test_crypto_coverage

# Run only cipher shim tests
check-shim: test_cipher_shim
	./test_cipher_shim

# Run only logger tests
check-logger: test_logger
	./test_logger

# Quick test (DH + RSA only)
check-quick: test_dh_modp_groups test_rsa_comprehensive
	./test_dh_modp_groups
	./test_rsa_comprehensive

# Generate code coverage report (requires --enable-coverage and lcov)
coverage: $(check_PROGRAMS)
	@which lcov > /dev/null 2>&1 || \
		{ echo "Error: lcov not found. Install lcov to generate coverage reports."; exit 1; }
	@LCOV_DIR=$$(cd $(top_builddir) && pwd); \
	SRC_DIR=$$(cd $(top_builddir)/src && pwd); \
	LCOV_MAJOR=$$(lcov --version 2>/dev/null | grep -oE '[0-9]+' | head -1); \
	echo "lcov major version: $${LCOV_MAJOR:-1}"; \
	if [ "$${LCOV_MAJOR:-1}" -ge 2 ]; then \
		LCOV_CAPTURE="--ignore-errors source,source,inconsistent,unused"; \
		LCOV_FILTER="--ignore-errors unused"; \
	else \
		LCOV_CAPTURE=""; \
		LCOV_FILTER=""; \
	fi; \
	echo "Running tests to collect coverage data..."; \
	lcov --directory "$$SRC_DIR" --zerocounters; \
	for test in $(TESTS); do \
		echo "Running $$test for coverage..."; \
		./$$test || exit 1; \
	done; \
	echo "Excluding eaytest's EAYDEBUG crypto_openssl build from the report..."; \
	rm -f "$$SRC_DIR/racoon/crypto_openssl_test.gcda"; \
	echo "Collecting coverage data..."; \
	lcov --directory "$$SRC_DIR" --capture \
		$$LCOV_CAPTURE \
		--output-file "$$LCOV_DIR/coverage_raw.info"; \
	lcov --remove "$$LCOV_DIR/coverage_raw.info" \
		'*/missing/*' '*/libipsec/*' '/usr/*' \
		'*/prsa_par.c' '*/prsa_par.y' \
		'*/prsa_tok.c' '*/prsa_tok.l' \
		$$LCOV_FILTER \
		--output-file "$$LCOV_DIR/coverage_filtered.info"; \
	lcov --list "$$LCOV_DIR/coverage_filtered.info"; \
	echo "Generating HTML report..."; \
	mkdir -p "$$LCOV_DIR/coverage"; \
	rm -rf "$$LCOV_DIR/coverage/*"; \
	cd "$$LCOV_DIR" && \
	genhtml "coverage_filtered.info" \
		--output-directory "coverage" \
		--title $(COVERAGE_TITLE) \
		--legend \
		--rc genhtml_hi_limit=$(COVERAGE_HI_LIMIT) \
		--rc genhtml_med_limit=$(COVERAGE_MED_LIMIT); \
	echo ""; \
	echo "Coverage report generated at $$LCOV_DIR/coverage/"; \
	echo "Open $$LCOV_DIR/coverage/index.html in a browser to view."
