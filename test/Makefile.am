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
	test_splitdns \
	test_modecfg_addrlist

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

# Test: f_status() (racoonctl.c, "racoonctl status") CLI parsing -- the
# get_combuf() av[]-shift/getopt() bug where "-v" as the sole argument was
# silently dropped (see test_racoonctl_status_cli.c's own header comment).
# f_status() is not ENABLE_HYBRID-gated, unlike test_racoonctl_logoutusr
# above; same wrapper/link approach otherwise (racoonctl_unittest_src.c,
# vmbuf.o + misc_noplog.o only, no COMMON_LDADD -- see that test's own
# comment for why).
if !SANITIZER_BUILD
check_PROGRAMS += test_racoonctl_status_cli

test_racoonctl_status_cli_SOURCES  = test_racoonctl_status_cli.c \
	racoonctl_unittest_src.c \
	racoonctl_unittest_stubs.c
test_racoonctl_status_cli_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_racoonctl_status_cli_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_racoonctl_status_cli_LDADD    = $(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_racoonctl_status_cli_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: get_comindex() address-form grammar (racoonctl.c, issue #119) --
# the "addr/prefix[port]" branch stripped ']' by searching *pref (already
# truncated to just the prefix digits, so it can never contain ']')
# instead of *port (which actually holds it), unconditionally rejecting
# every "addr/prefix[port]" input -- the documented esp/ah <saopts> form
# from usage(). See test_racoonctl_get_comindex.c's own header comment
# for the full grammar matrix this covers and the upstream-provenance
# finding (present in this repo's own upstream/0.8.2+20140711 tag and
# still unfixed in vendor/netbsd's current tree as of this writing).
#
# Same racoonctl.c wrapper source and link approach as
# test_racoonctl_logoutusr above; get_comindex() itself needs no vmbuf.o
# at all (it uses only racoon_strdup()/racoon_free(), gcmalloc.h macros
# for plain strdup()/free() in a non-debug build, not vmalloc()/vfree()),
# so it is omitted here.
#
# Unlike test_racoonctl_logoutusr, not gated on ENABLE_HYBRID:
# get_comindex() is unconditional.
#
# Also excluded from sanitizer builds, same reason as
# test_racoonctl_logoutusr above.
if !SANITIZER_BUILD
check_PROGRAMS += test_racoonctl_get_comindex

test_racoonctl_get_comindex_SOURCES  = test_racoonctl_get_comindex.c \
	racoonctl_unittest_src.c \
	racoonctl_unittest_stubs.c
test_racoonctl_get_comindex_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_racoonctl_get_comindex_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_racoonctl_get_comindex_LDADD    = $(top_builddir)/src/racoon/misc_noplog.o
test_racoonctl_get_comindex_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: get_comindexes()/get_index()/get_family()/get_proto()/
# get_ulproto() (racoonctl.c) -- the struct admin_com_indexes wire-layout
# builder above get_comindex() (test_racoonctl_get_comindex.c, issue
# #119). Also the regression test for issue #120 (p_prefs/p_prefd leaked
# on every successful parse with an explicit prefix). See
# test_racoonctl_get_comindexes.c's own header comment for both.
#
# get_comindexes() calls get_sockaddr() (kmpstat.c, a real getaddrinfo()
# call) twice per invocation; racoonctl_get_sockaddr_stub.c substitutes a
# numeric-only, DNS-free stand-in (ordinary external linkage, no
# -Wl,--wrap= needed -- see that file's own header comment). vmbuf.o is
# linked (unlike test_racoonctl_get_comindex/test_racoonctl_logoutusr's
# reasoning) because get_comindexes() itself calls vmalloc().
#
# -Wl,--wrap=free backs the issue #120 leak-count assertion specifically
# (racoon_free() is a plain free() in this non-debug build); a canary
# free() at startup SKIPs only that one assertion, not this binary's
# other (wrap-independent) tests, if the wrap does not intercept on this
# toolchain -- see doc/dev/v0.9.1-hardening-spec.md §3.2.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_racoonctl_get_comindexes

test_racoonctl_get_comindexes_SOURCES  = test_racoonctl_get_comindexes.c \
	racoonctl_unittest_src.c \
	racoonctl_unittest_stubs.c \
	racoonctl_get_sockaddr_stub.c
test_racoonctl_get_comindexes_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_racoonctl_get_comindexes_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_racoonctl_get_comindexes_LDADD    = $(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_racoonctl_get_comindexes_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections \
	-Wl,--wrap=free
endif

# Test: racoonctl.c request-encoding coverage -- make_request()
# (struct admin_com header shared by every request), get_combuf()
# (command-string dispatch), and every f_*() encoder except
# f_exchangesa() (test_racoonctl_exchangesa.c, its own dedicated test)
# and f_vpnc() (needs a real getaddrinfo()+UDP-socket source-address
# lookup, left as integration territory -- see f_vpnd()'s own test here
# instead, which covers its sibling's pure delegation-to-
# f_deleteallsadst() logic without any of that). This is racoonctl's own
# encode side of a wire protocol admin.c's tests already cover from the
# daemon's decode side; nothing here duplicates that.
#
# f_getsacert()/f_deletesa()/f_deleteallsadst()/get_proto_and_index()
# transitively reach get_sockaddr() (kmpstat.c, a real getaddrinfo()
# call); racoonctl_get_sockaddr_stub.c substitutes the same numeric-only
# stand-in as test_racoonctl_get_comindexes.c.
#
# get_combuf_unittest() needs cmdtab[] linked (it walks that table to
# dispatch a command string), and cmdtab[] is one data object holding
# function pointers to every f_*() handler including f_vpnc() --
# --gc-sections can only keep or discard that whole array, not prune
# individual pointers out of it, so linking cmdtab[] pulls in f_vpnc()
# too even though nothing here calls it. racoonctl_cmdtab_stubs.c
# supplies dead-but-linkable getlocaladdr()/saddr2str() (sockmisc.c)
# stand-ins so that transitive pull-in resolves without needing
# sockmisc.o's own much larger dependency closure -- see that file's own
# header comment.
#
# -Wl,--wrap=exit backs get_combuf()'s ac==0 path specifically (a direct
# exit(0) call in racoonctl.c itself, same technique as
# test_session_check_sigreq.c) -- NOT the various f_*() encoders'
# errx()-driven argument-count/protocol guards, which turned out not to
# be testable the same way: errx() lives inside libc (a pre-built shared
# object on a normal dynamically-linked build), so its own internal
# exit() call was already resolved when libc itself was built, before
# this binary's own -Wl,--wrap=exit (which only rewrites undefined
# references inside the object files this link session compiles) can
# apply. Confirmed empirically -- see test_racoonctl_encode_requests.c's
# own comment for the failure mode this produced. Those guards are
# exercised only on branches that return NULL/-1 instead of calling
# errx() (e.g. f_deletesa()'s unsupported-protocol case).
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_racoonctl_encode_requests

test_racoonctl_encode_requests_SOURCES  = test_racoonctl_encode_requests.c \
	racoonctl_unittest_src.c \
	racoonctl_unittest_stubs.c \
	racoonctl_get_sockaddr_stub.c \
	racoonctl_cmdtab_stubs.c
test_racoonctl_encode_requests_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_racoonctl_encode_requests_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_racoonctl_encode_requests_LDADD    = $(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_racoonctl_encode_requests_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections \
	-Wl,--wrap=exit
endif

# Test: f_exchangesa() (racoonctl.c) -- the establish-sa encoder, the
# most structurally involved of racoonctl's request builders: "-u
# identity"/PSK injection, "-n remoteconf" name append, "-w"
# wait-for-completion flag. See test_racoonctl_exchangesa.c's own header
# comment for the PSK id_len/key_len-includes-NUL convention this test
# pins down by decoding the real f_exchangesa() output through the exact
# struct layout admin.c's own ADMIN_ESTABLISH_SA_PSK test
# (test_admin_establish_sa_psk.c) assumes -- a genuine, previously
# unpinned assumption gap between the two sides of this wire protocol.
#
# Same racoonctl_get_sockaddr_stub.c as the other racoonctl.c tests
# above (get_proto_and_index() -> get_sockaddr()); also links
# racoonctl_getpass_stub.c for the "-u identity" branch's getpass() call
# (real terminal I/O) -- see that file's own header comment for the
# spike that confirmed this plain-symbol-shadowing substitution (no
# -Wl,--wrap=) is safe on this toolchain.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_racoonctl_exchangesa

test_racoonctl_exchangesa_SOURCES  = test_racoonctl_exchangesa.c \
	racoonctl_unittest_src.c \
	racoonctl_unittest_stubs.c \
	racoonctl_get_sockaddr_stub.c \
	racoonctl_getpass_stub.c
test_racoonctl_exchangesa_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_racoonctl_exchangesa_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_racoonctl_exchangesa_LDADD    = $(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_racoonctl_exchangesa_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: racoonctl.c reply-decoding/output-formatting coverage --
# pindex_isakmp(), fixed_addr(), dump_isakmp_sa(), dump_internal(),
# print_schedule(), print_evt(), print_cfg(), and handle_recv() itself
# (the ADMIN_* reply dispatcher, the client-side mirror of admin.c's own
# dispatch from the other direction). All previously entirely untested.
#
# Also the regression test for issue #118 (print_cfg()'s uninitialized
# ioctl(TIOCGWINSZ) read) -- see test_racoonctl_format_output.c's own
# header comment for why this is the one place in this pass where a
# well-behaved-output assertion, not just a return value, is what proves
# the fix.
#
# print_evt() calls saddr2str() (sockmisc.c); racoonctl_cmdtab_stubs.c's
# existing stand-in (see test_racoonctl_encode_requests.c above) is
# reused rather than adding a second one. Nothing in this file reaches
# get_sockaddr()/getpass(), so those stubs are not linked here.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_racoonctl_format_output

test_racoonctl_format_output_SOURCES  = test_racoonctl_format_output.c \
	racoonctl_unittest_src.c \
	racoonctl_unittest_stubs.c \
	racoonctl_cmdtab_stubs.c
test_racoonctl_format_output_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_racoonctl_format_output_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_racoonctl_format_output_LDADD    = $(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_racoonctl_format_output_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: kmpstat com_recv() short-read/EOF diagnostics (v0.9.1-hardening-spec.md
# §5.6, Issue 4) — com_recv()'s "sanity check" goto bad1 on a truncated header
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

# Test 18b: mode-cfg dns4/wins4 address list bounds — isakmp_cfg_config_add_addr4()
# and MAXCFGADDR in isakmp_cfg.h.  Header-only, so it needs no racoon objects
# beyond $(COMMON_LDADD): pulling in isakmp_cfg.o would drag in most of racoon.
test_modecfg_addrlist_SOURCES  = test_modecfg_addrlist.c
test_modecfg_addrlist_LDADD    = $(COMMON_LDADD)
test_modecfg_addrlist_LDFLAGS  = $(AM_LDFLAGS)

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
# (v0.9.1-hardening-spec.md §5.6, Issue 1 / F2) -- close_session()'s shutdown path used
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

# Test: privsep_sigterm_forward() (v0.9.1-hardening-spec.md §5.6, Issue 1, privsep half)
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
#
# Under --enable-coverage (ENABLE_COVERAGE, configure.ac), also links
# privsep_gcov_dump_shim.c and adds -Wl,--wrap=_exit: privsep_priv()'s own
# _exit() at every exit point bypasses gcov's atexit()-registered flush, so
# without this a coverage build's forked privsep_priv() child never writes
# its .gcda and `make coverage` reports privsep.c as unexecuted even though
# it demonstrably ran (doc/dev/v0.9.1-hardening-spec.md §2.2/§2.4 has the full
# writeup -- this wires that report's diagnostic workaround into the
# regular build instead of a one-off rebuild). The same two lines are
# repeated on every check_PROGRAMS target below that pulls in privsep.c via
# privsep_unittest_src.c, for the same reason.
# SANITIZER_BUILD variant per the sanitizer-build spike (doc/dev/
# v0.9.1-hardening-spec.md §2.4; see test_privsep_do_exit's
# own comment above for the full reasoning). Without --gc-sections, the
# linker needs every symbol privsep.c's whole translation unit
# references, not just what this test calls, so this variant also links
# privsep_priv_test_stubs.c and privsep_sanitizer_monitor_fd_stub.c even
# though the ordinary build needs neither.
if SANITIZER_BUILD
check_PROGRAMS += test_privsep_sigterm_forward

test_privsep_sigterm_forward_SOURCES  = test_privsep_sigterm_forward.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_sigterm_forward_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_sigterm_forward_CFLAGS   = $(AM_CFLAGS)
test_privsep_sigterm_forward_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_sigterm_forward_LDFLAGS  = $(AM_LDFLAGS)
else
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
if ENABLE_COVERAGE
test_privsep_sigterm_forward_SOURCES += privsep_gcov_dump_shim.c
test_privsep_sigterm_forward_LDFLAGS += -Wl,--wrap=_exit
endif
endif

# Test: prune_stale_monitored_fds() (v0.9.1-hardening-spec.md §5.6, Issue 4 follow-up)
# -- session()'s main loop used to treat any select() failure other than
# EINTR as fatal (return -1, no cleanup; main.c just calls session();
# return 0;, so the whole daemon process exits). A live bug (since fixed
# in admin.c) closed an admin-socket fd directly instead of going through
# unmonitor_fd(), and the very next select() failed with EBADF, taking
# the entire daemon down over one dangling fd unrelated to any other live
# Phase 1/2 SA. prune_stale_monitored_fds() recovers from exactly that:
# scans every monitored fd for validity and drops any no longer open,
# letting the main loop keep running instead of exiting unconditionally.
#
# session.c is pulled in via a local wrapper source
# (session_unittest_src.c, -ffunction-sections/--gc-sections, same
# pattern as the other wrapped-static-function tests above);
# monitor_fd()/unmonitor_fd() are already exported (evt.c already calls
# them in production), prune_stale_monitored_fds_unittest()/
# is_fd_monitored_unittest() are new -DENABLE_UNITTEST-only accessors.
# Drives the real function with real pipe() fds and a real close(), not
# a simulated fd-validity check.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_prune_stale_monitored_fds

test_prune_stale_monitored_fds_SOURCES  = test_prune_stale_monitored_fds.c \
	session_unittest_src.c
test_prune_stale_monitored_fds_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_prune_stale_monitored_fds_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_prune_stale_monitored_fds_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_prune_stale_monitored_fds_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: cmpsatrns() "authtype mismatched" log level (v0.9.1-hardening-spec.md
# §5.6, Issue 3) -- this line used to log at LLV_WARNING (the default visible
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

# Test: monitor_fd()/unmonitor_fd() fd range handling (issue #105, the
# audit that followed #102's prune_stale_monitored_fds()) -- both used to
# exit(1) on a descriptor outside the fd_set range. monitor_fd() is called
# not only for the sockets opened once at startup but for every accepted
# admin connection that asks for events (evt_subscribe(), evt.c) and every
# ISAKMP socket opened for an address that appears while running
# (isakmp_open(), isakmp.c), so that exit turned "this one connection
# cannot be watched" into "every live Phase 1/2 SA dies". They now report
# the failure and let the caller drop just that connection or socket.
#
# Same session.c wrapper source and -DENABLE_UNITTEST accessors as
# test_prune_stale_monitored_fds above; a regression that restores the
# exit(1) kills this test binary outright, which the harness records as a
# failure.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_monitor_fd_range

test_monitor_fd_range_SOURCES  = test_monitor_fd_range.c \
	session_unittest_src.c
test_monitor_fd_range_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_monitor_fd_range_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_monitor_fd_range_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_monitor_fd_range_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: monitor_fd()'s self-enforcing fd_monitor_tree[] initialization
# (doc/dev/v0.9.1-hardening-spec.md §2.4) -- unlike every
# other monitor_fd() test above, this binary deliberately never calls
# init_fd_monitor_unittest(), so its one monitor_fd() call is the first
# thing in the whole process that could touch fd_monitor_tree[] at all.
# See the file's own header comment for why that specific "called cold"
# condition needs its own binary rather than another test function in
# test_monitor_fd_range.c above (whose own main() already initializes
# before its first test runs).
#
# Same session.c wrapper source and -DENABLE_UNITTEST accessor as the
# other monitor_fd() tests; also excluded from sanitizer builds, same
# reason as those.
if !SANITIZER_BUILD
check_PROGRAMS += test_monitor_fd_cold_start

test_monitor_fd_cold_start_SOURCES  = test_monitor_fd_cold_start.c \
	session_unittest_src.c
test_monitor_fd_cold_start_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_monitor_fd_cold_start_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_monitor_fd_cold_start_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_monitor_fd_cold_start_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: session_wait_and_dispatch() -- session()'s live main loop body
# (select() + error recovery + fd dispatch), extracted out of session()
# unchanged (v0.9.1 unit-test-coverage hardening, Tier 3) so it can be
# driven directly instead of needing the full daemon startup (cfparse()/
# admin_init()/myaddr_init()/privsep_init()) session()'s own while(1)
# otherwise requires to ever reach this code at all. Covers a real
# dispatch (socketpair() fd made readable), the EBADF-recovery path
# reaching prune_stale_monitored_fds() from this call site specifically
# (v0.9.1-hardening-spec.md §5.6, Issue 4 follow-up; prune_stale_monitored_fds() itself
# is already covered in isolation by test_prune_stale_monitored_fds.c),
# a real signal interrupting select() (EINTR must retry, not fail), and
# an unrecovered select() failure (invalid timeval -> EINVAL) that must
# propagate as fatal.
#
# Every assertion here goes through session_wait_and_dispatch()'s own
# observable effects (its return value, dispatch-callback call count,
# is_fd_monitored_unittest()) -- no -Wl,--wrap= involved, so none of the
# whole-program-LTO wrap-defeat risk documented in doc/dev/v0.9.1-hardening-spec.md §3.2 applies here.
#
# Same session.c wrapper source and -DENABLE_UNITTEST accessors as the
# other monitor_fd()/session.c tests above; also excluded from sanitizer
# builds, same reason as those.
if !SANITIZER_BUILD
check_PROGRAMS += test_session_wait_and_dispatch

test_session_wait_and_dispatch_SOURCES  = test_session_wait_and_dispatch.c \
	session_unittest_src.c
test_session_wait_and_dispatch_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_session_wait_and_dispatch_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_session_wait_and_dispatch_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_session_wait_and_dispatch_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: privsep descriptor passing (issue #105) -- privsep.c's privileged
# dispatch loop used to _exit(0) on any local fault, killing the daemon
# (the unprivileged child exits as soon as privsep_sock reads EOF). Those
# faults can now be answered with an errno instead, but only because the
# two sides stay in step on the wire: PRIVSEP_SOCKET's client blocks in
# rec_fd() before reading the reply, so its failing paths send a
# descriptor message carrying no descriptor (send_fd(-1)), which rec_fd()
# reports as -1 instead of dereferencing CMSG_DATA(NULL). Exercises that
# handshake over a real socketpair with real SCM_RIGHTS messages;
# privsep_priv()'s loop itself needs privsep_init()'s privilege-dropping
# fork(), which not every test host can perform (same constraint as
# test_privsep_sigterm_forward above).
#
# Same privsep.c wrapper source (privsep_unittest_src.c) and explicit
# plog.o/logger.o linkage as test_privsep_sigterm_forward above;
# privsep_send_fd_unittest()/privsep_rec_fd_unittest() are new
# -DENABLE_UNITTEST-only accessors for send_fd()/rec_fd() (both static).
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
# SANITIZER_BUILD variant, same reasoning as test_privsep_sigterm_forward
# above (doc/dev/v0.9.1-hardening-spec.md §2.4).
if SANITIZER_BUILD
check_PROGRAMS += test_privsep_fd_passing

test_privsep_fd_passing_SOURCES  = test_privsep_fd_passing.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_fd_passing_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_fd_passing_CFLAGS   = $(AM_CFLAGS)
test_privsep_fd_passing_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_fd_passing_LDFLAGS  = $(AM_LDFLAGS)
else
check_PROGRAMS += test_privsep_fd_passing

test_privsep_fd_passing_SOURCES  = test_privsep_fd_passing.c \
	privsep_unittest_src.c
test_privsep_fd_passing_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_fd_passing_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_fd_passing_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_fd_passing_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_fd_passing_SOURCES += privsep_gcov_dump_shim.c
test_privsep_fd_passing_LDFLAGS += -Wl,--wrap=_exit
endif
endif

# Test: privsep_do_exit() (privsep.c) in isolation, decoupled from
# monitor_fd() -- doc/dev/v0.9.1-hardening-spec.md §2.4's review
# follow-up on §2.3: in production this is reachable only as the callback
# monitor_fd() dispatches to when privsep_sock[1] shows readable/EOF, so a
# test that only ever drove it through that full dispatch path could not
# tell "the callback's own logic is wrong" apart from "the dispatch
# machinery around it is wrong". privsep_do_exit_unittest() is a new
# -DENABLE_UNITTEST-only accessor (privsep_do_exit() is static).
#
# Same privsep.c wrapper source (privsep_unittest_src.c) and explicit
# plog.o/logger.o linkage as the other privsep tests above --
# privsep_do_exit()'s own body (kill()+return, nothing else) needs no
# other stubs under the ordinary (--gc-sections) build, so unlike
# test_privsep_priv_*.c this target does not link privsep_priv_test_stubs.c
# there; --gc-sections has nothing pulling those symbols in.
#
# PILOT for the sanitizer-build spike (doc/dev/v0.9.1-hardening-spec.md §2.4's review follow-up): every other privsep test in this
# suite is unconditionally excluded from sanitizer builds
# (if !SANITIZER_BUILD), citing a conflict between -ffunction-sections/
# --gc-sections (needed to keep a normal build's dependency closure small)
# and ASan/UBSan instrumentation. This target is the one used to test
# whether that conflict is actually about --gc-sections specifically, or
# about something else -- see the audit document for the answer and how
# it was reached. Unlike its ordinary build, the SANITIZER_BUILD variant
# below does link privsep_priv_test_stubs.c: without --gc-sections
# stripping privsep.c's unreached functions, the linker needs every
# symbol the whole translation unit references, not just what this test
# actually calls (the same set test_privsep_priv_*.c already needs). It
# also needs a monitor_fd() symbol for the same reason -- privsep_init()
# (unreached by this test, but still part of the linked translation unit
# without --gc-sections) calls it -- but the real one lives in session.c,
# whose own dependency closure is impractical to link into a privsep-only
# test binary; privsep_sanitizer_monitor_fd_stub.c supplies a minimal
# link-only stand-in instead. See that file's header comment for the full
# reasoning.
if SANITIZER_BUILD
check_PROGRAMS += test_privsep_do_exit

test_privsep_do_exit_SOURCES  = test_privsep_do_exit.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_do_exit_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_do_exit_CFLAGS   = $(AM_CFLAGS)
test_privsep_do_exit_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_do_exit_LDFLAGS  = $(AM_LDFLAGS)
else
check_PROGRAMS += test_privsep_do_exit

test_privsep_do_exit_SOURCES  = test_privsep_do_exit.c \
	privsep_unittest_src.c
test_privsep_do_exit_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_do_exit_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_do_exit_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_do_exit_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_do_exit_SOURCES += privsep_gcov_dump_shim.c
test_privsep_do_exit_LDFLAGS += -Wl,--wrap=_exit
endif
endif

# Test: PRIVSEP_SOCKET's policy gate (issue #105) -- the privileged
# process used to allow PF_INET/PF_INET6 only, refusing the PF_KEY socket
# pfkey_dump_sadb() needs and that the unprivileged process cannot open
# for itself. That broke every SADB dump under privsep ("racoonctl vd",
# "show-sa esp|ah|ipsec", purge_remote()'s fallback path and so DPD and
# peer-initiated teardown) and, before the same issue's containment work,
# took the whole daemon down each time. It survived that long because the
# gate is unreachable outside privsep_init()'s privilege-dropping fork():
# a live "racoonctl vd" on a real host is what finally evaluated it.
# privsep_socket_allowed() is a separate predicate so the policy can be
# asserted here, in both directions -- what must be allowed, and what must
# not.
#
# Same privsep.c wrapper source and explicit plog.o/logger.o linkage as
# the two privsep tests above; privsep_socket_allowed_unittest() is a new
# -DENABLE_UNITTEST-only accessor.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
# SANITIZER_BUILD variant, same reasoning as test_privsep_sigterm_forward
# above (doc/dev/v0.9.1-hardening-spec.md §2.4).
#
# HAVE_PF_PACKET-gated (configure.ac): this test's own PF_PACKET refusal
# case, and its #include <net/pfkeyv2.h>, are both Linux-specific -- see
# configure.ac's own comment on HAVE_PF_PACKET for the two ways this
# fails to compile on a host without it (NetBSD confirmed), rather than
# actually testing anything there.
if HAVE_PF_PACKET
if SANITIZER_BUILD
check_PROGRAMS += test_privsep_socket_policy

test_privsep_socket_policy_SOURCES  = test_privsep_socket_policy.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_socket_policy_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_socket_policy_CFLAGS   = $(AM_CFLAGS)
test_privsep_socket_policy_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_socket_policy_LDFLAGS  = $(AM_LDFLAGS)
else
check_PROGRAMS += test_privsep_socket_policy

test_privsep_socket_policy_SOURCES  = test_privsep_socket_policy.c \
	privsep_unittest_src.c
test_privsep_socket_policy_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_socket_policy_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_socket_policy_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_socket_policy_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_socket_policy_SOURCES += privsep_gcov_dump_shim.c
test_privsep_socket_policy_LDFLAGS += -Wl,--wrap=_exit
endif
endif
endif

# Test: privsep_setsockopt()'s return contract (issue #105) -- it opened
# with "err = setsockopt(...) == 0", assigning the comparison rather than
# the call's result, so err was 1 on success and 0 on failure and every
# caller (which all test "< 0") read an unescalated failure as success.
# That hid a second defect: the escalation condition tested EACCES alone,
# which is what KAME returns for IP_IPSEC_POLICY on an unprivileged
# socket, while Linux's xfrm returns EPERM -- so under privsep on Linux
# the privileged process was never asked, setsockopt_bypass()'s in/out
# bypass policies were never applied to racoon's own sockets, and the
# caller was told it had worked.
#
# Needs no privsep host and no PF_KEY/XFRM kernel, and behaves identically
# as root and as an ordinary user: it drives the real function against a
# real socket with an option that fails for a non-privilege reason.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
# SANITIZER_BUILD variant, same reasoning as test_privsep_sigterm_forward
# above (doc/dev/v0.9.1-hardening-spec.md §2.4).
if SANITIZER_BUILD
check_PROGRAMS += test_privsep_setsockopt

test_privsep_setsockopt_SOURCES  = test_privsep_setsockopt.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_setsockopt_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_setsockopt_CFLAGS   = $(AM_CFLAGS)
test_privsep_setsockopt_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_setsockopt_LDFLAGS  = $(AM_LDFLAGS)
else
check_PROGRAMS += test_privsep_setsockopt

test_privsep_setsockopt_SOURCES  = test_privsep_setsockopt.c \
	privsep_unittest_src.c
test_privsep_setsockopt_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_setsockopt_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_setsockopt_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_setsockopt_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_setsockopt_SOURCES += privsep_gcov_dump_shim.c
test_privsep_setsockopt_LDFLAGS += -Wl,--wrap=_exit
endif
endif

# Tests: privsep_priv() -- the privileged dispatch loop itself, extracted
# out of privsep_init()'s inline while(1) as pure code motion (doc/dev/
# v0.9.1-hardening-spec.md §2.2, follow-up to issue #105 and
# v0.9.1-hardening-spec.md §2.3, §7 "Making this permanent"). Before this
# extraction the loop was reachable only inside privsep_init()'s real
# privilege-dropping fork(), so every one of the runbook's phases had to be
# run by hand on a live host; now a test can fork(), have the child call
# privsep_priv(sock) directly over a socketpair() -- the same
# _exit(0)/_exit(1) at "out:"/"fail:", completely untouched -- and have the
# parent play the unprivileged side, driving the real wire protocol and
# checking both what comes back over it and waitpid()'s reported exit
# status. No behaviour change: privsep_init() itself just calls
# privsep_priv(privsep_sock[0]) where its while(1) loop used to start.
#
# All four binaries below share privsep_priv_test_stubs.c (lcconf,
# eay_get_pkcs1privkey(), getpsk(), script_exec(), and the ENABLE_HYBRID-
# only link targets privsep_priv()'s switch still references) alongside the
# usual privsep_unittest_src.c wrapper; same -ffunction-sections/
# --gc-sections and explicit plog.o/logger.o/vmbuf.o/misc_noplog.o linkage
# as the other privsep tests above, and excluded from sanitizer builds for
# the same reason (relies on --gc-sections dead-code elimination that ASan
# defeats).
# SANITIZER_BUILD variant, same reasoning as test_privsep_sigterm_forward
# above (doc/dev/v0.9.1-hardening-spec.md §2.4). Already links
# privsep_priv_test_stubs.c in the ordinary build below, so only adds
# privsep_sanitizer_monitor_fd_stub.c and drops -ffunction-sections/
# --gc-sections.
if SANITIZER_BUILD
check_PROGRAMS += test_privsep_priv_control_cases

test_privsep_priv_control_cases_SOURCES  = test_privsep_priv_control_cases.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_priv_control_cases_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_priv_control_cases_CFLAGS   = $(AM_CFLAGS)
test_privsep_priv_control_cases_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_priv_control_cases_LDFLAGS  = $(AM_LDFLAGS)
else
check_PROGRAMS += test_privsep_priv_control_cases

test_privsep_priv_control_cases_SOURCES  = test_privsep_priv_control_cases.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c
test_privsep_priv_control_cases_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_priv_control_cases_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_priv_control_cases_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_priv_control_cases_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_priv_control_cases_SOURCES += privsep_gcov_dump_shim.c
test_privsep_priv_control_cases_LDFLAGS += -Wl,--wrap=_exit
endif
endif

if SANITIZER_BUILD
check_PROGRAMS += test_privsep_priv_framing

test_privsep_priv_framing_SOURCES  = test_privsep_priv_framing.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_priv_framing_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_priv_framing_CFLAGS   = $(AM_CFLAGS)
test_privsep_priv_framing_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_priv_framing_LDFLAGS  = $(AM_LDFLAGS)
else
check_PROGRAMS += test_privsep_priv_framing

test_privsep_priv_framing_SOURCES  = test_privsep_priv_framing.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c
test_privsep_priv_framing_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_priv_framing_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_priv_framing_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_priv_framing_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_priv_framing_SOURCES += privsep_gcov_dump_shim.c
test_privsep_priv_framing_LDFLAGS += -Wl,--wrap=_exit
endif
endif

if SANITIZER_BUILD
check_PROGRAMS += test_privsep_priv_containment

test_privsep_priv_containment_SOURCES  = test_privsep_priv_containment.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_priv_containment_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_priv_containment_CFLAGS   = $(AM_CFLAGS)
test_privsep_priv_containment_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_priv_containment_LDFLAGS  = $(AM_LDFLAGS)
else
check_PROGRAMS += test_privsep_priv_containment

test_privsep_priv_containment_SOURCES  = test_privsep_priv_containment.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c
test_privsep_priv_containment_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_priv_containment_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_priv_containment_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_priv_containment_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_priv_containment_SOURCES += privsep_gcov_dump_shim.c
test_privsep_priv_containment_LDFLAGS += -Wl,--wrap=_exit
endif
endif

# Bounded-wait variant needs privsep_priv()'s own mid-request timeout to
# actually fire, so this one binary alone overrides PRIVSEP_IPC_WAIT_MAX_MS
# (privsep.c) down from the production 3s via
# -DPRIVSEP_IPC_WAIT_MAX_MS_UNITTEST_OVERRIDE -- a compile-time seam gated
# to this target's own CPPFLAGS (test/README.md), never the production
# build. 200ms is far above what a healthy exchange over a local
# socketpair needs and far below this suite's own IO_TIMEOUT_MS bounds.
# SANITIZER_BUILD variant, same reasoning as test_privsep_sigterm_forward
# above (doc/dev/v0.9.1-hardening-spec.md §2.4).
if SANITIZER_BUILD
check_PROGRAMS += test_privsep_priv_bounded_wait

test_privsep_priv_bounded_wait_SOURCES  = test_privsep_priv_bounded_wait.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_priv_bounded_wait_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST \
	-DPRIVSEP_IPC_WAIT_MAX_MS_UNITTEST_OVERRIDE=200
test_privsep_priv_bounded_wait_CFLAGS   = $(AM_CFLAGS)
test_privsep_priv_bounded_wait_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_priv_bounded_wait_LDFLAGS  = $(AM_LDFLAGS)
else
check_PROGRAMS += test_privsep_priv_bounded_wait

test_privsep_priv_bounded_wait_SOURCES  = test_privsep_priv_bounded_wait.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c
test_privsep_priv_bounded_wait_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST \
	-DPRIVSEP_IPC_WAIT_MAX_MS_UNITTEST_OVERRIDE=200
test_privsep_priv_bounded_wait_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_priv_bounded_wait_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_priv_bounded_wait_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_priv_bounded_wait_SOURCES += privsep_gcov_dump_shim.c
test_privsep_priv_bounded_wait_LDFLAGS += -Wl,--wrap=_exit
endif
endif

# Tests: privsep.c's client-side wrappers -- privsep_eay_get_pkcs1privkey(),
# privsep_getpsk(), privsep_script_exec(), privsep_socket(), privsep_bind()
# (privsep-priv-extraction follow-up: these five, plus the ENABLE_HYBRID/
# HAVE_LIBPAM ones in test_privsep_hybrid_client_wrappers.c below, were the
# untested half of privsep.c's own wire protocol -- test_privsep_priv_*.c
# above only ever drove the *privileged* side, playing the unprivileged
# side itself by hand-crafting wire messages).
#
# privsep_wire_roundtrip.c (shared with test_privsep_hybrid_client_wrappers.c
# and, for its uid-dropping helpers only, test_privsep_init.c) forks a
# child running the real privsep_priv() over a socketpair(), the same
# pattern as test_privsep_priv_*.c, then points this process's own
# privsep_sock[1] (privsep.c, ENABLE_UNITTEST) at the other end so the
# client-side wrapper under test can be called directly and for real.
# Needs privsep_priv_test_stubs.c for the same reason as test_privsep_priv_*.c
# (privsep_priv()'s switch still references eay_get_pkcs1privkey()/getpsk()/
# script_exec() and, since ENABLE_HYBRID is on by default, its two _system
# link targets).
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above (relies on --gc-sections dead-code
# elimination that ASan defeats), and gets the same ENABLE_COVERAGE
# -Wl,--wrap=_exit treatment as every other check_PROGRAMS target that
# compiles privsep.c via privsep_unittest_src.c.
# SANITIZER_BUILD variant, same reasoning as test_privsep_sigterm_forward
# above (doc/dev/v0.9.1-hardening-spec.md §2.4).
if SANITIZER_BUILD
check_PROGRAMS += test_privsep_client_wrappers

test_privsep_client_wrappers_SOURCES  = test_privsep_client_wrappers.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_wire_roundtrip.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_client_wrappers_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_client_wrappers_CFLAGS   = $(AM_CFLAGS)
test_privsep_client_wrappers_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_client_wrappers_LDFLAGS  = $(AM_LDFLAGS)
else
check_PROGRAMS += test_privsep_client_wrappers

test_privsep_client_wrappers_SOURCES  = test_privsep_client_wrappers.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_wire_roundtrip.c
test_privsep_client_wrappers_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_client_wrappers_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_client_wrappers_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_client_wrappers_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_client_wrappers_SOURCES += privsep_gcov_dump_shim.c
test_privsep_client_wrappers_LDFLAGS += -Wl,--wrap=_exit
endif
endif

# Test: privsep.c's ENABLE_HYBRID-only client-side wrappers --
# privsep_xauth_login_system(), privsep_accounting_system(), port_check(),
# and (nested under HAVE_LIBPAM) privsep_accounting_pam()/
# privsep_xauth_login_pam()/privsep_cleanup_pam(). Same
# privsep_wire_roundtrip.c driver and stub layer as
# test_privsep_client_wrappers.c above; this file's own content is guarded
# by #ifdef ENABLE_HYBRID (and, for the three PAM cases, a nested #ifdef
# HAVE_LIBPAM) at the C level rather than a second automake conditional,
# so a build with either off still gets this binary in `make check`'s
# output -- see the file's own header comment.
#
# Also excluded from sanitizer builds and gets the same ENABLE_COVERAGE
# treatment, same reasons as test_privsep_client_wrappers above.
# SANITIZER_BUILD variant, same reasoning as test_privsep_client_wrappers
# above (doc/dev/v0.9.1-hardening-spec.md §2.4).
if SANITIZER_BUILD
check_PROGRAMS += test_privsep_hybrid_client_wrappers

test_privsep_hybrid_client_wrappers_SOURCES  = test_privsep_hybrid_client_wrappers.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_wire_roundtrip.c \
	privsep_sanitizer_monitor_fd_stub.c
test_privsep_hybrid_client_wrappers_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_hybrid_client_wrappers_CFLAGS   = $(AM_CFLAGS)
test_privsep_hybrid_client_wrappers_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_hybrid_client_wrappers_LDFLAGS  = $(AM_LDFLAGS)
else
check_PROGRAMS += test_privsep_hybrid_client_wrappers

test_privsep_hybrid_client_wrappers_SOURCES  = test_privsep_hybrid_client_wrappers.c \
	privsep_unittest_src.c \
	privsep_priv_test_stubs.c \
	privsep_wire_roundtrip.c
test_privsep_hybrid_client_wrappers_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_hybrid_client_wrappers_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_hybrid_client_wrappers_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_hybrid_client_wrappers_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_hybrid_client_wrappers_SOURCES += privsep_gcov_dump_shim.c
test_privsep_hybrid_client_wrappers_LDFLAGS += -Wl,--wrap=_exit
endif
endif

# Test: privsep_init() itself -- the one privsep.c entry point every test
# above deliberately bypasses (they all drive privsep_priv() directly over
# a plain socketpair(), precisely because privsep_init()'s own
# socketpair()+fork()+setgid()/setuid()+monitor_fd() sequence needs real
# privilege to run at all). Every side effect that matters happens inside
# a forked child this test process itself never becomes -- see the file's
# own header comment for the full three-process (test binary / forked
# "outer child" / privsep_init()'s own further-forked child) breakdown.
#
# Needs session_unittest_src.c (-ffunction-sections, same as
# test_monitor_fd_range/test_prune_stale_monitored_fds above) alongside the
# usual privsep_unittest_src.c + privsep_priv_test_stubs.c: privsep_init()'s
# own privilege-dropping child branch calls monitor_fd() (session.c,
# already exported) on privsep_sock[1].
#
# Also excluded from sanitizer builds and gets the same ENABLE_COVERAGE
# treatment, same reasons as the other privsep.c wrapped-static-function
# tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_privsep_init

test_privsep_init_SOURCES  = test_privsep_init.c \
	privsep_unittest_src.c \
	session_unittest_src.c \
	privsep_priv_test_stubs.c
test_privsep_init_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_init_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_init_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_init_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
if ENABLE_COVERAGE
test_privsep_init_SOURCES += privsep_gcov_dump_shim.c
test_privsep_init_LDFLAGS += -Wl,--wrap=_exit
endif
endif

# Test: privsep_init()'s "case -1:" -- fork() itself failing -- which
# test_privsep_init.c's own scenarios never reach (they need a real,
# successful fork() for their own forked-child topology). A separate
# binary because -Wl,--wrap=fork redirects *every* fork() call in
# whatever it is linked into, which would break test_privsep_init.c's own
# real-fork scenarios if applied there instead. __wrap_fork() is defined
# directly in test_privsep_init_fork_failure.c itself (same as
# test_script_hook_leak.c's own __wrap_free()), always failing with
# EAGAIN, so privsep_init()'s internal fork() has only one branch it can
# ever take here. Same SOURCES/LDADD as test_privsep_init above (privsep.c
# still references monitor_fd()/privsep_priv() from its "case 0:"/
# default: branches even though neither ever runs in this binary -- the
# linker still needs them resolved) plus this one extra -Wl,--wrap=fork.
#
# Also excluded from sanitizer builds and gets the same ENABLE_COVERAGE
# treatment, same reasons as the other privsep.c wrapped-static-function
# tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_privsep_init_fork_failure

test_privsep_init_fork_failure_SOURCES  = test_privsep_init_fork_failure.c \
	privsep_unittest_src.c \
	session_unittest_src.c \
	privsep_priv_test_stubs.c
test_privsep_init_fork_failure_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_privsep_init_fork_failure_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_privsep_init_fork_failure_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_privsep_init_fork_failure_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections \
	-Wl,--wrap=fork
if ENABLE_COVERAGE
test_privsep_init_fork_failure_SOURCES += privsep_gcov_dump_shim.c
test_privsep_init_fork_failure_LDFLAGS += -Wl,--wrap=_exit
endif
endif

# Tests: admin.c hardening (v0.9.1) -- admin.c is daemon-only
# (racoon_SOURCES, src/racoon/Makefile.am) and previously had zero unit
# test coverage: nothing ever linked admin.o into a test binary, so no
# .gcda for it was ever produced. admin_unittest_src.c pulls it in the
# same way as isakmp_unittest_src.c/session_unittest_src.c above.
#
# test_admin_check_sockpath and test_admin_mkdir_p exercise the two
# brand-new, fully self-contained functions in this hunk (pure string
# validation / mkdir -p): -ffunction-sections/--gc-sections keeps their
# link surface to libc alone, the same technique as test_ipsec_doi_sa.
# mkdir_p() is static, exposed via mkdir_p_unittest() (admin.c,
# ENABLE_UNITTEST).
if !SANITIZER_BUILD
check_PROGRAMS += test_admin_check_sockpath

test_admin_check_sockpath_SOURCES  = test_admin_check_sockpath.c \
	admin_unittest_src.c
test_admin_check_sockpath_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_admin_check_sockpath_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_admin_check_sockpath_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_admin_check_sockpath_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections

check_PROGRAMS += test_admin_mkdir_p

test_admin_mkdir_p_SOURCES  = test_admin_mkdir_p.c \
	admin_unittest_src.c
test_admin_mkdir_p_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_admin_mkdir_p_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_admin_mkdir_p_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_admin_mkdir_p_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# test_admin_init drives admin_init() itself (already exported) end to
# end: path rejection, the lstat()/S_ISSOCK pre-existing-path gate, and
# monitor_fd() failure cleanup. admin_test_stubs.c supplies a real
# `lcconf` (admin.c dereferences lcconf->sock_admin unconditionally,
# unlike rsalist_test_stubs.c's NULL stand-in) and a controllable
# monitor_fd()/unmonitor_fd() pair so the failure path can be forced
# without session.c's fd_monitor_tree[] machinery.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above (relies on --gc-sections dead-code
# elimination that ASan defeats).
if !SANITIZER_BUILD
check_PROGRAMS += test_admin_init

test_admin_init_SOURCES  = test_admin_init.c \
	admin_unittest_src.c \
	admin_test_stubs.c
test_admin_init_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_admin_init_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_admin_init_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_admin_init_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# test_admin_delete_all_sa_dst is the priority regression test for this
# hunk: the ADMIN_DELETE_ALL_SA_DST reply-before-subscribe/no-dangling-fd
# fix (admin_process()'s own header comment on that case has the full
# incident writeup). admin_process() is static, exposed via
# admin_process_unittest() (admin.c, ENABLE_UNITTEST).
#
# admin_process() is one function containing every ADMIN_* case, so
# -ffunction-sections/--gc-sections cannot discard the cases this test
# never drives -- admin_test_stubs.c supplies link-time stand-ins for all
# of them (getph1(), evt_subscribe(), isakmp_info_send_d1(),
# purge_remote(), and everything else admin_process() references), so the
# whole function can link without pulling in the rest of racoon's
# ISAKMP/PF_KEY/policy state machinery. admin_reply() itself is NOT
# stubbed -- it runs for real over a real socketpair(), so the test
# observes the actual reply bytes and the actual send()-failure path.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_admin_delete_all_sa_dst

test_admin_delete_all_sa_dst_SOURCES  = test_admin_delete_all_sa_dst.c \
	admin_unittest_src.c \
	admin_test_stubs.c
test_admin_delete_all_sa_dst_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_admin_delete_all_sa_dst_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_admin_delete_all_sa_dst_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_admin_delete_all_sa_dst_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# test_admin_process_dispatch rounds out admin_process()'s remaining
# ADMIN_* cases at the dispatch level (right stub called, right l_ac_errno
# on the wire) -- same admin_process_unittest() accessor and
# admin_test_stubs.c as test_admin_delete_all_sa_dst.c above; see that
# test's own header comment for why admin_process() (one function
# containing every case) needs the full stub set just to link.
if !SANITIZER_BUILD
check_PROGRAMS += test_admin_process_dispatch

test_admin_process_dispatch_SOURCES  = test_admin_process_dispatch.c \
	admin_unittest_src.c \
	admin_test_stubs.c
test_admin_process_dispatch_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_admin_process_dispatch_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_admin_process_dispatch_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_admin_process_dispatch_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# test_status_dump covers status_dump() (status.c, ADMIN_STATUS/
# ADMIN_STATUS_VERBOSE, racoonctl status) -- the JSON/text extraction and
# rendering added alongside this test. status_test_stubs.c's enumph1()/
# enumph2() stand-ins let each test hand status_dump() an exact list of
# struct ph1handle/ph2handle pointers without a real ph1tree/ph2tree or
# handler.c's dependency closure; s_attr_isakmp_enc() and friends
# (strnames.o, RACOON_OBJS) are linked for real, since the enum-to-string
# mappings are exactly what this test wants genuine coverage of.
if !SANITIZER_BUILD
check_PROGRAMS += test_status_dump

test_status_dump_SOURCES  = test_status_dump.c \
	status_unittest_src.c \
	status_test_stubs.c
test_status_dump_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_status_dump_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_status_dump_LDADD    = $(RACOON_OBJS)
test_status_dump_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# test_admin_establish_sa_psk covers ADMIN_ESTABLISH_SA_PSK specifically
# (XAUTH id/password injection via the admin socket, despite the
# command's name -- see the test's own header comment): wire-parsing
# correctness (id/key bytes land in rmconf->xauth->login/pass unchanged)
# and the memory-leak fix (admin.c, this same commit) for every path that
# allocates id/key but previously never freed them. -Wl,--wrap=vfree lets
# __wrap_vfree() in the test observe every vfree() call this binary
# makes, the same linker-level interposition technique test_script_hook_
# leak.c already uses for free(). Same admin_process_unittest()/
# admin_test_stubs.c as the other admin_process() tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_admin_establish_sa_psk

test_admin_establish_sa_psk_SOURCES  = test_admin_establish_sa_psk.c \
	admin_unittest_src.c \
	admin_test_stubs.c
test_admin_establish_sa_psk_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_admin_establish_sa_psk_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_admin_establish_sa_psk_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_admin_establish_sa_psk_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections \
	-Wl,--wrap=vfree
endif

# test_admin_handler drives admin_handler() (admin.c) directly against a
# real AF_UNIX listening socket + connected client -- accept()'s failure
# path, the recv(MSG_PEEK) header sanity check, and the full round trip
# through the real admin_process(). admin_handler_unittest() is a new
# ENABLE_UNITTEST accessor (admin_handler() is static). Same
# admin_test_stubs.c as the admin_process() tests above, since a
# successful round trip reaches admin_process() for real.
if !SANITIZER_BUILD
check_PROGRAMS += test_admin_handler

test_admin_handler_SOURCES  = test_admin_handler.c \
	admin_unittest_src.c \
	admin_test_stubs.c
test_admin_handler_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_admin_handler_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_admin_handler_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_admin_handler_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# test_handler_flushph1 drives flushph1() (handler.c) directly against real
# newph1()/insph1()/newph2()/insph2()/bindph12() fixtures -- all already
# exported, so no wrapper-TU/ENABLE_UNITTEST accessor is needed to reach
# them, only the two new tree-size accessors (ph1tree_count_unittest(),
# ph2tree_count_unittest()) to observe that flushph1() actually empties
# both trees. Links handler_ffs.o (handler.c built with
# -ffunction-sections/-fdata-sections; see src/racoon/Makefile.am) so
# -Wl,--gc-sections discards every handler.c function this test doesn't
# call, keeping handler_flushph1_test_stubs.c's stub surface to just what
# flushph1()'s own call graph needs. Same AddressSanitizer/--gc-sections
# incompatibility as test_algorithm et al. (see configure.ac), hence
# !SANITIZER_BUILD.
if !SANITIZER_BUILD
check_PROGRAMS += test_handler_flushph1

test_handler_flushph1_SOURCES  = test_handler_flushph1.c \
	handler_flushph1_test_stubs.c
test_handler_flushph1_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_handler_flushph1_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_handler_flushph1_LDADD    = $(top_builddir)/src/racoon/handler_ffs.o \
	$(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_handler_flushph1_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# test_handler_enum drives enumph1()/enumph2() (handler.c) directly --
# coverage analysis found status.c's/admin.c's/pfkey.c's call sites to both
# functions covered while the real function bodies in handler.c showed
# zero coverage: every existing test that reaches either one goes through
# a hand-written stand-in (status_test_stubs.c, admin_test_stubs.c), never
# the real loop. That real loop carries a use-after-free fix (precompute
# "next" before calling enum_func(), since enum_func() can free the
# current entry) confirmed live via valgrind on a delete-sa/flush-sa run
# (see enumph1()'s own header comment in handler.c) -- never regression
# tested against the real function until now. Links handler_ffs.o (same as
# test_handler_flushph1 above) plus sockmisc_ffs.o for a real cmpsaddr(),
# since this test also wants enumph1()/enumph2()'s selector-filtering path
# exercised for real, not stubbed around. Same
# AddressSanitizer/--gc-sections incompatibility as the other
# wrapped-static-function tests, hence !SANITIZER_BUILD.
if !SANITIZER_BUILD
check_PROGRAMS += test_handler_enum

test_handler_enum_SOURCES  = test_handler_enum.c \
	handler_enum_test_stubs.c
test_handler_enum_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_handler_enum_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_handler_enum_LDADD    = $(top_builddir)/src/racoon/handler_ffs.o \
	$(top_builddir)/src/racoon/sockmisc_ffs.o \
	$(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_handler_enum_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# test_admin_close covers admin_close() -- pre-dates the v0.9.1 churn but
# had no coverage at all until now. Already exported, so no
# ENABLE_UNITTEST accessor needed; shares admin_test_stubs.c's real
# `lcconf` and call-counted unmonitor_fd() with the other admin.c tests.
if !SANITIZER_BUILD
check_PROGRAMS += test_admin_close

test_admin_close_SOURCES  = test_admin_close.c \
	admin_unittest_src.c \
	admin_test_stubs.c
test_admin_close_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_admin_close_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_admin_close_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_admin_close_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# test_admin2pfkey_proto covers admin2pfkey_proto() -- pins the literal
# RFC 2367 PF_KEY wire values as a canary against net/pfkeyv2.h being
# renumbered underneath this mapping (see the test's own header comment
# for why a macro-only assertion would be tautological). Self-contained,
# same as test_admin_check_sockpath.c/test_admin_mkdir_p.c: needs no
# admin_test_stubs.c.
if !SANITIZER_BUILD
check_PROGRAMS += test_admin2pfkey_proto

test_admin2pfkey_proto_SOURCES  = test_admin2pfkey_proto.c \
	admin_unittest_src.c
test_admin2pfkey_proto_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_admin2pfkey_proto_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_admin2pfkey_proto_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_admin2pfkey_proto_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: session_init_before_cfparse() (session.c, v0.9.1) -- session()'s
# pre-cfparse() setup (fd-monitoring reset, scheduler, signal handling,
# pfkey/isakmp/mode-cfg init, address-list init, save_params()) was pulled
# out of session() itself so "racoon -t" can run the exact same sequence.
# Pure code motion, so the regression risk is a future edit dropping or
# reordering one of these calls without either "racoon -t" or the real
# daemon startup visibly breaking right away.
#
# session.c is pulled in via session_unittest_src.c, the same wrapper
# source test_monitor_fd_range.c/test_prune_stale_monitored_fds.c use;
# session_init_test_stubs.c stubs the heavyweight subsystem entry points
# this test has no interest in exercising for real (pfkey_init()/
# isakmp_init() in particular open real PF_KEY/UDP sockets and call
# errx(1, ...) on failure). sched_init() (schedule.c) is linked for real
# -- trivially self-contained (a single TAILQ_INIT()) -- alongside the
# usual plog.o/logger.o/vmbuf.o/misc_noplog.o linkage.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_session_init_before_cfparse

test_session_init_before_cfparse_SOURCES  = test_session_init_before_cfparse.c \
	session_unittest_src.c \
	session_init_test_stubs.c
test_session_init_before_cfparse_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_session_init_before_cfparse_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_session_init_before_cfparse_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o \
	$(top_builddir)/src/racoon/schedule.o
test_session_init_before_cfparse_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections
endif

# Test: session.c's signal-dispatch cluster -- signal_handler(),
# check_sigreq(), reload_conf(), close_session() -- previously entirely
# uncovered (Tier 2 follow-up gap analysis on session.c). All four are
# otherwise reachable only from inside session()'s live main loop after
# a real signal delivery. check_sigreq_unittest() (session.c,
# ENABLE_UNITTEST) lets this test drive the dispatch directly via the
# real signal_handler().
#
# check_sigreq() references reload_conf()/close_session() directly, so
# --gc-sections cannot discard either one's dependency closure regardless
# of which signal a given test drives; session_signal_test_stubs.c
# supplies stand-ins for all of it (same "one dispatch function pulls in
# everything" situation as admin_process(), including why admin_close()
# is stubbed here rather than linked from the real, non
# -ffunction-sections admin.o -- see that stub file's own header
# comment).
#
# close_session() ends in an unconditional exit(0); -Wl,--wrap=exit lets
# the test intercept it via siglongjmp() instead of actually terminating
# the process -- the same interposition technique already used elsewhere
# in this suite for _exit()/fork(), applied to plain exit() instead.
#
# Also excluded from sanitizer builds, same reason as the other
# wrapped-static-function tests above.
if !SANITIZER_BUILD
check_PROGRAMS += test_session_check_sigreq

test_session_check_sigreq_SOURCES  = test_session_check_sigreq.c \
	session_unittest_src.c \
	session_signal_test_stubs.c
test_session_check_sigreq_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_session_check_sigreq_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_session_check_sigreq_LDADD    = $(top_builddir)/src/racoon/plog.o \
	$(top_builddir)/src/racoon/logger.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/misc_noplog.o
test_session_check_sigreq_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections \
	-Wl,--wrap=exit
endif

# Tests: getcertsbyname.c (v0.9.1 DNSSEC hardening pass, Tier 2) --
# daemon-only (racoon_SOURCES) and previously entirely uncovered: no test
# binary ever linked getcertsbyname.o. getcertsbyname_unittest_src.c
# pulls it in the same way as admin_unittest_src.c above.
#
# Unlike admin.c/session.c, getcertsbyname.c uses plain libc malloc()/
# free() throughout (never racoon_malloc()/vmalloc()/plog()), so these
# two binaries need none of the usual plog.o/logger.o/vmbuf.o/
# misc_noplog.o linkage.
#
# test_getcertsbyname_helpers only ever calls getnewci_unittest()
# (static, exposed via a new ENABLE_UNITTEST accessor) and
# freecertinfo() (already exported), never getcertsbyname() itself, so
# -ffunction-sections/--gc-sections drops that function -- and its
# res_query()/res_init()/libresolv dependency -- entirely; no -lresolv
# needed here.
if !SANITIZER_BUILD
check_PROGRAMS += test_getcertsbyname_helpers

test_getcertsbyname_helpers_SOURCES  = test_getcertsbyname_helpers.c \
	getcertsbyname_unittest_src.c
test_getcertsbyname_helpers_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_getcertsbyname_helpers_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_getcertsbyname_helpers_LDFLAGS  = $(AM_LDFLAGS) -Wl,--gc-sections \
	-Wl,--wrap=free
endif

# test_getcertsbyname_dnssec is the priority regression test for this
# file's actual churn: the DNSSEC validation fix removing "|| hp->aa"
# from the response-acceptance check (CWE-290/CWE-347 -- the Authoritative
# Answer bit is not a DNSSEC validation signal and must never be accepted
# as an alternate proof of one; see the test's own header comment for the
# full incident description).
#
# Drives parse_cert_answer_unittest() directly (getcertsbyname.c,
# ENABLE_UNITTEST) rather than getcertsbyname() itself: an earlier
# version of this test called getcertsbyname() and intercepted its
# res_query()/res_init() calls via -Wl,--wrap, but that silently failed
# to redirect them on Ubuntu Bionic 32-bit (older glibc/binutils; see
# parse_cert_answer()'s own header comment in getcertsbyname.c for the
# full explanation), letting the real, network-dependent resolver calls
# run instead. parse_cert_answer() was split out of getcertsbyname()
# specifically so this security-relevant validation/parsing logic could
# be tested without depending on intercepting resolver calls at all.
# Still needs -lresolv for the real dn_expand() it calls; no longer
# needs any -Wl,--wrap flags.
if !SANITIZER_BUILD
check_PROGRAMS += test_getcertsbyname_dnssec

test_getcertsbyname_dnssec_SOURCES  = test_getcertsbyname_dnssec.c \
	getcertsbyname_unittest_src.c
test_getcertsbyname_dnssec_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/libipsec \
	-I$(top_srcdir)/src/include-glibc \
	-I$(top_builddir)/src/include-glibc \
	-DENABLE_UNITTEST
test_getcertsbyname_dnssec_CFLAGS   = $(AM_CFLAGS) -ffunction-sections -fdata-sections
test_getcertsbyname_dnssec_LDFLAGS  = $(AM_LDFLAGS) -lresolv -Wl,--gc-sections
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
#
# A handful of these binaries (test_privsep_client_wrappers,
# test_privsep_hybrid_client_wrappers, and the two real-fork scenarios in
# test_privsep_init) need real root -- CAP_SETUID to seteuid() around a
# still-root forked privsep_priv() child, per CONTRIBUTING.md's "Running
# the Test Suite" section. Run unprivileged (the normal CI case), they
# detect that up front and exit 77, automake's own SKIP convention -- see
# test/README.md §4.4 of doc/dev/v0.9.1-hardening-spec.md §2.4.
# --error-exitcode=1 only overrides valgrind's own exit code when
# *valgrind itself* reports an error; with none found, valgrind exits
# with the child's own code unchanged, so a clean SKIP surfaces here as
# exit 77 -- not 0, and not the 1 "|| exit 1" was written to catch. Left
# unhandled, that turns "correctly skipped, no root" into a hard
# check-valgrind failure on every unprivileged run (i.e. every CI run,
# since running CI itself as root is a bigger blast radius than the thing
# it would save this from mattering for -- privileged valgrind runs stay
# a manual, local `sudo make check-valgrind` step). Handled the same way
# check-TESTS's own automake-generated driver already does: count and
# report skips, but only a genuine valgrind-flagged error (or any other
# nonzero/non-77 exit) fails the target.
check-valgrind: $(check_PROGRAMS)
	@echo "Running tests with valgrind..."
	@skipped=0; \
	for test in $(check_PROGRAMS); do \
		echo "Testing $$test..."; \
		valgrind --suppressions=$(srcdir)/valgrind.supp \
			--num-callers=40 \
			--leak-check=full --show-leak-kinds=all \
			--track-origins=yes --error-exitcode=1 \
			./$$test; \
		rc=$$?; \
		if [ $$rc -eq 77 ]; then \
			skipped=$$((skipped + 1)); \
		elif [ $$rc -ne 0 ]; then \
			exit 1; \
		fi; \
	done; \
	echo "All tests passed valgrind! ($$skipped skipped)"

# Run with verbose output
#
# Same SKIP handling as check-valgrind above, for the same reason: a
# binary that correctly detects it needs real root and exits 77
# (automake's own SKIP convention -- test_privsep_client_wrappers/
# test_privsep_hybrid_client_wrappers under an unprivileged run, see
# CONTRIBUTING.md's "Running the Test Suite" section) must be reported as
# skipped here too, not treated as this target's own failure.
check-verbose: $(check_PROGRAMS)
	@skipped=0; \
	for test in $(TESTS); do \
		echo "========================================"; \
		echo "Running $$test..."; \
		echo "========================================"; \
		./$$test; \
		rc=$$?; \
		if [ $$rc -eq 77 ]; then \
			skipped=$$((skipped + 1)); \
		elif [ $$rc -ne 0 ]; then \
			exit 1; \
		fi; \
	done; \
	echo "All tests passed! ($$skipped skipped)"

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
#
# Modules that are only ever compiled via a local <module>_unittest_src.c
# wrapper (privsep.c, session.c, isakmp.c, proposal.c, kmpstat.c, ... --
# "Testing Static Functions" in test/README.md) never produce a .gcda under
# $(top_builddir)/src: that wrapper's #include pulls the real .c file's
# source lines in (so gcov correctly attributes their coverage back to
# e.g. src/racoon/privsep.c, not to the wrapper), but the .gcda/.gcno pair
# itself is written next to the *compiled object*, i.e. under
# $(top_builddir)/test. Capturing with only --directory "$$SRC_DIR" (as
# this target used to) never looks there, so every such module was
# entirely absent from the report -- not just under-counted. TEST_DIR adds
# that second capture root; '*/test/*' in the --remove filter below then
# drops the *test driver's own* files (test_*.c, *_test_stubs.c,
# privsep_gcov_dump_shim.c) that capturing test/ also picks up, while
# correctly keeping the production sources whose path resolves under
# src/racoon/ regardless of which directory their .gcda lives in.
coverage: $(check_PROGRAMS)
	@which lcov > /dev/null 2>&1 || \
		{ echo "Error: lcov not found. Install lcov to generate coverage reports."; exit 1; }
	@LCOV_DIR=$$(cd $(top_builddir) && pwd); \
	SRC_DIR=$$(cd $(top_builddir)/src && pwd); \
	TEST_DIR=$$(pwd); \
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
	lcov --directory "$$SRC_DIR" --directory "$$TEST_DIR" --zerocounters; \
	for test in $(TESTS); do \
		echo "Running $$test for coverage..."; \
		./$$test; \
		rc=$$?; \
		if [ $$rc -ne 0 ] && [ $$rc -ne 77 ]; then \
			exit 1; \
		fi; \
	done; \
	echo "Excluding eaytest's EAYDEBUG crypto_openssl build from the report..."; \
	rm -f "$$SRC_DIR/racoon/crypto_openssl_test.gcda"; \
	echo "Collecting coverage data..."; \
	lcov --directory "$$SRC_DIR" --directory "$$TEST_DIR" --capture \
		$$LCOV_CAPTURE \
		--output-file "$$LCOV_DIR/coverage_raw.info"; \
	lcov --remove "$$LCOV_DIR/coverage_raw.info" \
		'*/missing/*' '*/libipsec/*' '/usr/*' \
		'*/prsa_par.c' '*/prsa_par.y' \
		'*/prsa_tok.c' '*/prsa_tok.l' \
		'*/test/*' \
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
