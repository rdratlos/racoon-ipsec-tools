# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

# scripts/ (the phase1-up/phase1-down split-DNS and routing hook set) is a
# real installed component, not example material -- unlike samples/ below,
# which stays EXTRA_DIST-only (dist-shipped, never installed). "." keeps
# this directory's own targets (racoon/racoonctl/plainrsa-gen/eaytest)
# building the way they always have; recursion is additive.
SUBDIRS = . scripts

sbin_PROGRAMS = racoon racoonctl plainrsa-gen
noinst_PROGRAMS = eaytest
include_racoon_HEADERS = racoonctl.h var.h vmbuf.h misc.h gcmalloc.h admin.h \
	schedule.h sockmisc.h isakmp_var.h isakmp.h isakmp_xauth.h \
	isakmp_cfg.h isakmp_unity.h ipsec_doi.h evt.h
lib_LTLIBRARIES = libracoon.la

adminsockdir=${localstatedir}/racoon

BUILT_SOURCES = cfparse.h prsa_par.h
AM_CPPFLAGS = -I${srcdir}/../libipsec
AM_CFLAGS = -D_GNU_SOURCE @GLIBC_BUGS@ -DSYSCONFDIR=\"${sysconfdir}\" \
	-DADMINPORTDIR=\"${adminsockdir}\" \
	@COVERAGE_FLAGS@
if WARN_DEPRECATED
AM_CFLAGS += -DRACOON_WARN_DEPRECATED -Wno-error=deprecated-declarations \
  $(if @DEPRECATION_DIAG_FORMAT@,-fdiagnostics-format=@DEPRECATION_DIAG_FORMAT@,)

endif

AM_LDFLAGS = @EXTRA_CRYPTO@ -lcrypto
AM_YFLAGS = -d ${$*_YFLAGS}
AM_LFLAGS = ${$*_LFLAGS}

prsa_par_YFLAGS = -p prsa
prsa_tok_LFLAGS = -Pprsa -olex.yy.c

MISSING_ALGOS = \
	missing/crypto/sha2/sha2.c \
	missing/crypto/rijndael/rijndael-api-fst.c \
	missing/crypto/rijndael/rijndael-alg-fst.c

racoon_SOURCES = \
	main.c session.c isakmp.c handler.c \
	isakmp_ident.c isakmp_agg.c isakmp_base.c \
	isakmp_quick.c isakmp_inf.c isakmp_newg.c \
	gssapi.c dnssec.c getcertsbyname.c privsep.c \
	pfkey.c admin.c evt.c ipsec_doi.c oakley.c grabmyaddr.c vendorid.c \
	policy.c localconf.c remoteconf.c crypto_openssl.c algorithm.c \
	openssl_compat.c eay_rsa.c proposal.c sainfo.c strnames.c \
	plog.c logger.c schedule.c str2val.c \
	safefile.c backupsa.c genlist.c rsalist.c \
	cftoken.l cfparse.y prsa_tok.l prsa_par.y
EXTRA_racoon_SOURCES = isakmp_xauth.c isakmp_cfg.c isakmp_unity.c throttle.c \
	isakmp_frag.c nattraversal.c security.c $(MISSING_ALGOS)
racoon_LDADD = $(CRYPTOBJS) $(HYBRID_OBJS) $(NATT_OBJS) $(FRAG_OBJS) $(LEXLIB) \
	 $(SECCTX_OBJS) vmbuf.o sockmisc.o misc.o ../libipsec/libipsec.la
racoon_DEPENDENCIES = \
	$(CRYPTOBJS) $(HYBRID_OBJS) $(NATT_OBJS) $(FRAG_OBJS) $(SECCTX_OBJS) \
	vmbuf.o sockmisc.o misc.o

racoonctl_SOURCES = racoonctl.c str2val.c
racoonctl_LDADD = libracoon.la ../libipsec/libipsec.la

libracoon_la_SOURCES = kmpstat.c vmbuf.c sockmisc.c misc.c
libracoon_la_CFLAGS = -DNOUSE_PRIVSEP $(AM_CFLAGS)

plainrsa_gen_SOURCES = plainrsa-gen.c plog.c \
	crypto_openssl.c logger.c openssl_compat.c eay_rsa.c
EXTRA_plainrsa_gen_SOURCES = $(MISSING_ALGOS)
plainrsa_gen_LDADD = $(CRYPTOBJS) vmbuf.o misc.o
plainrsa_gen_DEPENDENCIES = $(CRYPTOBJS) vmbuf.o misc.o

eaytest_SOURCES = eaytest.c plog.c logger.c openssl_compat.c eay_rsa.c
EXTRA_eaytest_SOURCES = missing/crypto/sha2/sha2.c
eaytest_LDADD =	crypto_openssl_test.o vmbuf.o str2val.o misc_noplog.o \
	$(CRYPTOBJS)
eaytest_DEPENDENCIES = crypto_openssl_test.o vmbuf.o str2val.o \
	misc_noplog.o $(CRYPTOBJS)

noinst_HEADERS = \
	admin.h           dnssec.h      isakmp_base.h   oakley.h      session.h \
	admin_var.h       dump.h        isakmp_ident.h  pfkey.h       sockmisc.h \
	algorithm.h       gcmalloc.h    isakmp_inf.h    plog.h        str2val.h \
	backupsa.h        gnuc.h        isakmp_newg.h   policy.h      strnames.h \
	grabmyaddr.h      isakmp_quick.h  proposal.h    var.h         evt.h \
	gssapi.h          isakmp_var.h	vendorid.h      nattraversal.h\
	crypto_openssl.h  handler.h     localconf.h     remoteconf.h  vmbuf.h \
	debug.h           ipsec_doi.h   logger.h        safefile.h \
	debugrm.h         isakmp.h      misc.h          sainfo.h \
	dhgroup.h         isakmp_agg.h  netdb_dnssec.h  schedule.h \
	isakmp_cfg.h      isakmp_xauth.h isakmp_unity.h isakmp_frag.h \
	throttle.h	  privsep.h     openssl_compat.h eay_rsa.h \
	cfparse_proto.h	  cftoken_proto.h genlist.h     rsalist.h \
	missing/crypto/sha2/sha2.h missing/crypto/rijndael/rijndael_local.h \
	missing/crypto/rijndael/rijndael-api-fst.h \
	missing/crypto/rijndael/rijndael-alg-fst.h \
	missing/crypto/rijndael/rijndael.h \
	missing/strlcpy.h missing/strlcat.h

man5_MANS = racoon.conf.5
man8_MANS = racoon.8 racoonctl.8 plainrsa-gen.8

EXTRA_DIST = \
   ${man5_MANS} ${man8_MANS} \
   missing/crypto/rijndael/boxes-fst.dat \
   doc/FAQ doc/README.certificate doc/README.gssapi doc/README.plainrsa \
   doc/README.privsep \
   contrib/sp.pl stats.pl \
   samples/racoon.conf.default.in \
   samples/psk.txt.example \
   samples/racoon.conf.sample-gssapi samples/racoon.conf.sample-natt \
   samples/racoon.conf.sample-inherit samples/racoon.conf.sample-plainrsa \
   samples/roadwarrior/README \
   samples/roadwarrior/client/phase1-down.sh \
   samples/roadwarrior/client/phase1-up.sh \
   samples/roadwarrior/client/racoon.conf \
   samples/roadwarrior/server/racoon.conf

# ---------------------------------------------------------------------------
# Default racoon.conf and documentation examples
# ---------------------------------------------------------------------------
# racoon.conf.default.in becomes the file `make install` places at
# $(sysconfdir)/racoon.conf -- but only if that path is not already
# occupied (install-data-local below); it is role-agnostic and inert
# (no "remote"/"sainfo" block), so racoon starts and idles safely right
# after a fresh install with no prior configuration. It is built here
# (not shipped pre-rendered) so its own comments can point at this
# build's *actual* configured $(sysconfdir) and $(examplesdir) instead of
# a guess -- see the .in source for what gets substituted.
#
# Every other racoon.conf variant (the roadwarrior client/server pair and
# the single-feature NAT-T/PlainRSA/GSSAPI/inherit examples) is reference
# material, not something any install should activate unasked: those are
# installed read-only under $(examplesdir), never $(sysconfdir), and
# never installed over a file that might already exist there.
# The two tokens replaced below are deliberately NOT spelled "@examplesdir@"/
# "@sysconfdir@" in racoon.conf.default.in: config.status performs a
# blind, whole-file @varname@ substitution pass over every AC_CONFIG_FILES
# target, including this Makefile itself, for every name AC_SUBST'd
# anywhere in configure.ac -- sysconfdir is one of those, so a literal
# "@sysconfdir@" written into this recipe would be substituted away by
# config.status before make ever runs the sed command below, leaving
# nothing for sed's own search pattern to match. RACOON_EXAMPLESDIR/
# RACOON_SYSCONFDIR are not AC_SUBST'd anywhere, so they pass through
# config.status unchanged and only get substituted here, at make time,
# with this build's actual configured directories.
racoon.conf.default: $(srcdir)/samples/racoon.conf.default.in Makefile
	$(AM_V_GEN)sed \
	    -e 's,@RACOON_EXAMPLESDIR@,$(examplesdir),g' \
	    -e 's,@RACOON_SYSCONFDIR@,$(sysconfdir),g' \
	    $(srcdir)/samples/racoon.conf.default.in > $@

all-local: racoon.conf.default

CLEANFILES = racoon.conf.default

examplesdir = $(docdir)/examples
examples_DATA = \
   racoon.conf.default \
   samples/racoon.conf.sample-natt \
   samples/racoon.conf.sample-plainrsa \
   samples/racoon.conf.sample-gssapi \
   samples/racoon.conf.sample-inherit \
   samples/psk.txt.example

roadwarriordir = $(examplesdir)/roadwarrior
roadwarrior_DATA = samples/roadwarrior/README

roadwarriorclientdir = $(roadwarriordir)/client
roadwarriorclient_DATA = samples/roadwarrior/client/racoon.conf
# Historical, minimal reference hooks (see samples/roadwarrior/README) --
# installed alongside the racoon.conf they were written for, but never
# wired into $(sysconfdir); the real, maintained hook set lives in
# scripts/ and is installed unconditionally to $(sysconfdir)/scripts
# above, independent of this example.
roadwarriorclient_SCRIPTS = \
   samples/roadwarrior/client/phase1-up.sh \
   samples/roadwarrior/client/phase1-down.sh

roadwarriorserverdir = $(roadwarriordir)/server
roadwarriorserver_DATA = samples/roadwarrior/server/racoon.conf

# hooks.conf.sample documents src/racoon/scripts' own configuration file
# (see scripts/Makefile.am and doc/admin/split-dns.html); installed
# directly under $(sysconfdir), alongside where an admin creates the
# real hooks.conf, unconditionally -- unlike racoon.conf above, its
# filename never collides with an active config, so there is nothing to
# preserve on reinstall.
sysconf_DATA = $(top_srcdir)/etc/racoon/hooks.conf.sample

TESTS = eaytest

.PHONY: check-valgrind

# Run with valgrind. "still reachable" blocks are excluded from the
# error count: glibc's dynamic linker keeps a few dlopen()-related
# allocations (for the OpenSSL provider .so files) reachable for the
# life of the process by design -- they are not leaks.
check-valgrind: $(TESTS)
	@echo "Running eaytest with valgrind..."
	@for test in $(TESTS); do \
		echo "Testing $$test..."; \
		valgrind --leak-check=full --show-leak-kinds=all \
			--errors-for-leak-kinds=definite,indirect,possible \
			--track-origins=yes --error-exitcode=1 \
			./$$test || exit 1; \
	done
	@echo "All tests passed valgrind!"


install-exec-local:
	${mkinstalldirs} $(DESTDIR)${adminsockdir}

# Installs racoon.conf.default (see above) at $(sysconfdir)/racoon.conf,
# but only if nothing is there yet -- an admin's existing configuration,
# from a previous install or hand-edited from one of the examples, is
# never overwritten by a reinstall/upgrade. The same default is also
# available, unconditionally, under $(examplesdir)/racoon.conf.default
# if you ever want to start over deliberately.
install-data-local: racoon.conf.default
	${mkinstalldirs} $(DESTDIR)${sysconfdir}
	@if test -f $(DESTDIR)${sysconfdir}/racoon.conf; then \
	  echo "$(DESTDIR)${sysconfdir}/racoon.conf already exists, leaving it untouched"; \
	else \
	  echo "${INSTALL_DATA} racoon.conf.default $(DESTDIR)${sysconfdir}/racoon.conf"; \
	  ${INSTALL_DATA} racoon.conf.default $(DESTDIR)${sysconfdir}/racoon.conf; \
	fi

# Symmetric with install-data-local above: automake's generated
# uninstall rules only know about files installed through a *_DATA/
# *_SCRIPTS primary, not the conditional install-data-local logic, so
# racoon.conf needs its own explicit removal here.
uninstall-local:
	rm -f $(DESTDIR)${sysconfdir}/racoon.conf

# special object rules
crypto_openssl_test.o: crypto_openssl.c
	$(COMPILE) -DEAYDEBUG -o crypto_openssl_test.o -c $(srcdir)/crypto_openssl.c

# Non-EAYDEBUG build of crypto_openssl.c for the modern unit-test suite in
# test/.  eaytest needs the EAYDEBUG variant (mem2x509() reads PEM), but the
# test/ unit tests exercise the production DER path -- eay_get_x509cert()
# writes DER, which only round-trips through the non-EAYDEBUG mem2x509().
# Sharing one non-EAYDEBUG object across the whole test/ suite also keeps its
# crypto_openssl.c coverage consistent: `make coverage` merges a single line
# structure instead of mixing EAYDEBUG and non-EAYDEBUG gcda for the same
# source file (which lcov reports as inconsistent).  Built via all-local so
# it exists before the test/ programs link against it.
crypto_openssl_unittest.o: crypto_openssl.c
	$(COMPILE) -o crypto_openssl_unittest.o -c $(srcdir)/crypto_openssl.c

all-local: crypto_openssl_unittest.o

misc_noplog.o: misc.c
	$(COMPILE) -DNOUSE_PLOG -o misc_noplog.o -c $(srcdir)/misc.c

# missing/*.c
strdup.o:	$(srcdir)/missing/strdup.c
	$(COMPILE) -c $(srcdir)/missing/$*.c
getaddrinfo.o:	$(srcdir)/missing/getaddrinfo.c
	$(COMPILE) -c $(srcdir)/missing/$*.c
getnameinfo.o:	$(srcdir)/missing/getnameinfo.c
	$(COMPILE) -c $(srcdir)/missing/$*.c
rijndael-api-fst.o: $(srcdir)/missing/crypto/rijndael/rijndael-api-fst.c
	$(COMPILE) -c $(srcdir)/missing/crypto/rijndael/$*.c
rijndael-alg-fst.o: $(srcdir)/missing/crypto/rijndael/rijndael-alg-fst.c
	$(COMPILE) -c $(srcdir)/missing/crypto/rijndael/$*.c
sha2.o: $(srcdir)/missing/crypto/sha2/sha2.c
	$(COMPILE) -c $(srcdir)/missing/crypto/sha2/$*.c

# vmbuf.o, sockmisc.o and misc.o are compiled twice: once via
# libracoon_la_SOURCES (libtool objects, automatically tracked and
# cleaned as libracoon_la-{vmbuf,sockmisc,misc}.Plo), and once as plain
# objects because racoon/plainrsa-gen/eaytest link them directly via
# LDADD instead of through libracoon.la. Automake only recognizes
# dependency files for objects derived from a *_SOURCES variable, so
# the plain objects' .Po files -- created as a side effect of the
# generic .c.o: rule satisfying those LDADD references -- are outside
# its automatic distclean bookkeeping and survive `make distclean`
# unless listed here explicitly.
DISTCLEANFILES = $(DEPDIR)/vmbuf.Po $(DEPDIR)/sockmisc.Po $(DEPDIR)/misc.Po

MAINTAINERCLEANFILES = \
    cftoken.c \
    cfparse.c \
    cfparse.h \
    prsa_tok.c \
    prsa_par.c \
    prsa_par.h

DEPRECATION_REPORT_DIR = deprecation-report
DEPRECATION_SCRIPT     = $(top_srcdir)/tools/gen_deprecation_report.py
DEPRECATION_DIAG_EXT   = @DEPRECATION_DIAG_EXT@

.PHONY: dev
dev:
	@echo "=== Development build: OpenSSL deprecation warnings ENABLED ==="
	$(MAKE) clean
if DEPRECATION_DIAG_STDERR
	@echo "Capturing JSON diagnostics from stderr..."
	@$(MAKE) \
	  NO_RECURSE=1 \
	  CFLAGS="$(CFLAGS) -DRACOON_WARN_DEPRECATED -Wno-error=deprecated-declarations \
	    $(if @DEPRECATION_DIAG_FORMAT@,-fdiagnostics-format=@DEPRECATION_DIAG_FORMAT@,)" \
	  all > $(builddir)/deprecation-stdout.log 2> $(builddir)/deprecation-stderr-raw.log; \
	python3 $(top_srcdir)/tools/merge_gcc_json.py \
	  --input $(builddir)/deprecation-stderr-raw.log \
	  --output $(builddir)/diagnostics.gcc.json
else
	$(MAKE) \
	  CFLAGS="$(CFLAGS) -DRACOON_WARN_DEPRECATED -Wno-error=deprecated-declarations \
	    $(if @DEPRECATION_DIAG_FORMAT@,-fdiagnostics-format=@DEPRECATION_DIAG_FORMAT@,)" \
	  all
endif
	@cat $(builddir)/deprecation-stderr-raw.log 2>/dev/null || true
	$(MAKE) deprecation-report

.PHONY: deprecation-report
deprecation-report:
	$(MKDIR_P) $(DEPRECATION_REPORT_DIR)
	@if [ -z "$(DEPRECATION_DIAG_EXT)" ]; then \
	  echo "NOTICE: GCC < 9 -- no machine-readable diagnostics available."; \
	  echo "        Check stderr output from 'make dev' manually."; \
	else \
	  echo "Collecting deprecation diagnostics (*.$(DEPRECATION_DIAG_EXT))..."; \
	  if [ "$(DEPRECATION_DIAG_FORMAT)" = "json" ]; then \
	    diag_files="$(builddir)/diagnostics.gcc.json"; \
	    [ -f "$$diag_files" ] || diag_files=""; \
	  else \
	    diag_files=$$(find $(builddir) -name '*.$(DEPRECATION_DIAG_EXT)' | sort); \
	  fi; \
	  if [ -n "$$diag_files" ]; then \
	    python3 $(DEPRECATION_SCRIPT) \
	      --format $(DEPRECATION_DIAG_EXT) \
	      --output-dir $(DEPRECATION_REPORT_DIR) \
	      --source-root $(top_srcdir) \
	      $$diag_files; \
	    echo "Deprecation report written to $(DEPRECATION_REPORT_DIR)/index.html"; \
	  else \
	    echo "NOTICE: No diagnostic files found. Run 'make dev' first."; \
	  fi; \
	fi

.PHONY: clean-deprecation-report
clean-deprecation-report:
	rm -rf $(DEPRECATION_REPORT_DIR)
	find $(builddir) \( -name '*.sarif' -o -name '*.gcc.json' \) -delete

clean-local: clean-deprecation-report
