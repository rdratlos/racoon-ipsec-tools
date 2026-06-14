# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

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
	missing/crypto/rijndael/rijndael.h

man5_MANS = racoon.conf.5
man8_MANS = racoon.8 racoonctl.8 plainrsa-gen.8

EXTRA_DIST = \
   ${man5_MANS} ${man8_MANS} \
   missing/crypto/rijndael/boxes-fst.dat \
   doc/FAQ doc/README.certificate doc/README.gssapi doc/README.plainrsa \
   doc/README.privsep \
   contrib/sp.pl stats.pl \
   samples/psk.txt.sample  samples/racoon.conf.sample \
   samples/psk.txt.in samples/racoon.conf.in \
   samples/racoon.conf.sample-gssapi samples/racoon.conf.sample-natt \
   samples/racoon.conf.sample-inherit samples/racoon.conf.sample-plainrsa \
   samples/roadwarrior/README \
   samples/roadwarrior/client/phase1-down.sh \
   samples/roadwarrior/client/phase1-up.sh \
   samples/roadwarrior/client/racoon.conf \
   samples/roadwarrior/server/racoon.conf \
   samples/roadwarrior/server/racoon.conf-radius

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

# special object rules
crypto_openssl_test.o: crypto_openssl.c
	$(COMPILE) -DEAYDEBUG -o crypto_openssl_test.o -c $(srcdir)/crypto_openssl.c

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
