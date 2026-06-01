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

# Reuse the same object files that eaytest uses in src/racoon.
# These are built by src/racoon/Makefile.am as side-effects of the
# main racoon build.  We reference them by path so automake does not
# try to rebuild them here.
RACOON_OBJS = \
	$(top_builddir)/src/racoon/crypto_openssl_test.o \
	$(top_builddir)/src/racoon/vmbuf.o \
	$(top_builddir)/src/racoon/str2val.o \
	$(top_builddir)/src/racoon/misc_noplog.o \
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
	test_eay_rsa

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

# Run these tests with 'make check'
TESTS = $(check_PROGRAMS)

# Extra files to distribute
EXTRA_DIST = README.md

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

# Run with valgrind
check-valgrind: $(check_PROGRAMS)
	@echo "Running tests with valgrind..."
	@for test in $(TESTS); do \
		echo "Testing $$test..."; \
		valgrind --leak-check=full --show-leak-kinds=all \
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
