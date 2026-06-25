# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

SUBDIRS = @INCLUDE_GLIBC@ libipsec setkey racoon

DIST_SUBDIRS = include-glibc libipsec setkey racoon

# For OpenSSL unit tests in folder test/
noinst_LTLIBRARIES = libtestcrypto.la
libtestcrypto_la_SOURCES = \
    libipsec/ipsec_get_policylen.c \
    libipsec/ipsec_strerror.c \
    libipsec/policy_parse.y \
    racoon/crypto_openssl.c \
    racoon/admin.c \
    racoon/logger.c \
    racoon/misc.c \
    racoon/plog.c \
    racoon/str2val.c \
    racoon/vmbuf.c

libtestcrypto_la_CPPFLAGS = \
    -I$(top_srcdir)/src/libipsec \
    -I$(top_srcdir)/src/racoon

libtestcrypto_la_CFLAGS = -D_GNU_SOURCE @GLIBC_BUGS@ -DSYSCONFDIR=\"${sysconfdir}\" \
        -DADMINPORTDIR=\"${adminsockdir}\"

libtestcrypto_la_YFLAGS = -d ${$*_YFLAGS}

.PHONY: dev
dev:
	@for dir in @INCLUDE_GLIBC@ libipsec setkey; do \
	  $(MAKE) $(AM_MAKEFLAGS) -C $$dir all || exit 1; \
	done
	$(MAKE) $(AM_MAKEFLAGS) -C racoon dev
