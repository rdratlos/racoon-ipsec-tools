# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

sbin_PROGRAMS = setkey

AM_CFLAGS = -I${top_srcdir}/src/libipsec -I${top_srcdir}/src/racoon/missing @GLIBC_BUGS@
AM_YFLAGS = -d

BUILT_SOURCES = parse.h

setkey_SOURCES = \
  setkey.c \
  parse.y \
  token.l

setkey_LDFLAGS = ../libipsec/libipsec.la
setkey_DEPENDENCIES = ../libipsec/libipsec.la
setkey_LDADD = $(LEXLIB)

noinst_HEADERS = vchar.h extern.h
man8_MANS = setkey.8

# Built from setkey.8.in, .Dd stamped with this build's own
# $(PACKAGE_VERSION) -- see ../racoon/Makefile.am's racoon.8 rule for
# why the sed pattern uses RACOON_PACKAGE_VERSION rather than the real,
# AC_SUBST'd PACKAGE_VERSION name.
setkey.8: $(srcdir)/setkey.8.in Makefile
	$(AM_V_GEN)sed -e 's,@RACOON_PACKAGE_VERSION@,$(PACKAGE_VERSION),g' \
	    $(srcdir)/setkey.8.in > $@

all-local: setkey.8

CLEANFILES = setkey.8

EXTRA_DIST = setkey.8.in sample-policy01.cf sample-policy02.cf sample.cf

MAINTAINERCLEANFILES = \
    parse.c \
    parse.h \
    token.c
