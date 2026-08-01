# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

#bin_PROGRAMS = test-policy test-policy-priority
lib_LTLIBRARIES = libipsec.la

libipsecdir = $(includedir)/libipsec
libipsec_HEADERS = libpfkey.h

man3_MANS = ipsec_set_policy.3 ipsec_strerror.3

# Built from their .in sources, .Dd stamped with this build's own
# $(PACKAGE_VERSION) -- see src/racoon/Makefile.am's racoon.8 rule for
# why the sed pattern uses RACOON_PACKAGE_VERSION rather than the real,
# AC_SUBST'd PACKAGE_VERSION name.
ipsec_set_policy.3: $(srcdir)/ipsec_set_policy.3.in Makefile
	$(AM_V_GEN)sed -e 's,@RACOON_PACKAGE_VERSION@,$(PACKAGE_VERSION),g' \
	    $(srcdir)/ipsec_set_policy.3.in > $@

ipsec_strerror.3: $(srcdir)/ipsec_strerror.3.in Makefile
	$(AM_V_GEN)sed -e 's,@RACOON_PACKAGE_VERSION@,$(PACKAGE_VERSION),g' \
	    $(srcdir)/ipsec_strerror.3.in > $@

all-local: ipsec_set_policy.3 ipsec_strerror.3

CLEANFILES = ipsec_set_policy.3 ipsec_strerror.3

AM_CFLAGS = @GLIBC_BUGS@
AM_YFLAGS = -d -p __libipsec
AM_LFLAGS = -P__libipsec -olex.yy.c

BUILT_SOURCES = policy_parse.h

libipsec_la_SOURCES = \
  ipsec_dump_policy.c \
  ipsec_get_policylen.c \
  ipsec_strerror.c \
  key_debug.c \
  pfkey.c \
  pfkey_dump.c \
  policy_parse.y \
  policy_token.l

# version is current:revision:age.
# See: http://www.gnu.org/manual/libtool-1.4.2/html_chapter/libtool_6.html#SEC32
libipsec_la_LDFLAGS = -version-info 0:1:0

noinst_HEADERS = ipsec_strerror.h

#test_policy_SOURCES = test-policy.c
#test_policy_LDFLAGS = libipsec.la

#test_policy_priority_SOURCES = test-policy-priority.c
#test_policy_priority_LDFLAGS = libipsec.la

EXTRA_DIST = ipsec_set_policy.3.in ipsec_strerror.3.in

MAINTAINERCLEANFILES = \
    policy_token.c \
    policy_parse.c \
    policy_parse.h
