# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

ACLOCAL_AMFLAGS = -I m4

# TODO(#68): old-style function definitions being modernized
# incrementally across ~80% of the codebase. Remove once that work lands —
# see legacy-cflags-canary.yml, which fails loudly if this becomes stale.
DISTCHECK_CONFIGURE_FLAGS = CFLAGS="-Wno-old-style-definition"

# systemd/ (racoon.service/setkey.service) is only built/installed when
# configure found (or was told) a systemdsystemunitdir -- see
# configure.ac's --with-systemdsystemunitdir and systemd/Makefile.am.
# This is Automake's standard "Conditional Subdirectories" idiom: SUBDIRS
# itself becomes conditional via a Makefile variable, which -- unlike
# @RPM@ below -- Automake CAN see is directory-shaped at autoreconf time,
# so DIST_SUBDIRS has to be given explicitly (see next paragraph) rather
# than left to default from $(SUBDIRS).
if HAVE_SYSTEMD
MAYBE_SYSTEMD_DIR = systemd
endif

SUBDIRS = src docs/examples $(MAYBE_SYSTEMD_DIR) test misc/kate @RPM@

# DIST_SUBDIRS is explicit (rather than left to Automake's usual default
# of $(SUBDIRS)) specifically so that `make dist` always includes
# systemd/ in the tarball, regardless of whether systemd happened to be
# available on the machine that built it -- $(MAYBE_SYSTEMD_DIR) above
# only controls the *build-time* SUBDIRS recursion. packaging/rpm is the
# opposite case: @RPM@ is an opaque configure.ac substitution (set only
# when the directory exists), so Automake cannot statically validate it
# at autoreconf time either way, letting it keep working unresolved for
# builds from the Debian native source tarball where packaging/ is
# intentionally excluded -- writing a literal "packaging/rpm" here
# instead would break that.
DIST_SUBDIRS = src docs/examples systemd test misc/kate @RPM@

EXTRA_DIST = bootstrap README.md NEWS.md depcomp docs/history/ChangeLog docs/history/ChangeLog.old docs/history/NEWS packaging/arch etc/racoon/hooks.conf.sample doc/admin/split-dns.html

MAINTAINERCLEANFILES = docs/history/ChangeLog

$(srcdir)/docs/history/ChangeLog:
	@if test -d "$(srcdir)/CVS"; then \
	  $(srcdir)/misc/cvs2cl.pl --follow-only ipsec-tools-0_8-branch -I docs/history/ChangeLog --utc -U $(srcdir)/misc/cvsusermap --group-by-author --fsf -T -l "-d2006-09-10<now" --tag-regexp "^ipsec-tools" --stdout > $@ ; \
	  echo "For older changes see docs/history/ChangeLog.old" >> $@ ; \
	else \
	  echo "A CVS checkout and perl is required to generate ChangeLog" ; \
	  exit 1 ; \
	fi

if WARN_DEPRECATED
# When --enable-warn-deprecated is set, redirect 'make' to the 'dev'
# target, which handles diagnostic capture correctly for all GCC versions
# (file-based and stderr JSON).  This avoids injecting
# -fdiagnostics-format=json into AM_CFLAGS globally, which would corrupt
# libtool's output parsing on GCC 9-11.
# We use .DEFAULT_GOAL to change make's default target from 'all' to 'dev'.
# The 'all' target still exists and works normally for explicit 'make all'.
.DEFAULT_GOAL = dev

all-local: dev
endif

.PHONY: dev
dev:
	$(MAKE) $(AM_MAKEFLAGS) -C src dev

.PHONY: kate-syntax
kate-syntax:
	$(MAKE) $(AM_MAKEFLAGS) -C misc/kate kate-syntax
