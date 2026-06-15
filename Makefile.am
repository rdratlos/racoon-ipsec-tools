# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

SUBDIRS = src test @RPM@

DIST_SUBDIRS = src test rpm

EXTRA_DIST = bootstrap README NEWS depcomp ChangeLog ChangeLog.old

MAINTAINERCLEANFILES = ChangeLog

$(srcdir)/ChangeLog:
	@if test -d "$(srcdir)/CVS"; then \
	  $(srcdir)/misc/cvs2cl.pl --follow-only ipsec-tools-0_8-branch -I ChangeLog --utc -U $(srcdir)/misc/cvsusermap --group-by-author --fsf -T -l "-d2006-09-10<now" --tag-regexp "^ipsec-tools" --stdout > $@ ; \
	  echo "For older changes see ChangeLog.old" >> $@ ; \
	else \
	  echo "A CVS checkout and perl is required to generate ChangeLog" ; \
	  exit 1 ; \
	fi

.PHONY: $(srcdir)/ChangeLog

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
