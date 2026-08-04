# Makefile.am — Kate syntax highlighting for racoon.conf
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

EXTRA_DIST = racoon.xml README.md

CFTOKEN_L = $(top_srcdir)/src/racoon/cftoken.l
GEN_KATE_SYNTAX = $(top_srcdir)/scripts/gen-kate-syntax.pl

# racoon.xml is committed to the repository so sysadmins can grab it
# without building racoon-ipsec-tools first. This target regenerates it
# from the grammar whenever cftoken.l changes; it is a maintainer-only
# convenience invoked explicitly via `make kate-syntax`.
#
# Deliberately NOT a real rule for $(srcdir)/racoon.xml itself: EXTRA_DIST
# files are prerequisites of distdir-am, so a target under that exact name
# would make `make dist`/`distcheck` try to satisfy it too -- failing on
# scripts/gen-kate-syntax.pl, which isn't (and doesn't need to be)
# distributed, or, in distcheck's read-only unpacked source tree, failing
# trying to write into it.
.PHONY: kate-syntax
kate-syntax: $(CFTOKEN_L) $(GEN_KATE_SYNTAX)
	@if test -z "$(PERL)"; then \
	  echo "perl is required to regenerate racoon.xml" >&2; \
	  exit 1; \
	fi
	$(PERL) $(GEN_KATE_SYNTAX) $(CFTOKEN_L) > $(srcdir)/racoon.xml
