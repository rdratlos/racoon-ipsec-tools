# Makefile.am — Kate syntax highlighting for racoon.conf
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

EXTRA_DIST = racoon.xml README.md

CFTOKEN_L = $(top_srcdir)/src/racoon/cftoken.l
GEN_KATE_SYNTAX = $(top_srcdir)/scripts/gen-kate-syntax.pl

# racoon.xml is committed to the repository so sysadmins can grab it
# without building racoon-ipsec-tools first. This target regenerates it
# from the grammar whenever cftoken.l changes; it is not part of "all"
# since the file is not needed to build or run racoon.
.PHONY: kate-syntax
kate-syntax: $(srcdir)/racoon.xml

$(srcdir)/racoon.xml: $(CFTOKEN_L) $(GEN_KATE_SYNTAX)
	@if test -z "$(PERL)"; then \
	  echo "perl is required to regenerate racoon.xml" >&2; \
	  exit 1; \
	fi
	$(PERL) $(GEN_KATE_SYNTAX) $(CFTOKEN_L) > $@
