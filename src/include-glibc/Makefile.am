# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause

.includes: ${top_builddir}/config.status
	ln -snf $(KERNEL_INCLUDE)/linux
	touch .includes

all: .includes

EXTRA_DIST = \
  glibc-bugs.h \
  net/pfkeyv2.h \
  netinet/ipsec.h \
  sys/queue.h

DISTCLEANFILES = .includes linux
