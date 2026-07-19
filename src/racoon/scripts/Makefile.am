# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause
#
# The phase1-up/phase1-down split-DNS and routing hook set (doc/admin/
# split-dns.html). Plain POSIX sh, nothing here is compiled -- installed
# via automake's SCRIPTS primary, which chmods them executable (0755) and
# handles DESTDIR/staged installs the same way the *_PROGRAMS targets in
# ../Makefile.am do.
#
# All four files are installed into the *same* directory and must stay
# there: phase1-up.sh, phase1-down.sh and racoon-dns-detect each locate
# racoon-hook-lib.sh by their own installed location (SCRIPT_DIR, derived
# from $0's directory), not a hardcoded path -- see racoon-hook-lib.sh's
# own header comment. racoon-dns-detect is a standalone diagnostic CLI an
# administrator runs directly (doc/admin/split-dns.html §5); it is not
# installed into sbindir precisely so it stays alongside the library it
# sources rather than needing a wrapper or a symlink-resolution trick.
#
# racoon.conf's own `script "..." phase1_up;` / `script "..." phase1_down;`
# directives point at these installed paths -- see etc/racoon/hooks.conf
# and doc/admin/split-dns.html §2 for how to wire that up after install.
#
# This project's own packaging (debian/rules) configures with
# --sysconfdir=/etc/racoon directly -- sysconfdir already *is* racoon's
# own config root there, matching how src/racoon/Makefile.am's other
# sysconfdir-relative paths behave and how debian/racoon.dirs already
# declares "etc/racoon/scripts" (not "etc/racoon/racoon/scripts") as the
# target directory. "$(sysconfdir)/racoon/scripts" would double up under
# that build; "$(sysconfdir)/scripts" is correct for both it and a
# generic `./configure` with sysconfdir left at its default.
hookscriptsdir = $(sysconfdir)/scripts

hookscripts_SCRIPTS = \
	racoon-hook-lib.sh \
	phase1-up.sh \
	phase1-down.sh \
	racoon-dns-detect

# automake does not distribute *_SCRIPTS files automatically the way it
# does *_SOURCES -- these are plain, hand-written files (nothing here is
# generated), so EXTRA_DIST is what makes `make dist`/`make distcheck`
# actually ship them.
EXTRA_DIST = $(hookscripts_SCRIPTS)
