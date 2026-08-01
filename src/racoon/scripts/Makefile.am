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
# racoon-hook-lib.sh is deliberately not in hookscripts_SCRIPTS below,
# even though it lives in the same directory and ships alongside the
# three that are: it has no #! interpreter line and is never executed
# directly (its own header comment: "Nothing in this file executes on
# its own; it only defines functions and default variables, so
# `. racoon-hook-lib.sh` is always safe") -- sourcing a file needs it to
# be readable, not executable. SCRIPTS' automatic 0755 on a file with no
# shebang is exactly what lintian's executable-not-elf-or-script check
# flags: a file marked executable that is neither an ELF binary nor a
# recognizable script. DATA installs it at the same path with the
# ordinary non-executable mode (0644) INSTALL_DATA uses, which is both
# correct for a sourced-only file and what silences the warning.
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
	phase1-up.sh \
	phase1-down.sh \
	racoon-dns-detect

hookscripts_DATA = \
	racoon-hook-lib.sh

# racoon-dns-detect's own man page, co-located with the script it
# documents (PR #91 review, comment #38) -- man8_MANS installs to the
# standard $(mandir)/man8 via automake's own MANS primary, not
# hookscriptsdir above; a man page belongs in the system man tree
# regardless of where the script itself is installed.
man8_MANS = racoon-dns-detect.8

# Built from racoon-dns-detect.8.in, .Dd stamped with this build's own
# $(PACKAGE_VERSION) -- see ../Makefile.am's racoon.8 rule for why the
# sed pattern uses RACOON_PACKAGE_VERSION rather than the real,
# AC_SUBST'd PACKAGE_VERSION name.
racoon-dns-detect.8: $(srcdir)/racoon-dns-detect.8.in Makefile
	$(AM_V_GEN)sed -e 's,@RACOON_PACKAGE_VERSION@,$(PACKAGE_VERSION),g' \
	    $(srcdir)/racoon-dns-detect.8.in > $@

all-local: racoon-dns-detect.8

CLEANFILES = racoon-dns-detect.8

# automake does not distribute *_SCRIPTS/*_DATA/*_MANS files
# automatically the way it does *_SOURCES -- these are plain,
# hand-written files (racoon-dns-detect.8 itself excepted -- generated
# from racoon-dns-detect.8.in above), so EXTRA_DIST is what makes
# `make dist`/`make distcheck` actually ship them. Verified directly
# (not assumed): a plain `make distdir` in this directory omits
# racoon-dns-detect.8.in without this line.
EXTRA_DIST = $(hookscripts_SCRIPTS) $(hookscripts_DATA) racoon-dns-detect.8.in
