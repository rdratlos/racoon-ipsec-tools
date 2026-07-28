# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause
#
# racoon.service / setkey.service: debian/ and packaging/arch/ used to
# fork these independently. Comparing the two forks, only two things
# actually differed: the binary path (/usr/sbin vs /usr/bin -- already a
# per-build --sbindir choice) and the EnvironmentFile= directory
# (/etc/default vs /etc/conf.d -- a distro convention, see configure.ac's
# --with-environmentdir). Both are template placeholders here instead,
# so there is exactly one unit definition to maintain (and, later, to add
# X.509 private-key handling directives to) rather than two to keep in
# sync by hand.
#
# This whole directory is only reached at all when configure decided
# HAVE_SYSTEMD (a systemdsystemunitdir was found or given explicitly);
# see the top-level Makefile.am's conditional SUBDIRS. Nothing below
# needs its own "if HAVE_SYSTEMD" guard as a result.
#
# The two tokens substituted below are deliberately NOT spelled
# "@sbindir@"/"@environmentdir@" in the .in sources: config.status
# performs a blind, whole-file @varname@ substitution pass over every
# AC_CONFIG_FILES target, including this Makefile itself, for every name
# AC_SUBST'd anywhere in configure.ac -- both sbindir (a standard
# autoconf directory variable) and environmentdir (this project's own)
# qualify, so literal "@sbindir@"/"@environmentdir@" written into this
# recipe would be substituted away by config.status before make ever
# runs the sed command below, leaving nothing for sed's own search
# pattern to match (the same reasoning as docs/examples/Makefile.am's
# RACOON_EXAMPLESDIR/RACOON_SYSCONFDIR). A second, independent reason
# this has to be a make-time sed rule rather than letting config.status
# render racoon.service directly via AC_CONFIG_FILES: sbindir's default
# value is the unexpanded literal string "${exec_prefix}/sbin" until
# something resolves the prefix/exec_prefix chain -- Make does that
# resolution correctly at recipe time via $(sbindir), config.status does
# not (it would write that literal, broken string into a non-Makefile
# file with no second expansion pass to fix it).
racoon.service: $(srcdir)/racoon.service.in Makefile
	$(AM_V_GEN)sed \
	    -e 's,@RACOON_SBINDIR@,$(sbindir),g' \
	    -e 's,@RACOON_ENVIRONMENTDIR@,$(environmentdir),g' \
	    $(srcdir)/racoon.service.in > $@

setkey.service: $(srcdir)/setkey.service.in Makefile
	$(AM_V_GEN)sed \
	    -e 's,@RACOON_SBINDIR@,$(sbindir),g' \
	    -e 's,@RACOON_ENVIRONMENTDIR@,$(environmentdir),g' \
	    $(srcdir)/setkey.service.in > $@

all-local: racoon.service setkey.service

CLEANFILES = racoon.service setkey.service

# systemdsystemunitdir is only AC_SUBST'd when HAVE_SYSTEMD -- harmless
# to reference unconditionally here since this Makefile is never
# recursed into otherwise (see the file header comment above).
systemdsystemunitdir = @systemdsystemunitdir@
systemdsystemunit_DATA = racoon.service setkey.service

environmentdir = @environmentdir@

EXTRA_DIST = racoon.service.in setkey.service.in racoon.envfile setkey.envfile

# racoon.envfile/setkey.envfile ship under distinctive source-tree names
# (so they are not confused with the .service files above in directory
# listings), but the installed filename an EnvironmentFile=-DIR/name
# directive actually opens has to match exactly what the unit above
# says -- "racoon"/"setkey", no extension -- so a plain *_DATA install
# (which always preserves the source basename) does not fit; installed
# by hand instead, the same reasoning as docs/examples/Makefile.am's
# racoon.conf.default install-data-local.
install-data-local:
	${mkinstalldirs} $(DESTDIR)${environmentdir}
	${INSTALL_DATA} $(srcdir)/racoon.envfile $(DESTDIR)${environmentdir}/racoon
	${INSTALL_DATA} $(srcdir)/setkey.envfile $(DESTDIR)${environmentdir}/setkey

uninstall-local:
	rm -f $(DESTDIR)${environmentdir}/racoon $(DESTDIR)${environmentdir}/setkey
