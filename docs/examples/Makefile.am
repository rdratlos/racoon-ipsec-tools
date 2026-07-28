# Makefile.am — Automake input for racoon-ipsec-tools
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# SPDX-License-Identifier: BSD-3-Clause
#
# racoon.conf.default.in becomes the file `make install` places at
# $(sysconfdir)/racoon.conf -- but only if that path is not already
# occupied (install-data-local below); it is role-agnostic and inert
# (no "remote"/"sainfo" block), so racoon starts and idles safely right
# after a fresh install with no prior configuration. It is built here
# (not shipped pre-rendered) so its own comments can point at this
# build's *actual* configured $(sysconfdir) and $(examplesdir) instead of
# a guess -- see the .in source for what gets substituted.
#
# Every other racoon.conf variant (the roadwarrior client/server pair and
# the single-feature NAT-T/PlainRSA/GSSAPI/inherit examples) is reference
# material, not something any install should activate unasked: those are
# installed read-only under $(examplesdir), never $(sysconfdir), and
# never installed over a file that might already exist there.
#
# The two tokens replaced below are deliberately NOT spelled "@examplesdir@"/
# "@sysconfdir@" in racoon.conf.default.in: config.status performs a
# blind, whole-file @varname@ substitution pass over every AC_CONFIG_FILES
# target, including this Makefile itself, for every name AC_SUBST'd
# anywhere in configure.ac -- sysconfdir is one of those, so a literal
# "@sysconfdir@" written into this recipe would be substituted away by
# config.status before make ever runs the sed command below, leaving
# nothing for sed's own search pattern to match. RACOON_EXAMPLESDIR/
# RACOON_SYSCONFDIR are not AC_SUBST'd anywhere, so they pass through
# config.status unchanged and only get substituted here, at make time,
# with this build's actual configured directories.
racoon.conf.default: $(srcdir)/racoon.conf.default.in Makefile
	$(AM_V_GEN)sed \
	    -e 's,@RACOON_EXAMPLESDIR@,$(examplesdir),g' \
	    -e 's,@RACOON_SYSCONFDIR@,$(sysconfdir),g' \
	    $(srcdir)/racoon.conf.default.in > $@

all-local: racoon.conf.default

CLEANFILES = racoon.conf.default

examplesdir = $(docdir)/examples
examples_DATA = \
   racoon.conf.default \
   racoon.conf.sample-natt \
   racoon.conf.sample-plainrsa \
   racoon.conf.sample-gssapi \
   racoon.conf.sample-inherit \
   psk.txt.example

roadwarriordir = $(examplesdir)/roadwarrior
roadwarrior_DATA = roadwarrior/README

roadwarriorclientdir = $(roadwarriordir)/client
roadwarriorclient_DATA = roadwarrior/client/racoon.conf
# Historical, minimal reference hooks (see roadwarrior/README) --
# installed alongside the racoon.conf they were written for, but never
# wired into $(sysconfdir); the real, maintained hook set lives in
# src/racoon/scripts/ and is installed unconditionally to
# $(sysconfdir)/scripts, independent of this example.
roadwarriorclient_SCRIPTS = \
   roadwarrior/client/phase1-up.sh \
   roadwarrior/client/phase1-down.sh

roadwarriorserverdir = $(roadwarriordir)/server
roadwarriorserver_DATA = roadwarrior/server/racoon.conf

EXTRA_DIST = \
   racoon.conf.default.in \
   psk.txt.example \
   racoon.conf.sample-gssapi racoon.conf.sample-natt \
   racoon.conf.sample-inherit racoon.conf.sample-plainrsa \
   roadwarrior/README \
   roadwarrior/client/phase1-down.sh \
   roadwarrior/client/phase1-up.sh \
   roadwarrior/client/racoon.conf \
   roadwarrior/server/racoon.conf

# Installs racoon.conf.default (see above) at $(sysconfdir)/racoon.conf,
# but only if nothing is there yet -- an admin's existing configuration,
# from a previous install or hand-edited from one of the examples, is
# never overwritten by a reinstall/upgrade. The same default is also
# available, unconditionally, under $(examplesdir)/racoon.conf.default
# if you ever want to start over deliberately.
#
# Also creates $(sysconfdir)/certs, empty, at default directory
# permissions (0755 root-owned) -- racoon.conf.default's own "path
# certificate" directive already points here, X.509 is this project's
# primary authentication path, and every certificate/key file an admin
# drops into it gets tightened individually (644 certs/CRLs, 600 keys;
# see README.Debian) regardless of the directory's own mode, so there is
# no reason to diverge from $(sysconfdir) itself's own default mode.
install-data-local: racoon.conf.default
	${mkinstalldirs} $(DESTDIR)${sysconfdir}
	${mkinstalldirs} $(DESTDIR)${sysconfdir}/certs
	@if test -f $(DESTDIR)${sysconfdir}/racoon.conf; then \
	  echo "$(DESTDIR)${sysconfdir}/racoon.conf already exists, leaving it untouched"; \
	else \
	  echo "${INSTALL_DATA} racoon.conf.default $(DESTDIR)${sysconfdir}/racoon.conf"; \
	  ${INSTALL_DATA} racoon.conf.default $(DESTDIR)${sysconfdir}/racoon.conf; \
	fi

# Symmetric with install-data-local above: automake's generated
# uninstall rules only know about files installed through a *_DATA/
# *_SCRIPTS primary, not the conditional install-data-local logic, so
# racoon.conf and certs/ need their own explicit removal here. certs/ is
# only removed if it is still empty -- an admin's actual certificates
# and keys are never touched by `make uninstall`.
uninstall-local:
	rm -f $(DESTDIR)${sysconfdir}/racoon.conf
	-rmdir $(DESTDIR)${sysconfdir}/certs 2>/dev/null
