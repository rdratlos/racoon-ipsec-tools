SUBDIRS = @INCLUDE_GLIBC@ libipsec setkey racoon

DIST_SUBDIRS = include-glibc libipsec setkey racoon

# For OpenSSL unit tests in folder test/
noinst_LTLIBRARIES = libtestcrypto.la
libtestcrypto_la_SOURCES = \
    libipsec/ipsec_get_policylen.c \
    libipsec/ipsec_strerror.c \
    libipsec/policy_parse.y \
    racoon/crypto_openssl.c \
    racoon/admin.c \
    racoon/logger.c \
    racoon/misc.c \
    racoon/plog.c \
    racoon/str2val.c \
    racoon/vmbuf.c

libtestcrypto_la_CPPFLAGS = \
    -I$(top_srcdir)/src/libipsec \
    -I$(top_srcdir)/src/racoon

libtestcrypto_la_CFLAGS = -D_GNU_SOURCE @GLIBC_BUGS@ -DSYSCONFDIR=\"${sysconfdir}\" \
        -DADMINPORTDIR=\"${adminsockdir}\"

libtestcrypto_la_YFLAGS = -d ${$*_YFLAGS}
