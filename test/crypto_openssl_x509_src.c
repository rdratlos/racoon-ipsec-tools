// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Local wrapper that compiles src/racoon/crypto_openssl.c into the
 * test_x509_cert binary WITHOUT -DEAYDEBUG.
 *
 * The rest of the test suite links src/racoon/crypto_openssl_test.o, which
 * src/racoon/Makefile.am builds with -DEAYDEBUG.  Under EAYDEBUG, mem2x509()
 * expects the in-memory certificate at cert->v[1..] to be PEM text, whereas
 * eay_get_x509cert() always emits DER — so the load/parse round-trip these
 * X.509 tests exercise only holds in the production (non-EAYDEBUG) build,
 * which is what racoon itself ships.  Pulling the source in via this wrapper
 * (rather than a _SOURCES reference to ../src/racoon/crypto_openssl.c) keeps
 * the compiled object and its .Po dependency file under test/.deps/, matching
 * the pattern used by ipsec_doi_unittest_src.c / vendorid_unittest_src.c for
 * Ubuntu Bionic automake compatibility.
 */

#include "crypto_openssl.c"
