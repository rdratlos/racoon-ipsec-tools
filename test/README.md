# Racoon IPSec - Test Suite

Modern test suite for Racoon IPSec OpenSSL 3.0 migration validation.

## Test Structure

```
test/
├── test_dh_modp_groups.c       - DH: All 8 MODP groups (7 tests)
├── test_dh_buffer_overflow.c   - DH: undersized shared-secret buffer (ISSUE #5)
├── test_rsa_comprehensive.c    - RSA: Textbook RSA validation (12 tests)
├── test_eay_rsa.c              - eayRSA opaque RSA object unit tests
├── test_crypto_coverage.c      - Coverage: All eay_* functions (~40 tests)
├── test_cipher_shim.c          - Legacy cipher shim (Blowfish, CAST5, IDEA, RC5)
├── test_logger.c               - Ring-buffer logger (src/racoon/logger.c)
├── test_str2val.c              - str2val()/val2str() hex<->binary conversion
├── test_vmbuf.c                - vmalloc()/vrealloc()/vfree()/vdup()
├── test_sockmisc.c             - Pure socket-address utility functions
├── test_genlist.c              - Generic linked-list operations
├── test_x509_cert.c            - X.509 cert load/verify/sign/SAN (ISSUE #52),
│                                  using cert-framework fixtures
├── gen-x509-fixtures.sh        - Generates real PEM certs/keys/CRLs for
│                                  test_x509_cert via cert-framework/lib/ca.sh
├── rsalist_test_stubs.c        - Stub symbols (lcconf, monitor_fd, privsep_*, ...)
│                                  needed by tests that link rsalist.o/sockmisc.o
├── valgrind.supp               - Valgrind suppressions (OpenSSL provider noise)
├── Makefile.am                 - Automake control
└── README.md                   - This file
```

## Quick Start

```bash
# Run all tests (from the top level, or with -C test)
make check -C test

# Run a specific test binary directly
./test/test_dh_modp_groups

# Run with valgrind  -- must be invoked from test/, see "Important" below
cd test && make check-valgrind

# Run with verbose output
make check-verbose -C test
```

> **Important — `check-valgrind` and `coverage`/`check-coverage` are only
> available in this directory (`test/`) and in `src/racoon/` (for the
> legacy `eaytest` binary). The top-level and `src/` Makefiles do **not**
> define these targets — `make check-valgrind` or `make coverage` run from
> the repository root or from `src/` will fail with "No rule to make
> target". Always `cd test` (or pass `-C test`) first.

## Test Files

### test_dh_modp_groups.c (7 tests)

**Purpose:** Complete DH validation for IPSec
**Coverage:** All 8 MODP groups (RFC 2409, RFC 3526)

**Tests:**
1. ✅ DH key generation for all 8 MODP groups
2. ✅ DH shared secret computation for all groups
3. ✅ DH with generator g=5 for all groups
4. ✅ Generators g=2 vs g=5 produce different keys
5. ✅ Cross-group incompatibility detection
6. ✅ Memory leak detection (100 iterations)
7. ✅ Performance comparison across groups

**MODP Groups:**
- MODP 768 (96 bytes, legacy)
- MODP 1024 (128 bytes)
- MODP 1536 (192 bytes)
- MODP 2048 (256 bytes, recommended)
- MODP 3072 (384 bytes)
- MODP 4096 (512 bytes)
- MODP 6144 (768 bytes)
- MODP 8192 (1024 bytes)

**Run:** `./test_dh_modp_groups`

### test_dh_buffer_overflow.c

**Purpose:** Regression test for ISSUE #5 — `eay_dh_compute()` writes the
DH shared secret right-aligned into a buffer of length `prime->l`. If the
caller allocates a smaller buffer, the `memcpy()` becomes an out-of-bounds
write. This test passes a deliberately undersized buffer and verifies the
function rejects it instead of corrupting memory.

**Run:** `./test_dh_buffer_overflow`

### test_rsa_comprehensive.c (12 tests)

**Purpose:** Thorough RSA validation for "textbook RSA"
**Coverage:** EVP_PKEY_verify_recover, OpenSSL 3.0 API

**Priority 1: Critical Tests (6)**
1. 🔴 Textbook RSA with EVP_PKEY_verify_recover
2. 🔴 PKCS1 padding verification
3. 🔴 RSA ↔ EVP_PKEY conversion (OpenSSL 3.0)
4. 🔴 Signature tampering detection (security)
5. 🔴 Data tampering detection (security)
6. 🔴 Wrong key rejection (security)

**Priority 2: Key Conversions (3)**
7. 🟡 RSA key component extraction
8. 🟡 BIGNUM to RSA conversion
9. 🟡 Various key sizes (1024-4096 bits)

**Priority 3: Edge Cases (3)**
10. 🟢 Empty data handling
11. 🟢 Maximum data size (4KB)
12. 🟢 Stress test (100 iterations)

**CRITICAL:** All Priority 1 tests MUST pass before production!

**Run:** `./test_rsa_comprehensive`

### test_eay_rsa.c

**Purpose:** Unit tests for `eay_rsa.c`/`eay_rsa.h`, the eayRSA opaque RSA
object used throughout racoon's RSA signing/verification code paths.

**Run:** `./test_eay_rsa`

### test_crypto_coverage.c (~40 tests)

**Purpose:** Complete coverage of all eay_* functions
**Coverage:** Ciphers, hashing, HMAC, X.509, utilities

**Test Categories:**
- ✅ Symmetric ciphers (DES, 3DES, AES, Blowfish, CAST, IDEA, RC5, Camellia)
- ✅ Hash functions (MD5, SHA1, SHA2-256, SHA2-384, SHA2-512)
- ✅ HMAC functions (HMAC-MD5, HMAC-SHA1, HMAC-SHA2-*)
- ✅ ASN.1 DN conversion (the X.509 helpers that need no real certificate;
     certificate load/verify/sign are covered by `test_x509_cert.c`)
- ✅ Base64 encoding/decoding
- ✅ Random number generation
- ✅ BIGNUM conversions
- ✅ Utility functions

**Run:** `./test_crypto_coverage`

### test_x509_cert.c (ISSUE #52, 10 tests)

**Purpose:** Exercise the `crypto_openssl.c` functions that load, parse,
verify and sign *real* X.509 certificates — everything `test_crypto_coverage.c`
does **not** touch (it only covers the raw-string ASN.1 DN helpers).

**Covered functions:** `eay_get_x509cert`, `eay_check_x509cert`,
`eay_check_x509sign`, `eay_get_x509asn1subjectname`,
`eay_get_x509asn1issuername`, `eay_get_x509subjectaltname`,
`eay_get_x509text`, `eay_get_pkcs1privkey`, `eay_get_pkcs1pubkey`,
`eay_get_x509sign`.

**Test coverage highlights:**
- Load + leading `ISAKMP_CERT_X509SIGN` tag byte, missing-file → NULL
- Chain + CRL verification (valid), and rejection of a wrong-CA and a
  **revoked** cert (the CRL path — needs a root CRL too, see below)
- Subject/issuer names compared structurally via `eay_cmp_asn1dn`
- Subject Alternative Names: DNS, email, IPv4, IPv6, out-of-range `pos`,
  and a no-SAN cert
- RSA sign/verify round-trip with tamper detection, and rejection of a
  non-RSA (EC) key

**Fixtures:** generated at run time by `gen-x509-fixtures.sh`, which drives
`cert-framework/lib/ca.sh` (ISSUE #50) to build a real Root → Intermediate →
End-Entity CA into a throwaway scratch dir. The test binary shells out to it
via `system()` once at start-up and locates the script through
`X509_FIXTURE_SRCDIR` (exported by `AM_TESTS_ENVIRONMENT`; defaults to `.`
for a hand-run binary). Two additive `ca.sh` helpers were introduced —
`ca_generate_root_crl` / `ca_generate_intermediate_crl` — because
`eay_check_x509cert` always sets `X509_V_FLAG_CRL_CHECK_ALL`, so a CRL must
exist for every issuer in the chain, root included.

**EAYDEBUG note:** the whole modern suite links `crypto_openssl_unittest.o`
— the **non-EAYDEBUG** build of `crypto_openssl.c` (see
`src/racoon/Makefile.am`) — rather than `eaytest`'s `crypto_openssl_test.o`
(built with `-DEAYDEBUG`, under which `mem2x509()` reads PEM while
`eay_get_x509cert()` writes DER, so `test_x509_cert`'s load/parse round-trip
would break). No test in `test/` depends on the EAYDEBUG PEM behaviour, and
sharing one non-EAYDEBUG object keeps `crypto_openssl.c` coverage consistent
under `make coverage` (a single line structure `lcov` can merge, instead of
mixing EAYDEBUG and non-EAYDEBUG `.gcda` for the same source file). The
`coverage` target additionally drops `eaytest`'s `crypto_openssl_test.gcda`
so the report reflects only the production build.

**Out of scope (follow-up):** encrypted PKCS#1 private keys (the eay loaders
pass no passphrase callback), the SAN NUL-termination rejection branch (not
reachable with a well-formed cert), CRL parsing itself and OCSP.

**Run:** `./test_x509_cert`

### test_cipher_shim.c

**Purpose:** Validates the `evp_crypt` shim and legacy cipher support
(Blowfish, CAST5, IDEA, RC5) under OpenSSL 3.0+'s legacy provider.

**Run:** `./test_cipher_shim`

### test_logger.c

**Purpose:** Unit tests for the ring-buffer logger (`src/racoon/logger.c`).
Exists primarily to provide lcov coverage so `logger.c` is not excluded
from coverage reports; has no OpenSSL dependency.

**Run:** `./test_logger`

### test_str2val.c

**Purpose:** Unit tests for `str2val()`/`val2str()` hex-string/binary
conversion.

**Run:** `./test_str2val`

### test_vmbuf.c

**Purpose:** Unit tests for `vmalloc()`/`vrealloc()`/`vfree()`/`vdup()`.

**Run:** `./test_vmbuf`

### test_sockmisc.c

**Purpose:** Unit tests for the pure-function subset of sockmisc
(`cmpsaddr()`, `extract_port()`, `set_port()`, `get_port_ptr()`,
`newsaddr()`, `dupsaddr()`, `saddr2str()`, `saddrwop2str()`). Functions
requiring network I/O are not exercised here.

**Run:** `./test_sockmisc`

### test_genlist.c

**Purpose:** Unit tests for genlist (`genlist_init()`, `genlist_insert()`,
`genlist_append()`, `genlist_foreach()`, `genlist_next()`,
`genlist_free()`).

**Run:** `./test_genlist`

## Running Tests

### All Tests

```bash
# Run all modern tests
make check -C test

# Run legacy (eaytest) + modern tests
make check
```

### Specific Categories

```bash
# Only DH tests
make check-dh -C test

# Only RSA tests
make check-rsa -C test

# Only coverage tests
make check-coverage -C test

# Only cipher shim tests
make check-shim -C test

# Only logger tests
make check-logger -C test

# Quick test (DH + RSA)
make check-quick -C test
```

### With Memory Leak Detection

`check-valgrind` is defined in `test/Makefile.am` (and separately, for the
legacy binary, in `src/racoon/Makefile.am`). It is **not** available from
the top level or from `src/` — run it from the directory that owns the
binaries you want to check:

```bash
# Modern test suite
cd test && make check-valgrind

# Legacy eaytest binary
cd src/racoon && make check-valgrind

# Expected output: 0 bytes leaked
```

`test/valgrind.supp` suppresses known-benign OpenSSL provider allocations;
`src/racoon`'s `check-valgrind` instead excludes "still reachable" blocks
from the error count for the same reason (dlopen'd provider .so files).

### With Verbose Output

```bash
# Verbose mode
make check-verbose -C test
```

### Code Coverage (lcov)

Like `check-valgrind`, the `coverage` target only exists in
`test/Makefile.am` and requires the build to have been configured with
`--enable-coverage` (so object files carry `-fprofile-arcs
-ftest-coverage`). Run it from `test/`, not from the top level or `src/`:

```bash
./configure --enable-coverage
make
cd test && make coverage
# HTML report: test/../coverage/index.html (relative to the build root)
```

### OpenSSL Deprecation-Warning Report

Separately from test execution, `--enable-warn-deprecated` (configured at
the top level) plus `make dev` rebuilds racoon with
`-Wdeprecated-declarations` surfaced instead of suppressed, and generates
an HTML/text report of every OpenSSL 3.x deprecation warning found. This
is implemented in `src/racoon/Makefile.am` (the `dev` and
`deprecation-report` targets) using `tools/gen_deprecation_report.py` and
`tools/merge_gcc_json.py`; it is unrelated to the `test/` suite or to
`check-valgrind`/`coverage`.

```bash
./configure --enable-warn-deprecated
make dev
# Report: src/racoon/deprecation-report/index.html
```

## Expected Output

### Success

```
========================================================================
  Racoon IPSec - Complete DH MODP Group Tests
  OpenSSL 3.0 - All 8 MODP Groups + Both Generators
========================================================================

=== DH MODP Group Tests ===

[TEST] DH Key Generation - All 8 MODP Groups ... 
    MODP 768 (96 bytes)... ✓ OK (pub=96, priv=96 bytes)
    MODP 1024 (128 bytes)... ✓ OK (pub=128, priv=128 bytes)
    ...
    All 8 MODP groups generated keys successfully ✓ PASS

...

========================================================================
  ✓ ALL DH TESTS PASSED (7 tests)
  All 8 MODP groups validated with g=2 and g=5!
========================================================================
```

### Failure

```
[TEST] DH Key Generation ... 
    MODP 2048 (256 bytes)... FAIL (keygen)
    ✗ FAIL: Some MODP groups failed key generation

========================================================================
  ✗ 1 DH TEST(S) FAILED
========================================================================
```

### SKIP

`SKIP` is a third, distinct outcome from `PASS`/`FAIL` — automake's own
convention, signaled by a test binary calling `exit(77)` (or returning 77
from `main()`). `make check`, `make check-verbose`, and `make
check-valgrind` all honor it the same way: tallied separately, and never
treated as a failure.

```
[TEST] freecertinfo() frees ci_cert and the node for every entry in the chain ...
SKIP: -Wl,--wrap=free did not intercept free() calls made via a canary
      getnewci_unittest()/freecertinfo() round trip on this toolchain.
      See doc/dev/wrap-based-tests-vs-lto.md.
...
All tests passed! (2 skipped)
```

Two independent reasons a binary in this suite reports `SKIP`, both
covered in more depth in `CONTRIBUTING.md`:

- **Needs real root** (`test_privsep_client_wrappers`,
  `test_privsep_hybrid_client_wrappers`, part of `test_privsep_init`) —
  expected on every unprivileged run, i.e. every normal CI run. See
  "Why some tests need root".
- **Whole-program LTO defeats a `-Wl,--wrap=` test double**
  (`test_admin_establish_sa_psk`, `test_getcertsbyname_helpers`) —
  expected whenever the toolchain enables `-flto=auto
  -ffat-lto-objects` (Ubuntu's `dpkg-buildflags` hardening default as
  of "Resolute"). See "Two tests skip under whole-program LTO" and
  `doc/dev/wrap-based-tests-vs-lto.md`.

`develop`'s CI (`develop-build-test.yml`) asserts these two LTO-canary
SKIPs are actually observed on every run, rather than trusting that the
`-flto` configure flags imply it — see `test/check-expected-skips.sh` and
`test/expected-skips.yml`. A `SKIP` that unexpectedly becomes a `PASS`
means the canary itself stopped being exercised (the assumption behind
the SKIP is now stale); a `SKIP` that becomes a real `FAIL` means an
actual regression. Both fail that check with a message pointing back
here and to `CONTRIBUTING.md`.

### Choosing a wrapper pattern for a new test

Deciding how to intercept a call for a new test, roughly in order of
preference:

1. **Can you assert through the real function's own observable effect**
   (a return value, a struct field, an errno) **instead of counting calls
   to an internal one?** Prefer this — it has no wrapper to defeat in the
   first place. Most of this suite's tests (DH, RSA, cipher, X.509) work
   this way.
2. **Does the call cross a `fork()`/`execve()` boundary**, or go through
   several stub indirections before reaching the wrapped symbol (like
   `test_script_hook_leak.c`'s `ipsecdoi_id2str()` path)? `-Wl,--wrap=`
   is safe here — the indirection defeats the same whole-program-LTO
   interprocedural analysis that makes simple cases risky (see
   `doc/dev/wrap-based-tests-vs-lto.md`'s "Why test_script_hook_leak.c is
   unaffected").
3. **Is it a simple, local allocate/free (or similarly trivial) pair**,
   wrapped via `-Wl,--wrap=` **with no cross-TU opacity in between?**
   This is the risky case — GCC's own semantic knowledge of
   `malloc()`/`free()`, or a same-TU inlining of the real definition
   (`vfree()`'s case), can make the wrap symbol dead code under LTO
   *even without any indication in the test output other than a
   suspiciously-zero call count*. If you must use this pattern:
   - Add a startup canary that exercises the exact same wrapped symbol
     through the same call path the real assertion uses (not a bare
     `malloc()`/`free()`, which can be optimized away even without LTO —
     see `test_getcertsbyname_helpers.c`'s reasoning for routing its
     canary through `getnewci_unittest()`/`freecertinfo()` specifically).
   - `return 77` (`SKIP`) if the canary isn't observed, rather than
     asserting on a count that reads identically whether it's correct
     or the wrap is simply gone.
   - Add the binary to `test/expected-skips.yml`'s `unprivileged` list
     so CI asserts the SKIP keeps happening, not just that the tests
     keep passing.
4. **Configure-time exclusion** (this project's `SANITIZER_BUILD`
   precedent) is the fallback when even a canary can't distinguish
   "correctly skipped" from "silently defeated" — but it drops every
   assertion in the binary, not just the ones that depend on the wrap,
   so prefer option 3 when only part of a binary is at risk.

## Test Coverage

| Component | eaytest (legacy) | Modern Tests | Coverage |
|-----------|------------------|--------------|----------|
| **DH Operations** | Basic (8 groups) | Complete (g=2,g=5) + overflow regression | ✅✅✅ |
| **RSA Operations** | Basic | Textbook RSA + eayRSA object | ✅✅✅ |
| **Symmetric Ciphers** | Basic | Complete + legacy shim | ✅✅✅ |
| **Hash Functions** | Basic | Complete | ✅✅✅ |
| **HMAC Functions** | Basic | Complete | ✅✅✅ |
| **X.509 Certs** | Basic | Complete | ✅✅✅ |
| **Utilities** | Basic | str2val, vmbuf, sockmisc, genlist, logger | ✅✅✅ |

## Debugging Failed Tests

### DH Tests Fail

```bash
# Check OpenSSL version
openssl version  # Need 3.0+

# Run with debug
gdb ./test_dh_modp_groups
(gdb) run
(gdb) bt  # backtrace on failure

# Check memory
valgrind --leak-check=full ./test_dh_modp_groups
```

### RSA Tests Fail

```bash
# Check textbook RSA implementation
grep -A 20 "EVP_PKEY_verify_recover" src/racoon/crypto_openssl.c

# Check for OpenSSL errors
./test_rsa_comprehensive 2>&1 | grep "OpenSSL"
```

### Coverage Tests Fail

```bash
# Check which function fails
./test_crypto_coverage 2>&1 | grep "FAIL"
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run Modern Test Suite
  run: |
    make check -C test
    make -C test check-valgrind
```

### GitLab CI

```yaml
test:
  script:
    - make check -C test
  artifacts:
    when: on_failure
    paths:
      - test/*.log
```

### Jenkins

```groovy
stage('Modern Tests') {
    steps {
        sh 'make check -C test'
        sh 'make -C test check-valgrind'
    }
}
```

## Requirements

### Build Requirements

- OpenSSL 3.0+ development headers
- Automake, Autoconf, Libtool
- GCC or Clang with C99 support
- pkg-config

### Runtime Requirements

- OpenSSL 3.0+ libraries
- Linux kernel 4.0+ (for modern crypto)

### Optional

- Valgrind (for memory leak detection; `test/` and `src/racoon/` only)
- lcov (for code coverage via `--enable-coverage`; `test/` only)
- GDB (for debugging)

## Adding New Tests

### Add to Existing File

```c
// In test_crypto_coverage.c
int test_my_new_function()
{
        TEST_START("My New Function");

        // Test code here

        if (/* success */) {
                printf("Success ");
                TEST_PASS();
                return 0;
        } else {
                TEST_FAIL("Reason");
        }
}

// In main():
if (test_my_new_function() != 0) failed++;
```

### Add New Test File

```bash
# 1. Create test file
vim test/test_new_feature.c

# 2. Update test/Makefile.am
# Add to check_PROGRAMS:
check_PROGRAMS += test_new_feature

# Add compilation rules:
test_new_feature_SOURCES = test_new_feature.c
test_new_feature_LDADD   = $(COMMON_LDADD)
test_new_feature_LDFLAGS = $(AM_LDFLAGS)

# 3. Rebuild
make -C test
```

### Testing a Static (or Otherwise Unreachable) Function Directly

Several racoon source files export nothing a test could link against --
the function under test is `static`, or it is reachable only from inside a
real `fork()`/privilege-drop (`privsep_init()`) that not every build host
can perform. The established pattern for both, used throughout this suite
(`session_unittest_src.c`, `kmpstat_unittest_src.c`, `privsep_unittest_src.c`,
and others):

1. A tiny wrapper source file (`<module>_unittest_src.c`) `#include`s the
   real `.c` file directly, so the test binary gets its own private
   compilation of it -- `static` functions included.
2. The module itself gets a handful of `#ifdef ENABLE_UNITTEST` accessors
   at its own end for whatever internal state or `static` function a test
   needs to reach, but does not otherwise change: no new production API,
   no behaviour change.
3. The test's own `check_PROGRAMS` entry in `test/Makefile.am` compiles
   the wrapper with `-DENABLE_UNITTEST -ffunction-sections -fdata-sections`
   and links with `-Wl,--gc-sections`, so only the functions the test
   actually reaches (plus whatever `--gc-sections` cannot prove dead) end
   up in the binary -- see any `test_privsep_*` block in `test/Makefile.am`
   for the concrete flags.
4. Guarded (`if !SANITIZER_BUILD`) by default: `--gc-sections` dead-code
   elimination and ASan do not get along on this project's toolchain, so a
   binary built this way is ordinarily skipped under a sanitizer build.
   Where the module under test needs no dependencies outside itself (every
   `privsep.c`-only `test_privsep_*` binary — see `doc/dev/
   privsep-hardening-followup-audit.md` §9.4 for the investigation), a
   `SANITIZER_BUILD`-conditional variant that drops `-ffunction-sections`/
   `--gc-sections` and links whatever those flags were otherwise pruning
   away can build a genuinely ASan/UBSan-instrumented binary instead of
   skipping it outright; not every module's dependency closure is small
   enough for that to be practical, though (`session.c`'s is not, for
   example), so this is a per-target judgment call, not something to apply
   uniformly.

`privsep_priv()` (privsep.c's privileged dispatch loop, extracted from
`privsep_init()` -- see `doc/dev/privsep-priv-extraction.md`) is a
variant worth calling out explicitly: it is *not* wrapped in an
`ENABLE_UNITTEST`-only accessor the way `send_fd()`/`rec_fd()` etc. are.
It has ordinary external linkage and is called directly, by design -- a
test forks, the child calls `privsep_priv(sock)` for real (same
`_exit(0)`/`_exit(1)` as production, untouched), and the parent drives
`sock` as the unprivileged side over a plain `socketpair()`. See
`test_privsep_priv_*.c` for the pattern and `privsep_priv_test_stubs.c`
for the stub layer (a real, minimal `struct localconf`; canned
`eay_get_pkcs1privkey()`/`getpsk()`; a `script_exec()` that only records
its call, never `fork()+execve()`s) that lets the real dispatch loop run
without a privilege drop or a real kernel.

Because `privsep_priv()` always exits via `_exit()`, its own module's
coverage under `--enable-coverage` needs one more piece: `_exit()`
bypasses gcov's normal `atexit()`-registered flush, so the forked child's
counters never reach disk on their own. Every `check_PROGRAMS` target that
compiles `privsep.c` (via `privsep_unittest_src.c`) links
`privsep_gcov_dump_shim.c` and `-Wl,--wrap=_exit` under `ENABLE_COVERAGE`
(`test/Makefile.am`) to flush counters before the real `_exit()` runs --
see `doc/dev/privsep-priv-extraction.md` §5 for the full writeup, including
a second, separate gap this same fix closed (`make coverage` not scanning
`test/` at all, so every `<module>_unittest_src.c`-only module, not just
`privsep.c`, was previously missing from the report entirely).

#### The Other Half: Client-Side Wrappers and `privsep_init()` Itself

`test_privsep_priv_*.c` above only ever drives the *privileged* side of
privsep.c's wire protocol, playing the unprivileged side itself by
hand-crafting wire messages by hand. Three more `check_PROGRAMS` targets
cover the other half -- the client-side wrapper functions
(`privsep_eay_get_pkcs1privkey()`, `privsep_getpsk()`,
`privsep_script_exec()`, `privsep_socket()`, `privsep_bind()`, and the
`ENABLE_HYBRID`/`HAVE_LIBPAM` ones) and `privsep_init()` itself, the one
privsep.c entry point every other test in this suite deliberately
bypasses:

- **`test_privsep_client_wrappers.c`** / **`test_privsep_hybrid_client_wrappers.c`**
  (the latter split out because its content -- `port_check()`,
  `privsep_xauth_login_system()`, `privsep_accounting_system()`, and,
  nested under `HAVE_LIBPAM`, `privsep_accounting_pam()`/
  `privsep_xauth_login_pam()`/`privsep_cleanup_pam()` -- is
  `ENABLE_HYBRID`-only, guarded by `#ifdef ENABLE_HYBRID`/nested `#ifdef
  HAVE_LIBPAM` at the C level rather than a second automake conditional,
  so a build with either off still gets the binary in `make check`'s
  output with fewer, or for `ENABLE_HYBRID` none, cases actually run).
  Every function gets two cases: "passthrough" (called as this binary's
  own root, taking each wrapper's own `if (geteuid() == 0) return <real
  syscall/function>(...)` branch directly) and "wire protocol" (this
  process's effective uid dropped to `nobody`, so the same call instead
  builds and sends the real wire message, against a forked child running
  the real `privsep_priv()` -- `privsep_unittest_src.c` +
  `privsep_priv_test_stubs.c`, same as `test_privsep_priv_*.c` above).
  Real production code on both ends of the real wire protocol; the two
  test suites together just never run both ends in the same process
  (`privsep_init()`'s own fork() is the only thing that does that for
  real -- see below).

  The shared driver for the "wire protocol" case, `privsep_wire_roundtrip.c`
  (linked into both binaries), needs two new `privsep.c` `ENABLE_UNITTEST`
  accessors: `privsep_set_sock_unittest()`/`privsep_get_sock_unittest()`
  point the client wrappers' own static `privsep_sock[]` -- normally only
  ever written by a real `privsep_init()` -- at a test socketpair, and
  `privsep_reset_state_unittest()` clears it (and `privsep_child_pid`)
  between scenarios in the same process. `port_check_unittest()` exposes
  the other new static accessor, `port_check()` itself.

- **`test_privsep_init.c`** drives `privsep_init()` directly for its two
  side-effect-free early-return cases (`lcconf->uid == 0`; a missing
  cert/script path); for a third, `lcconf->chroot` pointed at a path that
  does not exist, so the real forked child's `chdir()` fails and
  `privsep_init()` returns `-1` before ever reaching `setgid()`/`setuid()`/
  `monitor_fd()`; and, for the real `socketpair()`+`fork()`+`chroot()`/
  `setgid()`/`setuid()`+`monitor_fd()`+`privsep_priv()` happy path, forks a
  disposable child first so every one of those side effects happens inside
  a process this test binary itself never becomes -- `privsep_init()`'s
  *own* internal `fork()` then produces a second, further-nested child
  that actually drops privilege and makes one real `ENABLE_HYBRID`
  client-wrapper call over the *real* `privsep_sock` (no test accessor
  involved at that point -- it is the genuine, fully production
  `privsep_init()` setup), reporting its verdict back up a pipe since it
  is not the outer test process's own direct child and gets reparented
  once its parent exits. See the file's own header comment for the full
  three-process breakdown, shared by both of these last two scenarios via
  one `run_forked_privsep_init()` helper parameterized by a
  per-scenario callback for what the innermost child does with
  `privsep_init()`'s return value. The `ENABLE_HYBRID` round trip is the
  one scenario in this suite that reaches `privsep_priv()`'s
  `ENABLE_HYBRID` dispatch cases through the real production entry point
  rather than a synthetic direct `privsep_priv(sock)` call.

  Needs `session_unittest_src.c` linked alongside the usual
  `privsep_unittest_src.c` (for `monitor_fd()`, which `privsep_init()`'s
  child branch calls) and, less obviously, `session.c`'s own
  `init_fd_monitor_unittest()` accessor called *before* forking: in
  production, `monitor_fd()`'s `TAILQ_INSERT_TAIL()` into `fd_monitor_tree[]`
  is only safe because `session()`'s own startup always `TAILQ_INIT()`s it
  long before `privsep_init()` ever forks, so the real child just inherits
  already-initialized state. A test that calls `privsep_init()` directly,
  with none of that surrounding startup, hits a `TAILQ_INSERT_TAIL()` into
  a head that is still its all-zero static default -- confirmed to
  segfault the real forked child immediately until this was added.

  Left as a documented gap rather than a silent one: a real, *successful*
  `chroot()` (as opposed to the deliberate `chdir()` failure above) is
  never exercised -- setting up a real, populated jail directory is an
  orthogonal concern from what this file tests, and getting it wrong risks
  the test host rather than just a failing test.

- **`test_privsep_init_fork_failure.c`** covers `privsep_init()`'s
  remaining branch: `fork()` itself failing. A separate binary, because it
  is linked with `-Wl,--wrap=fork` (same technique as `test_script_hook_leak.c`'s
  own `-Wl,--wrap=free`), redirecting *every* `fork()` call in the binary
  to a `__wrap_fork()` that always fails with `EAGAIN` -- which would break
  `test_privsep_init.c`'s own real-fork scenarios if applied there instead.
  Asserts `privsep_init()` returns `-1` and, via an open-file-descriptor
  count from `/proc/self/fd` taken immediately before and after the call,
  that it leaks nothing. Writing this test caught a real bug it now pins:
  `privsep_init()`'s `socketpair()` call happens *before* its `fork()`
  call, so a failing `fork()` used to return `-1` having leaked both
  `privsep_sock[]` descriptors -- fixed in `privsep.c` alongside this test.
  Needs no real root at all (`fork()` never actually runs, wrapped or
  not), so this one runs unconditionally regardless of who invokes
  `make check`.

`test_privsep_client_wrappers`, `test_privsep_hybrid_client_wrappers`, and
two of `test_privsep_init`'s four scenarios need real root to reach their
wire-protocol/privilege-drop/real-`chroot()`-attempt cases (`seteuid()` to
a different account, or a real forked child's own `setgid()`/`setuid()`,
both need `CAP_SETUID`) and detect and skip (exit 77, or -- for
`test_privsep_init`'s two root-independent scenarios -- just keep running
normally) rather than fail when they don't have it.
`test_privsep_init_fork_failure` is the one exception: since its wrapped
`fork()` never actually runs, it needs no privilege at all and always
runs in full. See `CONTRIBUTING.md`'s "Running the Test Suite" section for
what all of this looks like in `make check`'s own output and why
`fakeroot` is not a substitute for actually being root here.

#### Overriding a Production Timing Constant for One Binary

`privsep_priv()`'s mid-request bound (`PRIVSEP_IPC_WAIT_MAX_MS`,
privsep.c -- 3s in production, doc/dev/fatal-exit-path-audit.md §2.3.1)
needs to actually *fire* to be tested, which nobody wants costing 3 real
seconds per run. `privsep.c` exposes a compile-time-only seam for this:

```c
#ifdef PRIVSEP_IPC_WAIT_MAX_MS_UNITTEST_OVERRIDE
#define PRIVSEP_IPC_WAIT_MAX_MS  PRIVSEP_IPC_WAIT_MAX_MS_UNITTEST_OVERRIDE
#else
#define PRIVSEP_IPC_WAIT_MAX_MS  3000
#endif
```

Only `test_privsep_priv_bounded_wait`'s own `_CPPFLAGS` in
`test/Makefile.am` defines
`-DPRIVSEP_IPC_WAIT_MAX_MS_UNITTEST_OVERRIDE=200`; every other
`check_PROGRAMS` target -- including the other three `test_privsep_priv_*`
binaries, which recompile the same `privsep.c` via the same
`privsep_unittest_src.c` wrapper -- gets the ordinary 3000ms constant,
because each `check_PROGRAMS` target compiles its own private copy of
every wrapper source with its own flags (the `<target>-<source>.o` naming
`make check`'s build output shows is this in action). The production
`racoon`/`racoonctl` build never defines the override macro at all, so
`src/racoon/privsep.o` is completely unaffected -- this is "a compile-time
... seam, not a runtime knob the production binary also exposes" (the
constraint this pattern was written to satisfy), and the general
technique -- an `#ifdef SOMETHING_UNITTEST_OVERRIDE` around one constant,
defined only in one test target's own `_CPPFLAGS` -- generalises to any
future case where a real production constant needs shrinking for exactly
one test binary without becoming a runtime option anywhere else.

## Maintenance

### Regular Tasks

- ✅ Run tests after every commit
- ✅ Run valgrind weekly (`cd test && make check-valgrind`)
- ✅ Update tests when adding features
- ✅ Review test coverage monthly

### OpenSSL Updates

When updating OpenSSL:

```bash
# 1. Update and rebuild
sudo apt-get upgrade libssl-dev
make clean && make

# 2. Run all tests
make check -C test

# 3. Check for deprecation warnings (see "OpenSSL Deprecation-Warning
#    Report" above for the dedicated tooling)
./configure --enable-warn-deprecated && make dev

# 4. Run valgrind
cd test && make check-valgrind
```

## Known Issues

### OpenSSL 3.0.0 - 3.0.7

- EVP_PKEY_verify_recover may have issues
- Workaround: Update to 3.0.8+

### ARM Architecture

- DH operations may be slower
- Expected: 2-3x slower than x86_64

### Valgrind False Positives

- OpenSSL may show "still reachable" memory
- This is normal, not a leak

## Support

### Test Failures

1. Check OpenSSL version: `openssl version`
2. Check test logs: `cat test/*.log`
3. Run with debug: `gdb ./test/test_name`
4. Check with valgrind: `valgrind ./test/test_name`

### Build Issues

1. Clean and rebuild: `make clean && make`
2. Regenerate: `autoreconf -fi`
3. Check configure: `./configure --help`

## License

See top-level LICENSE file.

## Contributors

See top-level AUTHORS file.

## References

- RFC 2409 - IKE (MODP groups 1-4)
- RFC 3526 - Additional MODP groups (5-18)
- RFC 8247 - Algorithm Implementation Requirements
- OpenSSL 3.0 Migration Guide
- Racoon2 Documentation
</content>
