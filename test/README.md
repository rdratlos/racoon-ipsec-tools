# Racoon IPSec - Test Suite

Modern test suite for Racoon IPSec OpenSSL 3.0 migration validation.

## Test Structure

```
test/
├── test_dh_modp_groups.c       - DH: All 8 MODP groups (7 tests)
├── test_rsa_comprehensive.c    - RSA: Textbook RSA validation (12 tests)
├── test_crypto_coverage.c      - Coverage: All eay_* functions (~40 tests)
├── Makefile.am                 - Automake control
└── README.md                   - This file
```

## Quick Start

```bash
# Run all tests
make check

# Run specific test
./test/test_dh_modp_groups

# Run with valgrind
make check-valgrind -C test

# Run with verbose output
make check-verbose -C test
```

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

### test_crypto_coverage.c (~40 tests)

**Purpose:** Complete coverage of all eay_* functions  
**Coverage:** Ciphers, hashing, HMAC, X.509, utilities

**Test Categories:**
- ✅ Symmetric ciphers (DES, 3DES, AES, Blowfish, CAST, IDEA, RC5, Camellia)
- ✅ Hash functions (MD5, SHA1, SHA2-256, SHA2-384, SHA2-512)
- ✅ HMAC functions (HMAC-MD5, HMAC-SHA1, HMAC-SHA2-*)
- ✅ X.509 certificate parsing
- ✅ ASN.1 DN conversion
- ✅ Base64 encoding/decoding
- ✅ Random number generation
- ✅ BIGNUM conversions
- ✅ Utility functions

**Run:** `./test_crypto_coverage`

## Running Tests

### All Tests

```bash
# Run all modern tests
make check -C test

# Run legacy + modern tests
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

# Quick test (DH + RSA)
make check-quick -C test
```

### With Memory Leak Detection

```bash
# Run with valgrind
make check-valgrind -C test

# Expected output: 0 bytes leaked
```

### With Verbose Output

```bash
# Verbose mode
make check-verbose -C test

# Or run directly
./test/test_dh_modp_groups -v
```

### Performance Benchmarks

```bash
# Run benchmarks
make benchmark -C test

# Shows:
# - DH key generation time per group
# - RSA sign/verify time per key size
# - Cipher performance
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

## Test Coverage

| Component | eaytest (legacy) | Modern Tests | Coverage |
|-----------|------------------|--------------|----------|
| **DH Operations** | Basic (8 groups) | Complete (g=2,g=5) | ✅✅✅ |
| **RSA Operations** | Basic | Textbook RSA | ✅✅✅ |
| **Symmetric Ciphers** | Basic | Complete | ✅✅✅ |
| **Hash Functions** | Basic | Complete | ✅✅✅ |
| **HMAC Functions** | Basic | Complete | ✅✅✅ |
| **X.509 Certs** | Basic | Complete | ✅✅✅ |
| **Utilities** | Basic | Complete | ✅✅✅ |

**Total:** ~59 modern tests + 8 legacy tests = **67 tests**

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

# Run single test
# (Modify main() to run only one test)
```

### Coverage Tests Fail

```bash
# Check which function fails
./test_crypto_coverage 2>&1 | grep "FAIL"

# Test that function directly
# (Add debug output to test)
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run Modern Test Suite
  run: |
    make check -C test
    make check-valgrind -C test
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
        sh 'make check-valgrind -C test'
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

- Valgrind (for memory leak detection)
- lcov (for code coverage)
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
test_new_feature_CFLAGS = $(AM_CFLAGS)
test_new_feature_LDADD = $(LDADD)

# 3. Rebuild
make -C test
```

## Maintenance

### Regular Tasks

- ✅ Run tests after every commit
- ✅ Run valgrind weekly
- ✅ Update tests when adding features
- ✅ Review test coverage monthly

### OpenSSL Updates

When updating OpenSSL:

```bash
# 1. Update and rebuild
sudo apt-get upgrade libssl-dev
make clean && make

# 2. Run all tests
make check

# 3. Check for deprecation warnings
make 2>&1 | grep deprecated

# 4. Run valgrind
make check-valgrind -C test
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

### Performance Issues

1. Check CPU: `lscpu`
2. Check OpenSSL: `openssl speed rsa2048`
3. Run benchmarks: `make benchmark -C test`

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
