# Kernelpaws Test Proposal & Integration Testing Annex

## 1. Overview

This document defines the test-driven development (TDD) strategy for the
kernelpaws kernel abstraction layer. It is organized into four categories:

| Category | Target | Environment | Purpose |
|----------|--------|-------------|---------|
| **A. Unit Tests** | Netlink message construction/parsing, address conversion | Mocked sockets, no kernel | Catch format, alignment, and encoding bugs early |
| **B. Integration Tests** | Real XFRM SA/Policy lifecycle | Real kernel, privileged process | Verify kernelpaws works against live XFRM subsystem |
| **C. Failure Path Tests** | Error handling, kernel rejection | Error-injection mode or real kernel edge cases | Verify graceful degradation and error propagation |
| **D. End-to-End Tests** | Full IKEv1 SA establishment | Incus/LXC containers, roadwarrior topology | Verify complete Racoon daemon with XFRM backend |

### 1.1 Design Philosophy

- **TDD ordering**: Write tests before implementation. Each kernelpaws_ops
  function must have at least one unit test and one integration test before
  its XFRM backend implementation is considered complete.
- **Hybrid model**: Lightweight unit tests for message construction/parsing
  (mocked sockets, fast execution), integration tests for real kernel
  interaction (privileged, slower), end-to-end tests for full daemon
  verification (containers, slowest).
- **Adapted VPP pattern**: LibreSwan's `testing/pluto/` directory contains
  1000+ integration tests using a directory-per-test convention with
  declarative scripts. Racoon has **zero** integration tests. We adopt a
  simplified subset of this pattern for the XFRM migration.
- **No libnl dependency**: Unit tests must validate raw netlink message
  construction without external libraries.

---

## 2. Test Infrastructure

### 2.1 Build System Integration

```
tests/
  Makefile.am              - Top-level test build rules
  unit/
    Makefile.am            - Unit test build
    test_netlink_build.c   - Netlink message construction tests
    test_netlink_parse.c   - Netlink message parsing tests
    test_addr_conv.c       - Address conversion tests
    test_alignment.c       - 32-bit alignment validation
    mock_netlink.c         - Mock netlink socket pair infrastructure
    mock_netlink.h
  integration/
    Makefile.am            - Integration test build
    test_sa_lifecycle.c    - SA add/update/delete tests
    test_policy_lifecycle.c - Policy add/delete/flush tests
    test_spi_alloc.c       - SPI allocation tests
    test_notification.c    - ACQUIRE/EXPIRE notification tests
    test_error_paths.c     - Kernel error injection tests
    integration_common.c   - Shared helpers (socket setup, assertions)
    integration_common.h
```

Tests are controlled by a configure flag:
```autoconf
AC_ARG_ENABLE([tests],
  [AS_HELP_STRING([--enable-tests], [build test suite @<default=no>@])],
  [], [enable_tests=no])

AS_IF([test "x$enable_tests" = "xyes"],
  [SUBDIRS += tests])
```

Run via `make check` (unit tests) and `make check-integration` (integration).

### 2.2 Assertion Framework

Minimal, self-contained assertion macros (no external test framework):

```c
// tests/test_assert.h
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { test_fail(__FILE__, __LINE__, msg, #cond); } \
} while (0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { test_fail(__FILE__, __LINE__, msg, #a " != " #b); } \
} while (0)

#define TEST_ASSERT_EQ_MSG(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        test_fail_hex(__FILE__, __LINE__, msg, (a), (b), (len)); \
    } \
} while (0)
```

Test runner pattern:
```c
static int tests_run = 0;
static int tests_failed = 0;

static void test_sa_add_basic(void) {
    tests_run++;
    // ... setup, execute, assert ...
}

int main(void) {
    test_sa_add_basic();
    test_sa_add_ipv6();
    // ...
    printf("%d tests run, %d failed\n", tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
```

### 2.3 Privilege Requirements

| Category | Privileges | Rationale |
|----------|------------|-----------|
| Unit tests | None | Mocked sockets; no kernel interaction |
| Integration tests | `CAP_NET_ADMIN` | Creates netlink sockets, installs XFRM SA/Policy |
| End-to-end tests | Container management (Incus/LXC) | Full network namespace isolation |

---

## 3. Category A: Unit Tests

Unit tests validate the correctness of netlink message construction and
parsing in isolation, without any kernel interaction. All socket I/O is
intercepted via a mock socket pair.

### 3.1 Mock Netlink Socket Infrastructure

```c
// tests/unit/mock_netlink.h
struct mock_nl_socket {
    int fd;                     // Actual socketpair() FD
    uint32_t seq;               // Next sequence number to assign
    uint32_t pid;               // Local netlink PID
    struct mock_response {      // Pre-programmed responses
        const char *buf;
        size_t len;
    } responses[32];
    unsigned response_idx;
};

// Create a mock socket pair (socketpair(AF_NETLINK, ...))
struct mock_nl_socket *mock_nl_create(void);

// Pre-program a response (NLMSG_ERROR with -EINVAL, etc.)
void mock_nl_enqueue_response(struct mock_nl_socket *m,
                               const char *buf, size_t len);

// Intercept: replace sendmsg to capture outgoing messages
void mock_nl_capture_outgoing(struct mock_nl_socket *m,
                               char **out_buf, size_t *out_len);

void mock_nl_destroy(struct mock_nl_socket *m);
```

The mock intercepts `sendmsg()` on the socket FD via a wrapper socket pair,
capturing the raw netlink buffer for inspection. The caller can then validate
the constructed message byte-for-byte.

### 3.2 Test Cases: Netlink Message Construction

#### A1: SPI Allocation (`XFRM_MSG_ALLOCSPI`)

```
Test: test_allocspi_message_ipv4
  Given: IPv4 SA parameters (src=10.0.0.1, dst=10.0.0.2, proto=ESP)
  When: kernelpaws_xfrm builds XFRM_MSG_ALLOCSPI message
  Then: Message contains:
    - nlmsghdr.nlmsg_type == XFRM_MSG_ALLOCSPI
    - xfrm_userspi_info with correct src, dst, proto, mode
    - XFRMA_SA_DIR attribute set to XFRM_DIR_INBOUND
    - No crypto attributes (SPI allocation doesn't include keys)
    - nlmsg_seq is non-zero, nlmsg_pid matches local PID
  Verify: Raw buffer byte layout matches expected construction
```

```
Test: test_allocspi_message_ipv6
  Same as above with IPv6 addresses (AF_INET6, 128-bit addresses)
```

```
Test: test_allocspi_spi_range
  Given: SPI range [0x1000, 0x1FFF]
  When: ALLOCSPI message is built
  Then: xfrm_userspi_info.min_alloc and max_alloc match range
```

#### A2: SA Add (`XFRM_MSG_NEWSA`)

```
Test: test_newsa_message_esp_transport
  Given: ESP SA in transport mode (src, dst, spi, key, lifetime)
  When: NEWSA message is built
  Then: Message contains:
    - nlmsghdr.nlmsg_type == XFRM_MSG_NEWSA
    - xfrm_usersa_info with src, dst, proto=ESP, mode=XFRM_MODE_TRANSPORT
    - XFRMA_ALG_AUTH attribute with HMAC-SHA1-96 algo + key
    - XFRMA_ALG_CRYPT attribute with AES-CBC-128 algo + key
    - Lifetimes: soft/hard byte and time values encoded
    - replay_window field in xfrm_usersa_info
    - NLM_F_REQUEST | NLM_F_ACK flags
```

```
Test: test_newsa_message_esp_tunnel
  Same as above, mode=XFRM_MODE_TUNNEL, with tunnel address (tunnel_dst)
```

```
Test: test_newsa_message_aead
  Given: AES-GCM-128 AEAD SA
  When: NEWSA message is built
  Then: XFRMA_ALG_AEAD attribute present (NOT ALG_AUTH + ALG_CRYPT)
```

```
Test: test_newsa_message_ah
  Given: AH SA (auth-only, no encryption)
  When: NEWSA message is built
  Then: Only XFRMA_ALG_AUTH present, no XFRMA_ALG_CRYPT
```

```
Test: test_newsa_esn_enabled
  Given: SA with ESN enabled, replay_window=64
  When: NEWSA message is built
  Then: XFRMA_REPLAY_ESN_VAL attribute with xfrm_replay_state_esn
```

```
Test: test_newsa_mark
  Given: SA with policy mark (value=0x1, mask=0xFFFFFFFF)
  When: NEWSA message is built
  Then: XFRMA_MARK attribute present with correct value/mask
```

#### A3: SA Update (`XFRM_MSG_UPDSA`)

```
Test: test_updsa_message
  Given: Existing SA (spi, src, dst, proto) with updated lifetime
  When: UPDSA message is built
  Then: nlmsg_type == XFRM_MSG_UPDSA, same structure as NEWSA
    but without key attributes (kernel already has keys)
```

#### A4: SA Delete (`XFRM_MSG_DELSA`)

```
Test: test_delsa_message
  Given: SA identifier (spi, src, dst, proto)
  When: DELSA message is built
  Then: nlmsg_type == XFRM_MSG_DELSA, xfrm_usersa_id with correct fields
```

#### A5: Policy Add (`XFRM_MSG_NEWPOLICY`)

```
Test: test_newpolicy_message_basic
  Given: Policy (src_sel, dst_sel, dir=IN, tmpl=ESP tunnel)
  When: NEWPOLICY message is built
  Then: nlmsg_type == XFRM_MSG_NEWPOLICY
    - xfrm_userpolicy_info with dir, priority, action=XFRM_POLICY_ALLOW
    - XFRMA_TMPL attribute with one template (dst, proto, mode)
    - Selector fields in xfrm_userpolicy_info.sel correct
```

```
Test: test_newpolicy_multiple_tmpl
  Given: Policy with two IPsec templates (ESP + AH, for fallback)
  When: NEWPOLICY message is built
  Then: XFRMA_TMPL contains two nested rtattr entries
```

```
Test: test_newpolicy_selector
  Given: Policy with non-trivial selector (src=10.0.0.0/24,
         dst=192.168.1.0/24, proto=TCP, dport=443)
  When: NEWPOLICY message is built
  Then: xfrm_userpolicy_info.sel contains all selector fields
    with correct prefixlen
```

#### A6: Policy Delete (`XFRM_MSG_DELPOLICY`)

```
Test: test_delpolicy_by_index
  Given: Kernel-assigned policy index
  When: DELPOLICY message is built
  Then: xfrm_userpolicy_id with correct index, dir, family
```

#### A7: Policy Flush & SA Flush

```
Test: test_flushpolicy_message
  When: FLUSHPOLICY message is built
  Then: nlmsg_type == XFRM_MSG_FLUSHPOLICY, minimal payload
```

```
Test: test_flushsa_message
  When: FLUSHSA message is built
  Then: nlmsg_type == XFRM_MSG_FLUSHSA, xfrm_usersa_flush with
    family=AF_UNSPEC, spi=0 (flush all)
```

#### A8: EACQUIRE Acknowledgment

```
Test: test_eacquire_skip_policy
  Given: Acquired policy (src_sel, dst_sel)
  When: skip policy is built (XFRM_POLICY_ADD, action=XFRM_POLICY_SKIP)
  Then: NEWPOLICY with action=SKIP, no XFRMA_TMPL
    (acknowledges the acquire by telling kernel to bypass policy)
```

### 3.3 Test Cases: Netlink Message Parsing

These tests validate the response/notification parsing code by feeding
pre-constructed netlink buffers through the parser.

```
Test: test_parse_allocspi_response
  Given: Pre-constructed XFRM_MSG_NEWSA response (from ALLOCSPI request)
  When: Parser processes the message
  Then: Extracted SPI matches expected value
    - nlmsg_seq matches request sequence
    - xfrm_usersa_info.id.spi is the allocated SPI
```

```
Test: test_parse_nlmsg_error_success
  Given: NLMSG_ERROR with err->error == 0
  When: Parser processes the message
  Then: Returns success (no error condition)
```

```
Test: test_parse_nlmsg_error_failure
  Given: NLMSG_ERROR with err->error == -EINVAL
  When: Parser processes the message
  Then: Returns -1, errno == EINVAL
```

```
Test: test_parse_nlmsg_error_enobufs
  Given: NLMSG_ERROR with err->error == -ENOBUFS
  When: Parser processes the message
  Then: Returns -1, errno == ENOBUFS
```

```
Test: test_parse_acquire_notification
  Given: Pre-constructed XFRM_MSG_ACQUIRE multicast message
  When: Parser processes the xfrm_user_acquire
  Then: Extracted selector (src, dst, proto, family) matches
    Expected selector. 64-bit fields (curlft.bytes, curlft.packets)
    are read via memcpy (NOT direct dereference).
```

```
Test: test_parse_expire_notification
  Given: Pre-constructed XFRM_MSG_EXPIRE multicast message
  When: Parser processes the xfrm_user_expire
  Then: Extracted (spi, src, dst, proto) matches expected SA
    hard_len_expires and soft_len_expires flags are correct
```

```
Test: test_parse_polexpire_notification
  Given: Pre-constructed XFRM_MSG_POLEXPIRE message
  When: Parser processes the xfrm_user_polexpire
  Then: Extracted policy index matches expected value
```

```
Test: test_parse_migrate_notification
  Given: Pre-constructed XFRM_MSG_MIGRATE message
  When: Parser processes the xfrm_user_migrate
  Then: Extracted new peer address matches expected value
```

```
Test: test_parse_correlated_response_skip_unrelated
  Given: Message stream with 2 messages:
    (1) Unrelated multicast (wrong nlmsg_seq)
    (2) Expected response (matching nlmsg_seq)
  When: Correlation loop processes the stream
  Then: Skips message (1), returns message (2)
```

### 3.4 Test Cases: Address Conversion

```
Test: test_addr_conv_ipv4
  Given: Racoon secasindex with AF_INET, 10.0.0.1
  When: Converted to xfrm_address_t
  Then: Family == AF_INET, a4.s_addr matches
```

```
Test: test_addr_conv_ipv6
  Given: Racoon secasindex with AF_INET6, 2001:db8::1
  When: Converted to xfrm_address_t
  Then: Family == AF_INET6, a6.in6_addr matches
```

```
Test: test_selector_conv_basic
  Given: Racoon policyindex with src=10.0.0.0/24, dst=192.168.1.0/24, proto=ESP
  When: Converted to xfrm_selector
  Then: sel.src, sel.dst, sel.proto, sel.prefixlen_dst all correct
```

```
Test: test_selector_conv_any
  Given: Racoon policyindex with src=%any (0.0.0.0/0)
  When: Converted to xfrm_selector
  Then: sel.prefixlen_src == 0, sel.src is zeroed
```

```
Test: test_selector_conv_port_range
  Given: Racoon policyindex with srcport=[500,500], dstport=[any,any]
  When: Converted to xfrm_selector
  Then: sel.sport[15]==500, sel.dport[0]==0, sport_mask==0xFFFF
```

### 3.5 Test Cases: 32-bit Alignment

**CRITICAL**: These tests verify that 64-bit fields in XFRM netlink
structures are accessed via `memcpy()` and never directly dereferenced.

```
Test: test_acquire_64bit_alignment
  Given: xfrm_user_acquire struct at 32-bit aligned offset in buffer
  When: 64-bit fields (curlft.bytes, replay_seq) are read
  Then: Values are correct (read via memcpy)
  Method: Deliberately construct buffer with misaligned 64-bit fields,
    verify memcpy produces correct values while direct dereference
    would produce garbage on strict architectures.
```

```
Test: test_expire_64bit_alignment
  Same pattern for xfrm_user_expire
```

```
Test: test_compile_time_alignment_check
  Method: Use static assertions or compiler warnings:
    Compile with -Werror=address-of-packed-member, verify no warnings
    from kernelpaws_xfrm.c
```

### 3.6 Test Summary: Unit Tests

| Test ID | Category | Count |
|---------|----------|-------|
| A1 | SPI allocation construction | 3 |
| A2 | SA add construction | 6 |
| A3 | SA update construction | 1 |
| A4 | SA delete construction | 1 |
| A5 | Policy add construction | 3 |
| A6 | Policy delete construction | 1 |
| A7 | Flush construction | 2 |
| A8 | EACQUIRE construction | 1 |
| A9 | Response parsing | 5 |
| A10 | Notification parsing | 4 |
| A11 | Correlation loop | 1 |
| A12 | Address conversion | 5 |
| A13 | 32-bit alignment | 3 |
| **Total** | | **36** |

---

## 4. Category B: Integration Tests

Integration tests run against the **real kernel XFRM subsystem**. These
tests require `CAP_NET_ADMIN` and root privileges. They validate that
kernelpaws correctly installs, queries, and removes SAs and policies.

### 4.1 Test Environment

```
  +---------------------------+
  |  Integration Test Binary  |
  |                           |
  |  test_sa_lifecycle        |  CAP_NET_ADMIN
  |  test_policy_lifecycle    |  Runs on real Linux kernel
  |  test_spi_alloc           |  Verifies with ip xfrm state/policy
  +---------------------------+
           |
           v
  +---------------------------+
  |  Linux Kernel XFRM        |
  |  Subsystem                |
  +---------------------------+
```

### 4.2 Common Helper Functions

```c
// tests/integration/integration_common.h

// Setup: create netlink sockets, initialize kernelpaws_xfrm backend
int integration_setup(void);
void integration_teardown(void);

// Verify helpers using external commands:
// "ip xfrm state list" -> parse output -> return SA count
int integration_verify_sa_count(int expected);
int integration_verify_policy_count(int expected);

// "ip xfrm state list src <a> dst <b> proto esp" -> verify SA exists
int integration_verify_sa_exists(struct in_addr *src, struct in_addr *dst,
                                  int proto, uint32_t spi);

// "ip xfrm policy list" -> verify policy exists
int integration_verify_policy_exists(int dir, uint32_t index);

// xfrmcheck equivalent: verify /proc/net/xfrm_stat has no errors
int integration_verify_xfrm_stat_clean(void);

// Cleanup: flush all SAs and policies
void integration_flush_all(void);
```

### 4.3 Test Cases: SA Lifecycle

```
Test: B1_sa_add_delete_esp_transport
  Given: Clean kernel state (flushed)
  When: kernelpaws_backend->send_add() installs ESP transport SA
    (src=10.0.0.1, dst=10.0.0.2, proto=ESP, mode=transport,
     auth=HMAC-SHA1, encrypt=AES-CBC-128)
  Then:
    - ip xfrm state shows exactly 1 new SA
    - SA has correct src, dst, proto, mode, spi
    - Algorithm names match (sha1, aes)
    - /proc/net/xfrm_stat shows no errors
  Cleanup: send_delete(), verify SA is removed
```

```
Test: B2_sa_add_delete_esp_tunnel
  Same as B1 but with tunnel mode, tunnel_dst=192.168.1.1
```

```
Test: B3_sa_add_delete_ah
  Same as B1 but with AH protocol (auth-only)
```

```
Test: B4_sa_add_delete_ipv6
  Same as B1 but with IPv6 addresses
```

```
Test: B5_sa_add_with_aead
  Given: AES-GCM-128 AEAD parameters
  When: send_add() installs AEAD SA
  Then: ip xfrm state shows SA with auth=aes_gcm_cm_128 (or equivalent)
    No separate auth and encrypt entries
```

```
Test: B6_sa_add_replay_window
  Given: SA with replay_window=32
  When: send_add() installs SA
  Then: ip xfrm state shows replay-window=32
```

```
Test: B7_sa_add_lifetime_bytes
  Given: SA with hard byte lifetime = 1GB
  When: send_add() installs SA
  Then: ip xfrm state shows lifetime bytes correct
    (soft and hard lifetime values)
```

```
Test: B8_sa_update_lifetime
  Given: Existing SA
  When: send_update() updates lifetime byte count
  Then: ip xfrm state reflects updated lifetime
    (soft byte count advanced)
```

```
Test: B9_sa_add_with_mark
  Given: SA with policy mark (value=0x1234)
  When: send_add() installs SA with mark
  Then: ip xfrm state shows mark=0x1234
```

### 4.4 Test Cases: SPI Allocation

```
Test: B10_spi_alloc_basic
  Given: Clean kernel state
  When: send_getspi() allocates SPI for (src=10.0.0.1, dst=10.0.0.2, ESP)
  Then:
    - Returned SPI is non-zero
    - SPI is in valid range (kernel-assigned)
    - No SA is installed yet (only SPI reservation)
```

```
Test: B11_spi_alloc_with_range
  Given: SPI range [0x1000, 0x1FFF]
  When: send_getspi() allocates SPI
  Then: Returned SPI is within [0x1000, 0x1FFF]
```

```
Test: B12_spi_alloc_ipv6
  Same as B10 with IPv6 addresses
```

```
Test: B13_spi_alloc_then_add
  Given: SPI allocated via send_getspi()
  When: send_add() installs SA with that SPI
  Then: SA exists with the allocated SPI
    This validates the critical SPI -> SA install path
```

### 4.5 Test Cases: Policy Lifecycle

```
Test: B14_policy_add_delete_basic
  Given: Clean kernel state
  When: spd_add() installs policy
    (src=10.0.0.0/24, dst=192.168.1.0/24, dir=IN, tmpl=ESP tunnel)
  Then:
    - ip xfrm policy shows 1 new policy
    - Policy has correct selector, direction, template
    - Kernel-assigned policy index > 0
    - Policy index is stored in secpolicy for later deletion
  Cleanup: spd_delete() using stored index, verify removed
```

```
Test: B15_policy_add_multiple
  Given: Clean state
  When: spd_add() installs 3 policies (different selectors)
  Then: ip xfrm policy shows exactly 3 new policies
    (excluding kernel default policies)
```

```
Test: B16_policy_update
  Given: Existing policy with kernel index
  When: spd_update() updates policy priority
  Then: ip xfrm policy reflects updated priority
    Kernel index remains the same
```

```
Test: B17_policy_flush
  Given: 3 installed policies
  When: spd_flush() is called
  Then: All policies are removed
    (ip xfrm policy shows only kernel defaults, if any)
```

```
Test: B18_policy_with_multiple_tmpl
  Given: Policy with 2 IPsec templates (ESP + AH fallback)
  When: spd_add() installs policy
  Then: ip xfrm policy shows both templates in the policy entry
```

### 4.6 Test Cases: SA Flush

```
Test: B19_sa_flush
  Given: 3 installed SAs
  When: spi_flush() is called
  Then: All SAs are removed (ip xfrm state is empty)
```

### 4.7 Test Summary: Integration Tests

| Test ID | Category | Count |
|---------|----------|-------|
| B1-B9 | SA lifecycle | 9 |
| B10-B13 | SPI allocation | 4 |
| B14-B18 | Policy lifecycle | 5 |
| B19 | SA flush | 1 |
| **Total** | | **19** |

---

## 5. Category C: Failure Path Tests

These tests verify that kernelpaws handles kernel errors gracefully,
propagating failures to the caller with correct errno values.

### 5.1 Error Injection Strategies

Two approaches, used in combination:

1. **Real kernel errors**: Trigger genuine kernel rejections by
   constructing invalid requests (e.g., invalid algorithm, duplicate SPI
   in certain contexts, unsupported parameters).

2. **Impairment-in-test**: For the full daemon end-to-end tests (Category D),
   implement a minimal impairment framework modeled after LibreSwan's
   `--impair` system. The unit/integration layer does NOT need this — real
   kernel errors suffice.

### 5.2 Test Cases: Kernel Rejection

```
Test: C1_newsa_invalid_algorithm
  Given: Clean state
  When: send_add() with unsupported encryption algorithm (e.g., "DES")
  Then:
    - Returns -1 (failure)
    - errno == EOPNOTSUPP or EINVAL
    - No SA is installed in kernel
    - /proc/net/xfrm_stat may show XfrmAcquireError incremented
```

```
Test: C2_newsa_zero_spi
  Given: Clean state
  When: send_add() with spi=0 (kernel should reject or auto-assign)
  Then: Behavior is defined (document actual kernel behavior):
    - Kernel auto-assigns SPI (most common), OR
    - Returns -EINVAL
    Either way, the operation completes without hanging
```

```
Test: C3_delsa_nonexistent
  Given: Clean state (no SAs)
  When: send_delete() for spi=0xDEADBEEF
  Then:
    - Returns 0 (kernel treats DELSA for non-existent SA as success)
    - OR returns -ESRCH (acceptable alternative)
    - Operation does NOT hang or crash
```

```
Test: C4_delpolicy_nonexistent
  Given: Clean state (no policies)
  When: spd_delete() for non-existent index
  Then: Returns 0 or -ESRCH (non-hanging behavior)
```

```
Test: C5_newsa_duplicate_spi_conflict
  Given: SA with SPI=X installed
  When: send_add() attempts to install SA with same SPI=X, different params
  Then:
    - Returns -1 with errno == EEXIST or -EINVAL
    - Original SA remains unchanged
```

```
Test: C6_newsa_corrupted_key_length
  Given: SA with encryption key of invalid length (e.g., AES key = 10 bytes)
  When: send_add() attempts install
  Then: Returns -1 with errno == EINVAL
    Kernel validates key length for each algorithm
```

```
Test: C7_newpolicy_invalid_family
  Given: Clean state
  When: spd_add() with AF_UNIX (unsupported address family)
  Then: Returns -1 with errno == EAFNOSUPPORT or -EINVAL
```

```
Test: C8_allocspi_conflict
  Given: Kernel with many SAs installed (near SPI range limit)
  When: send_getspi() requests SPI
  Then:
    - Returns -1 with errno == EAGAIN or ENOBUFS, OR
    - Successfully allocates (kernel can still find free SPI)
    Either way, no hang or crash
```

### 5.3 Test Cases: Correlation Failure

```
Test: C9_response_timeout
  Given: Mock socket that never sends a response
  When: kernelpaws_xfrm_recv_response() with 5-second timeout
  Then: Returns -1 with errno == ETIMEDOUT
    (validates timeout behavior, prevents infinite blocking)
```

```
Test: C10_correlation_seq_mismatch
  Given: Mock socket that sends response with wrong nlmsg_seq
  When: recv_response() waits for seq=5, receives seq=3
  Then: Skips the mismatched message, continues waiting
    (does NOT accept wrong response)
```

### 5.4 Test Cases: Socket Failure

```
Test: C11_init_netlink_create_fail
  Given: Non-root user (no CAP_NET_ADMIN)
  When: kernelpaws_backend->init() is called
  Then: Returns -1, errno == EPERM
    Graceful failure, no crash
```

```
Test: C12_send_to_closed_socket
  Given: XFRM socket created then closed
  When: send_add() attempts to send
  Then: Returns -1, errno == EBADF or ENOTSOCK
```

### 5.5 Test Summary: Failure Path Tests

| Test ID | Category | Count |
|---------|----------|-------|
| C1-C8 | Kernel rejection | 8 |
| C9-C10 | Correlation failure | 2 |
| C11-C12 | Socket failure | 2 |
| **Total** | | **12** |

---

## 6. Category D: Notification Tests

These tests verify that kernelpaws correctly processes XFRM multicast
notifications (ACQUIRE, EXPIRE, POLEXPIRE, MIGRATE) and routes them
to the correct Racoon state machine handlers.

### 6.1 Test Approach

Notifications are **multicast** events from the kernel. Testing them
requires:
1. Installing SA/Policy with short lifetimes to trigger EXPIRE.
2. Triggering ACQUIRE by generating traffic that matches a policy with
   no SA.
3. Verifying that the correct callback handler is invoked.

For unit-level notification tests, use pre-constructed netlink buffers
fed through the notification parser. For integration-level tests, use
real kernel events.

### 6.2 Test Cases: Notification Parsing (Unit-Level)

```
Test: D1_parse_acquire_from_buffer
  Given: Pre-constructed XFRM_MSG_ACQUIRE buffer
    (src=10.0.0.0/24, dst=192.168.1.0/24, proto=ESP)
  When: xfrm_recvacquire() processes the notification
  Then: Extracted selector matches expected values
    Policy index is extracted
    64-bit fields are read via memcpy
```

```
Test: D2_parse_expire_hard_from_buffer
  Given: Pre-constructed XFRM_MSG_EXPIRE with XFRM_EXPIRE_HARD
  When: xfrm_recvexpire() processes the notification
  Then: (spi, src, dst, proto) extracted correctly
    hard_len_expires flag detected
```

```
Test: D3_parse_expire_soft_from_buffer
  Given: Pre-constructed XFRM_MSG_EXPIRE with XFRM_EXPIRE_SOFT
  When: xfrm_recvexpire() processes the notification
  Then: soft_len_expires flag detected
```

```
Test: D4_parse_polexpire_from_buffer
  Given: Pre-constructed XFRM_MSG_POLEXpire with policy index
  When: xfrm_recvpolexpire() processes the notification
  Then: Policy index extracted, direction matches
```

```
Test: D5_parse_migrate_from_buffer
  Given: Pre-constructed XFRM_MSG_MIGRATE with new peer address
  When: xfrm_recvmigrate() processes the notification
  Then: New peer address (colAddr) extracted correctly
    Old peer address (sel.daddr) extracted correctly
    Protocol family (AF_INET/AF_INET6) correct
```

```
Test: D6_parse_delsa_multicast
  Given: Pre-constructed XFRM_MSG_DELSA multicast event
  When: Notification handler processes the message
  Then: (spi, src, dst, proto) tuple extracted
```

### 6.3 Test Cases: Notification Integration (Real Kernel)

```
Test: D7_acquire_on_traffic
  Given: Policy installed with no matching SA
    (spd_add with ESP template, but no SA)
  When: Traffic matching the policy is sent (ping through tunnel)
  Then:
    - Kernel sends XFRM_MSG_ACQUIRE on NL_XFRM_FD
    - Notification handler processes the ACQUIRE
    - isakmp_request_acquire() is called with correct selector
    Verification: Check racoon log for ACQUIRE event
```

```
Test: D8_expire_on_lifetime
  Given: SA installed with very short lifetime (10 seconds)
  When: Test waits for lifetime to expire
  Then:
    - Kernel sends XFRM_MSG_EXPIRE after ~10s
    - Notification handler processes the EXPIRE
    - ph2handle expire logic is triggered
    Verification: Check racoon log for EXPIRE event,
      then verify SA is removed (ip xfrm state)
```

```
Test: D9_eacquire_resolves_acquire
  Given: Active ACQUIRE event from kernel
  When: send_eacquire() installs skip policy
  Then:
    - Kernel stops sending ACQUIRE for that policy
    - Skip policy is installed (action=XFRM_POLICY_SKIP)
    - Policy index is tracked for later deletion
```

```
Test: D10_acquire_multiple_policies
  Given: 3 policies installed, no SAs
  When: Traffic triggers ACQUIRE on all 3 policies
  Then:
    - 3 ACQUIRE notifications received
    - Each notification carries correct selector and policy index
    - All 3 are processed without loss or conflation
```

### 6.4 Test Summary: Notification Tests

| Test ID | Category | Count |
|---------|----------|-------|
| D1-D6 | Parsing (unit) | 6 |
| D7-D10 | Integration | 4 |
| **Total** | | **10** |

---

## 7. Grand Summary: All Tests

| Category | Unit | Integration | Failure | Notification | Total |
|----------|------|-------------|---------|--------------|-------|
| Count | 36 | 19 | 12 | 10 | **77** |

| Phase | Required Tests Before Phase Is Complete |
|-------|------------------------------------------|
| Phase 1 (PF_KEYv2 wrapper) | A9-A11 (parsing/correlation on PF_KEY messages) |
| Phase 2.X (XFRM init/shutdown) | C11, C12 (socket failure) |
| Phase 2.Y (SPI allocation) | A1, B10-B13 |
| Phase 2.Z (SA add/delete) | A2-A4, B1-B9, C1-C7 |
| Phase 2.W (Policy add/delete) | A5-A7, B14-B18 |
| Phase 2.V (Notifications) | D1-D10 |
| Phase 3 (Cleanup) | All 77 tests pass on both backends |

---

## 8. Integration Testing Annex

### 8.1 Objective

Verify that the Racoon IKEv1 daemon with the XFRM kernelpaws backend
can successfully establish, maintain, and tear down IPsec tunnels in
realistic network topologies.

### 8.2 Gap Analysis: Racoon vs LibreSwan Testing

| Aspect | LibreSwan | Racoon (Current) | Racoon (Target) |
|--------|-----------|------------------|-----------------|
| **Test infrastructure** | `testing/pluto/` with 1000+ VPP tests | **None** | New VPP-style test suite |
| **Execution environment** | KVM/QEMU guests (libvirt) | **None** | Incus/LXC containers |
| **Test format** | Directory-per-test, declarative scripts | **None** | Adapted VPP format |
| **Sanitizers** | 34 sed/awk scripts for output normalization | **None** | New sanitizer set |
| **Kernel verification** | `ipsec _kernel state/policy`, `xfrmcheck.sh` | **None** | `ip xfrm state/policy`, adapted xfrmcheck |
| **Impairment testing** | `ipsec whack --impair` with ~80 impairments | **None** | Minimal impairment set for migration |
| **Topology** | west/east/north/road/nic VMs | **None** | gateway/roadwarrior containers |

### 8.3 Container Infrastructure (Incus/LXC)

#### Why Incus/LXC instead of KVM?
- **Faster**: Container startup is seconds vs. minutes for KVM guests.
- **Lighter**: No full OS boot, no virtio drivers, less resource overhead.
- **Sufficient**: XFRM operations work identically in containers with
  proper capability delegation (`CAP_NET_ADMIN`).
- **CI-friendly**: Easier to run in CI/CD pipelines with nested containers
  or LXD-in-LXD.

#### Topology

```
  +-----------+     10.0.0.0/24     +-----------+
  |  gateway  | ------------------ |  roadwarrior |
  |           |  10.0.0.1     10.0.0.2 |              |
  | racoon    |  VPN: 192.168.1.0/24  | racoon        |
  | (XFRM)    |  VPN: 192.168.2.0/24  | (XFRM or PF) |
  +-----------+                       +-----------+
```

#### Incus Profile

```yaml
# profiles/racoon-test.yaml
config:
  security.nesting: "true"
  security.privileged: "true"
description: Racoon IPsec test container

devices:
  eth0:
    name: eth0
    network: racoon-test-net
    type: nic
  eth1:
    name: eth1
    network: vpn-net
    type: nic

profiles:
  - default
  - racoon-test
```

#### Network Configuration

```bash
# Create Incus networks
incus network create racoon-test-net ipv4.address=10.0.0.0/24
incus network create vpn-net ipv4.address=192.168.0.0/16

# Launch containers
incus launch racoon-image gateway --profile racoon-test
incus launch racoon-image roadwarrior --profile racoon-test

# Assign static IPs
incus config device set gateway eth0 ipv4.address 10.0.0.1
incus config device set roadwarrior eth0 ipv4.address 10.0.0.2
```

#### Container Image

The racoon test image should contain:
- Racoon daemon (built with `--enable-xfrm`)
- `iproute2` (for `ip xfrm state/policy`)
- `ipsec-tools` setkey (for `setkey -D/-DP` verification)
- `ping`, `traceroute` (traffic generation)
- Valgrind (for memory error detection)
- Pre-configured racoon.conf and secret key

### 8.4 Test Tooling Requirements

| Tool | Purpose | Installation |
|------|---------|--------------|
| **valgrind** | Memory error detection (leaks, invalid reads, alignment issues) | `apt install valgrind` in container image |
| **iproute2** | `ip xfrm state/policy list` for kernel state verification | Pre-installed on most distros |
| **setkey** | Alternative verification (`setkey -D`, `setkey -DP`) | From `ipsec-tools` package |
| **sshd** | Remote test script execution | `apt install openssh-server` in container |
| **ping** | Traffic generation and connectivity verification | Standard utility |
| **tcpdump** | Packet capture for debugging failures | `apt install tcpdump` |
| **incus** | Container lifecycle management | Host system |
| **sanitizers** | Output normalization (adapted from LibreSwan) | Custom sed scripts |

### 8.5 Test Execution Framework

#### Test Directory Structure

```
testing/racoon/
  README                         - Test suite documentation
  TESTLIST                       - Test registry (name, kind, status)
  testparams.sh                  - Default test parameters, sanitizer config
  run-tests.sh                   - Top-level test runner
  guestbin/
    xfrmcheck.sh                 - Check /proc/net/xfrm_stat for errors
    ping-once.sh                 - Ping with expectation (--up/--down)
    wait-for-racoon.sh           - Wait for racoon to reach specific state
    racoon-prep.sh               - Container preparation (keys, certs, config)
  sanitizers/
    ipsec-kernel-state.sed       - Normalize ip xfrm state output
    spi-sanitize.sed             - Replace SPIs with placeholder
    timestamp-sanitize.sed       - Normalize timestamps
  cases/
    ikev1-hostpair-01/           - Basic host-to-host IKEv1
      description.txt
      gateway.conf               - Racoon config for gateway
      roadwarrior.conf           - Racoon config for roadwarrior
      gatewayinit.sh             - Gateway init script
      roadwarriorinit.sh         - Roadwarrior init script
      01-init.sh                 - Ordered: start racoon both sides
      02-up.sh                   - Initiate connection
      03-ping.sh                 - Verify connectivity
      04-down.sh                 - Tear down connection
      final.sh                   - Verify kernel state, check logs
    ikev1-rw-subnet-01/          - Roadwarrior with subnet
    ikev1-expire-01/             - SA lifetime expiration
    ikev1-policy-drop-01/        - Policy drop action
    ikev1-rekey-01/              - SA rekeying
    ikev1-ipv6-01/               - IPv6 support
    ikev1-dual-af-01/            - Dual-stack (IPv4 + IPv6)
```

#### Test Runner (`run-tests.sh`)

```bash
#!/bin/bash
# Usage: run-tests.sh [--backend xfrm|pfkey] [--test <name>] [--valgrind]

BACKEND="${1:-xfrm}"
VALGRIND="${VALGRIND:-0}"
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"

# For each test in TESTLIST:
while IFS= read -r test_name; do
    test_case="cases/${test_name}"
    [ -d "$test_case" ] || continue

    echo "=== Running ${test_name} (backend=${BACKEND}) ==="

    # Launch containers
    incus launch racoon-image "${test_name}-gateway"
    incus launch racoon-image "${test_name}-roadwarrior"

    # Deploy configs
    for f in "${test_case}"/*.conf; do
        incus file push "$f" "${test_name}-gateway/etc/racoon/$(basename "$f")"
    done

    # Run ordered scripts
    for script in "${test_case}"/[0-9]*.sh; do
        echo "  Running $(basename "$script")..."
        run_in_container "${test_name}-gateway" "$script"
        run_in_container "${test_name}-roadwarrior" "$script"
    done

    # Final verification
    run_in_container "${test_name}-gateway" "${test_case}/final.sh"

    # Clean up
    incus delete --force "${test_name}-gateway" "${test_name}-roadwarrior"

    echo "=== ${test_name}: PASSED ==="
done < <(grep "^${BACKEND}" TESTLIST)
```

#### Sanitizer Pipeline

```bash
# testparams.sh
REF_CONSOLE_FIXUPS="
  -f ${TEST_DIR}/sanitizers/spi-sanitize.sed
  -f ${TEST_DIR}/sanitizers/timestamp-sanitize.sed
  -f ${TEST_DIR}/sanitizers/ipsec-kernel-state.sed
"
```

```sed
# sanitizers/spi-sanitize.sed
# Replace hex SPIs (e.g., reqid 0x12345678) with placeholder
s/0x[0-9a-fA-F]\{4,\}/SPISPI/g
```

```sed
# sanitizers/timestamp-sanitize.sed
# Replace timestamps like "2025-01-15 10:30:45"
s/[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9:]\{8\}/TIMESTAMP/g
```

#### Expected Output Model

Each test has a `.console.txt` per host with expected sanitized output:

```
# gateway.console.txt (expected output for gateway container)
Starting racoon daemon...
racoon: Ike_SAS:  created new SAS with remote address 10.0.0.2
racoon: ISAKMP SA established
racoon: IPsec SA established
ip xfrm state
src 10.0.0.1 dst 10.0.0.2
    proto esp spi SPISPI reqid SPISPI replay-window 32
    auth sha1 0xHASHKEY
    enc aes 0xENCKEY
    mode tunnel
    ...
# final checks:
ipsec trafficstatus
#1: tunnel ESTABLISHED
```

After each test run, actual output is sanitized and diffed against
the expected `.console.txt`. A diff indicates regression.

### 8.6 End-to-End Test Cases

Each test case corresponds to a LibreSwan VPP test that has been adapted
for Racoon.

#### E1: Basic Host-to-Host IKEv1 (`ikev1-hostpair-01`)

```
Description: Basic IKEv1 Main Mode + Quick Mode host-to-host tunnel
Topology: gateway (10.0.0.1) <--> roadwarrior (10.0.0.2)
Config: PSK authentication, ESP tunnel mode, AES-128-CBC + HMAC-SHA1
Steps:
  01: Start racoon on both sides
  02: Roadwarrior initiates connection
  03: Ping from roadwarrior to gateway through tunnel
  04: Verify kernel state: 2 SAs (inbound + outbound), 2 policies
  05: Tear down connection
  Final: ip xfrm state/policy clean, no kernel errors
Expected:
  - IKEv1 SA established (Main Mode)
  - IPsec SA established (Quick Mode)
  - Ping succeeds through tunnel
  - ip xfrm shows ESP SAs with correct parameters
```

#### E2: Roadwarrior with Subnet (`ikev1-rw-subnet-01`)

```
Description: Roadwarrior connecting with a local subnet
Topology: gateway (10.0.0.1/192.168.1.0/24) <--> rw (10.0.0.2/192.168.2.0/24)
Config: Subnet-to-subnet policy
Steps:
  01: Start racoon on both sides
  02: Roadwarrior initiates with subnet
  03: Ping from 192.168.2.100 to 192.168.1.100 through tunnel
  04: Verify kernel state: SAs with tunnel addresses matching subnet
Expected:
  - Policies reference correct subnet selectors
  - ip xfrm policy shows correct src/dst selectors
  - Multiple pings to different subnet hosts succeed
```

#### E3: SA Expiration (`ikev1-expire-01`)

```
Description: Verify SA expiration and rekeying
Config: Short lifetime (30s IPsec SA)
Steps:
  01: Start racoon, establish SA
  02: Wait for SA to expire (monitor racoon logs for EXPIRE)
  03: Verify kernel sends XFRM_MSG_EXPIRE
  04: Verify racoon processes EXPIRE and triggers rekey
  05: Verify new SA is installed after rekey
Expected:
  - EXPIRE notification received on NL_XFRM_FD
  - Rekey initiated automatically
  - New SA with fresh SPI installed in kernel
  - Traffic continues without interruption
```

#### E4: Policy Drop (`ikev1-policy-drop-01`)

```
Description: Policy with drop action (no IPsec SA)
Config: One policy set to DROP
Steps:
  01: Establish normal IPsec tunnel
  02: Add additional policy with DROP action for specific traffic
  03: Send traffic matching DROP policy
  04: Verify traffic is dropped (no ping response)
Expected:
  - DROP policy installed in kernel (XFRM_POLICY_BLOCK)
  - Matching traffic is silently dropped
  - Other traffic on IPsec SA continues normally
```

#### E5: Rekey (`ikev1-rekey-01`)

```
Description: Verify SA rekeying (soft lifetime triggers rekey)
Config: Soft lifetime = 20s, hard lifetime = 30s
Steps:
  01: Establish SA
  02: Wait for soft lifetime (20s)
  03: Racoon initiates rekey (new Quick Mode)
  04: New SA installed alongside old SA
  05: Old SA expires (30s), removed from kernel
Expected:
  - Two SAs visible during rekey window
  - Old SA removed after hard lifetime
  - Traffic flows without interruption
```

#### E6: IPv6 (`ikev1-ipv6-01`)

```
Description: IKEv1 over IPv6
Topology: gateway (fd00::1) <--> roadwarrior (fd00::2)
Config: IPv6 addresses, ESP tunnel mode
Steps:
  01: Start racoon on both sides (IPv6)
  02: Establish IKEv1 + IPsec SA
  03: Ping6 through tunnel
  04: Verify ip -6 xfrm state/policy
Expected:
  - IPv6 XFRM SAs and policies installed
  - xfrm_selector has correct AF_INET6 addresses
  - Ping6 succeeds
```

#### E7: Impairment - SA Install Failure (`ikev1-impair-sa-fail-01`)

```
Description: Verify graceful handling of SA install failure
Config: Normal config + impairment injection
Impairment: Fail outbound SA install (mimics kernel rejection)
Steps:
  01: Start racoon, enable impairment on gateway
  02: Roadwarrior initiates connection
  03: Gateway receives Quick Mode, attempts SA install
  04: Impairment causes send_add() to fail
  05: Gateway sends error notification to roadwarrior
  06: Verify connection is NOT established
  07: Disable impairment
  08: Re-attempt, verify connection succeeds
Expected:
  - Failure logged, connection not established
  - No crash or hang
  - Recovery works after impairment cleared
  - ip xfrm shows no stale SAs
```

#### E8: Valgrind Clean (`ikev1-valgrind-01`)

```
Description: Run racoon under valgrind, verify no memory errors
Steps:
  01: Start racoon under valgrind --leak-check=full
  02: Establish and tear down IPsec tunnel 3 times
  03: Collect valgrind output
Expected:
  - Zero definitely lost bytes
  - Zero invalid reads/writes
  - Zero use-after-free
  - Suppressions file for known safe patterns
```

### 8.7 Test Summary: End-to-End Tests

| Test ID | Description | Priority |
|---------|-------------|----------|
| E1 | Basic host-to-host | **Critical** |
| E2 | Roadwarrior with subnet | **Critical** |
| E3 | SA expiration | High |
| E4 | Policy drop | Medium |
| E5 | SA rekeying | High |
| E6 | IPv6 support | High |
| E7 | Impairment recovery | Medium |
| E8 | Valgrind clean | **Critical** |

### 8.8 Continuous Integration

The end-to-end test suite should integrate with CI:

```yaml
# .github/workflows/test-xfrm.yml
name: Test XFRM Backend
on: [push, pull_request]

jobs:
  integration:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Build racoon with XFRM
        run: ./autogen.sh && ./configure --enable-xfrm --enable-tests && make
      - name: Run unit tests
        run: make check
        env:
          VALGRIND: 0
      - name: Run integration tests (requires root)
        run: sudo make check-integration
      - name: Run end-to-end tests
        run: |
          sudo apt install incus
          sudo incus admin init --auto
          sudo testing/racoon/run-tests.sh --backend xfrm
```

### 8.9 Valgrind Integration

Valgrind is used at two levels:

1. **Unit/Integration tests**: Run individual test binaries under valgrind:
   ```bash
   valgrind --leak-check=full --error-exitcode=1 \
     --suppressions=tests/valgrind.sup \
     ./test_sa_lifecycle
   ```

2. **End-to-end tests**: Run the full racoon daemon under valgrind in
   the container (Test E8 above).

Suppressions file (`tests/valgrind.sup`) for known safe patterns:
```
{
   racoon_socket_leak
   Memcheck:Leak
   match-leak-kinds: reachable
   ...
   fun:socket
   fun:monitor_fd
}
```

### 8.10 xfrmcheck Equivalent

Adapted from LibreSwan's `testing/guestbin/xfrmcheck.sh`:

```bash
#!/bin/bash
# guestbin/xfrmcheck.sh
# Check /proc/net/xfrm_stat for non-zero error counters

check_xfrm_stat() {
    local errors=0
    if [ -f /proc/net/xfrm_stat ]; then
        while IFS=' ' read -r count name; do
            case "$name" in
                *Error*|*Drop*|*Mismatch*|*Buffer*)
                    if [ "$count" -gt 0 ] 2>/dev/null; then
                        echo "XFRM error: $name = $count"
                        errors=$((errors + 1))
                    fi
                    ;;
            esac
        done < /proc/net/xfrm_stat
    fi
    return $errors
}

check_xfrm_stat
```

---

## 9. Implementation Checklist

Track progress against test coverage:

```
Phase 0 (Merge libipsec):
  [ ] Build system compiles with --enable-tests
  [ ] Assertion framework and test runner working

Phase 1 (PF_KEYv2 wrapper):
  [ ] A9-A11: Parsing/correlation tests pass for PF_KEY path
  [ ] E1: Basic host-to-host works with PF_KEY backend

Phase 2.X (XFRM init/shutdown):
  [ ] A13: Alignment tests pass
  [ ] C11, C12: Socket failure tests pass

Phase 2.Y (SPI allocation):
  [ ] A1: SPI allocation construction tests pass
  [ ] B10-B13: SPI allocation integration tests pass

Phase 2.Z (SA add/delete):
  [ ] A2-A4: SA construction tests pass
  [ ] B1-B9: SA lifecycle integration tests pass
  [ ] C1-C8: SA error path tests pass

Phase 2.W (Policy):
  [ ] A5-A7: Policy construction tests pass
  [ ] B14-B18: Policy lifecycle tests pass

Phase 2.V (Notifications):
  [ ] D1-D6: Notification parsing tests pass
  [ ] D7-D10: Notification integration tests pass
  [ ] E3: SA expiration test passes
  [ ] E5: Rekey test passes

Phase 3 (Cleanup):
  [ ] All 77 unit/integration tests pass on XFRM backend
  [ ] E1-E6: All end-to-end tests pass
  [ ] E8: Valgrind clean
  [ ] PF_KEY backend deprecated
```

---

## 10. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Container networking not identical to bare metal | Tests pass in containers but fail on real hardware | Supplement with bare-metal smoke tests before release |
| XFRM behavior varies by kernel version | Tests pass on 6.x but fail on 5.x | Pin minimum kernel version (5.10+) for tests; maintain kernel-version-specific test markers |
| Incus availability in CI | CI cannot run end-to-end tests | Fall back to `ip netns` (Linux network namespaces) as minimum viable CI environment |
| Valgrind suppressions incomplete | False positives mask real issues | Build suppressions incrementally; review each suppression with code audit |
| Race conditions in notification tests | Intermittent test failures on EXPIRE timing | Use `wait-for-racoon.sh` with pattern matching; configurable timeouts; retry logic |