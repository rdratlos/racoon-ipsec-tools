// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for sockmisc (socket utility functions)
 *
 * File: test/test_sockmisc.c
 * Coverage: cmpsaddr(), extract_port(), set_port(), get_port_ptr(),
 *           newsaddr(), dupsaddr(), saddr2str(), saddrwop2str()
 *
 * NOTE: Only tests pure functions that don't require network I/O.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sockmisc.h"
#include "gcmalloc.h"

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* Helper: build IPv4 sockaddr */
static void make_inet4(struct sockaddr_in *sin, const char *ip, uint16_t port)
{
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    inet_pton(AF_INET, ip, &sin->sin_addr);
}

/* Helper: build IPv6 sockaddr */
static void make_inet6(struct sockaddr_in6 *sin6, const char *ip, uint16_t port)
{
    memset(sin6, 0, sizeof(*sin6));
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    inet_pton(AF_INET6, ip, &sin6->sin6_addr);
}

/* --- cmpsaddr tests --- */

int test_cmpsaddr_both_null()
{
    TEST_START("cmpsaddr both NULL");

    if (cmpsaddr(NULL, NULL) != CMPSADDR_MATCH)
        TEST_FAIL("expected CMPSADDR_MATCH");

    TEST_PASS();
    return 0;
}

int test_cmpsaddr_one_null()
{
    struct sockaddr_in sin1, sin2;

    TEST_START("cmpsaddr one NULL");

    make_inet4(&sin1, "10.0.0.1", 500);

    if (cmpsaddr((const struct sockaddr *)&sin1, NULL) != CMPSADDR_MISMATCH)
        TEST_FAIL("expected CMPSADDR_MISMATCH");
    if (cmpsaddr(NULL, (const struct sockaddr *)&sin2) != CMPSADDR_MISMATCH)
        TEST_FAIL("expected CMPSADDR_MISMATCH");

    TEST_PASS();
    return 0;
}

int test_cmpsaddr_ipv4_exact_match()
{
    struct sockaddr_in sin1, sin2;

    TEST_START("cmpsaddr IPv4 exact match");

    make_inet4(&sin1, "10.0.0.1", 500);
    make_inet4(&sin2, "10.0.0.1", 500);

    if (cmpsaddr((const struct sockaddr *)&sin1, (const struct sockaddr *)&sin2)
        != CMPSADDR_MATCH)
        TEST_FAIL("expected CMPSADDR_MATCH");

    TEST_PASS();
    return 0;
}

int test_cmpsaddr_ipv4_port_mismatch()
{
    struct sockaddr_in sin1, sin2;

    TEST_START("cmpsaddr IPv4 port mismatch");

    make_inet4(&sin1, "10.0.0.1", 500);
    make_inet4(&sin2, "10.0.0.1", 4500);

    if (cmpsaddr((const struct sockaddr *)&sin1, (const struct sockaddr *)&sin2)
        != CMPSADDR_WOP_MATCH)
        TEST_FAIL("expected CMPSADDR_WOP_MATCH");

    TEST_PASS();
    return 0;
}

int test_cmpsaddr_ipv4_addr_mismatch()
{
    struct sockaddr_in sin1, sin2;

    TEST_START("cmpsaddr IPv4 address mismatch");

    make_inet4(&sin1, "10.0.0.1", 500);
    make_inet4(&sin2, "10.0.0.2", 500);

    if (cmpsaddr((const struct sockaddr *)&sin1, (const struct sockaddr *)&sin2)
        != CMPSADDR_MISMATCH)
        TEST_FAIL("expected CMPSADDR_MISMATCH");

    TEST_PASS();
    return 0;
}

int test_cmpsaddr_ipv4_wildcard_port_any()
{
    struct sockaddr_in sin1, sin2;

    TEST_START("cmpsaddr IPv4 wildcard port (addr1)");

    make_inet4(&sin1, "10.0.0.1", 0);
    make_inet4(&sin2, "10.0.0.1", 500);

    if (cmpsaddr((const struct sockaddr *)&sin1, (const struct sockaddr *)&sin2)
        != CMPSADDR_WILDPORT_MATCH)
        TEST_FAIL("expected CMPSADDR_WILDPORT_MATCH");

    TEST_PASS();
    return 0;
}

int test_cmpsaddr_ipv4_wildcard_port_both()
{
    struct sockaddr_in sin1, sin2;

    TEST_START("cmpsaddr IPv4 wildcard port both");

    make_inet4(&sin1, "10.0.0.1", 0);
    make_inet4(&sin2, "10.0.0.1", 0);

    if (cmpsaddr((const struct sockaddr *)&sin1, (const struct sockaddr *)&sin2)
        != CMPSADDR_MATCH)
        TEST_FAIL("expected CMPSADDR_MATCH");

    TEST_PASS();
    return 0;
}

int test_cmpsaddr_ipv6_exact_match()
{
    struct sockaddr_in6 sin6a, sin6b;

    TEST_START("cmpsaddr IPv6 exact match");

    make_inet6(&sin6a, "::1", 500);
    make_inet6(&sin6b, "::1", 500);

    if (cmpsaddr((const struct sockaddr *)&sin6a, (const struct sockaddr *)&sin6b)
        != CMPSADDR_MATCH)
        TEST_FAIL("expected CMPSADDR_MATCH");

    TEST_PASS();
    return 0;
}

int test_cmpsaddr_ipv6_addr_mismatch()
{
    struct sockaddr_in6 sin6a, sin6b;

    TEST_START("cmpsaddr IPv6 address mismatch");

    make_inet6(&sin6a, "::1", 500);
    make_inet6(&sin6b, "::2", 500);

    if (cmpsaddr((const struct sockaddr *)&sin6a, (const struct sockaddr *)&sin6b)
        != CMPSADDR_MISMATCH)
        TEST_FAIL("expected CMPSADDR_MISMATCH");

    TEST_PASS();
    return 0;
}

int test_cmpsaddr_family_mismatch()
{
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;

    TEST_START("cmpsaddr family mismatch");

    make_inet4(&sin, "127.0.0.1", 500);
    make_inet6(&sin6, "::1", 500);

    if (cmpsaddr((const struct sockaddr *)&sin, (const struct sockaddr *)&sin6)
        != CMPSADDR_MISMATCH)
        TEST_FAIL("expected CMPSADDR_MISMATCH");

    TEST_PASS();
    return 0;
}

int test_cmpsaddr_unspec()
{
    struct sockaddr sa1 = { 0 };
    struct sockaddr sa2 = { 0 };

    TEST_START("cmpsaddr AF_UNSPEC");

    sa1.sa_family = AF_UNSPEC;
    sa2.sa_family = AF_UNSPEC;

    if (cmpsaddr(&sa1, &sa2) != CMPSADDR_MATCH)
        TEST_FAIL("expected CMPSADDR_MATCH for AF_UNSPEC");

    TEST_PASS();
    return 0;
}

/* --- extract_port tests --- */

int test_extract_port_ipv4()
{
    struct sockaddr_in sin;

    TEST_START("extract_port IPv4");

    make_inet4(&sin, "10.0.0.1", 500);

    if (extract_port((const struct sockaddr *)&sin) != 500)
        TEST_FAIL("expected port 500");

    TEST_PASS();
    return 0;
}

int test_extract_port_ipv6()
{
    struct sockaddr_in6 sin6;

    TEST_START("extract_port IPv6");

    make_inet6(&sin6, "::1", 4500);

    if (extract_port((const struct sockaddr *)&sin6) != 4500)
        TEST_FAIL("expected port 4500");

    TEST_PASS();
    return 0;
}

int test_extract_port_null()
{
    TEST_START("extract_port NULL");

    if (extract_port(NULL) != 0)
        TEST_FAIL("expected 0 for NULL");

    TEST_PASS();
    return 0;
}

int test_extract_port_unspec()
{
    struct sockaddr sa = { 0 };

    TEST_START("extract_port AF_UNSPEC");

    sa.sa_family = AF_UNSPEC;

    if (extract_port(&sa) != 0)
        TEST_FAIL("expected 0 for AF_UNSPEC");

    TEST_PASS();
    return 0;
}

/* --- set_port / get_port_ptr tests --- */

int test_set_port_ipv4()
{
    struct sockaddr_in sin;

    TEST_START("set_port IPv4");

    make_inet4(&sin, "10.0.0.1", 500);

    u_int16_t *pp = set_port((struct sockaddr *)&sin, 1234);
    if (!pp) TEST_FAIL("set_port returned NULL");
    if (*pp != htons(1234))
        TEST_FAIL("port not set correctly");
    if (extract_port((const struct sockaddr *)&sin) != 1234)
        TEST_FAIL("extract_port after set_port mismatch");

    TEST_PASS();
    return 0;
}

int test_set_port_ipv6()
{
    struct sockaddr_in6 sin6;

    TEST_START("set_port IPv6");

    make_inet6(&sin6, "::1", 0);

    u_int16_t *pp = set_port((struct sockaddr *)&sin6, 9999);
    if (!pp) TEST_FAIL("set_port returned NULL");
    if (extract_port((const struct sockaddr *)&sin6) != 9999)
        TEST_FAIL("extract_port after set_port mismatch");

    TEST_PASS();
    return 0;
}

int test_get_port_ptr_ipv4()
{
    struct sockaddr_in sin;

    TEST_START("get_port_ptr IPv4");

    make_inet4(&sin, "10.0.0.1", 0);

    u_int16_t *pp = get_port_ptr((struct sockaddr *)&sin);
    if (!pp) TEST_FAIL("get_port_ptr returned NULL");

    *pp = htons(7777);
    if (extract_port((const struct sockaddr *)&sin) != 7777)
        TEST_FAIL("port modification via pointer failed");

    TEST_PASS();
    return 0;
}

int test_get_port_ptr_null()
{
    TEST_START("get_port_ptr NULL");

    if (get_port_ptr(NULL) != NULL)
        TEST_FAIL("expected NULL for NULL addr");

    TEST_PASS();
    return 0;
}

/* --- newsaddr tests --- */

int test_newsaddr_ipv4()
{
    struct sockaddr *sa;

    TEST_START("newsaddr IPv4");

    sa = newsaddr(sizeof(struct sockaddr_in));
    if (!sa) TEST_FAIL("newsaddr returned NULL");
    if (sa->sa_family != AF_INET)
        TEST_FAIL("expected AF_INET");

    racoon_free(sa);
    TEST_PASS();
    return 0;
}

int test_newsaddr_ipv6()
{
    struct sockaddr *sa;

    TEST_START("newsaddr IPv6");

    sa = newsaddr(sizeof(struct sockaddr_in6));
    if (!sa) TEST_FAIL("newsaddr returned NULL");
    if (sa->sa_family != AF_INET6)
        TEST_FAIL("expected AF_INET6");

    racoon_free(sa);
    TEST_PASS();
    return 0;
}

/* --- dupsaddr tests --- */

int test_dupsaddr_ipv4()
{
    struct sockaddr_in sin;
    struct sockaddr *copy;

    TEST_START("dupsaddr IPv4");

    make_inet4(&sin, "192.168.1.1", 500);

    copy = dupsaddr((struct sockaddr *)&sin);
    if (!copy) TEST_FAIL("dupsaddr returned NULL");

    struct sockaddr_in *csin = (struct sockaddr_in *)copy;
    if (csin->sin_family != AF_INET)
        TEST_FAIL("family mismatch");
    if (csin->sin_port != htons(500))
        TEST_FAIL("port mismatch");
    if (memcmp(&csin->sin_addr, &sin.sin_addr, sizeof(struct in_addr)) != 0)
        TEST_FAIL("address mismatch");

    racoon_free(copy);
    TEST_PASS();
    return 0;
}

int test_dupsaddr_ipv6()
{
    struct sockaddr_in6 sin6;
    struct sockaddr *copy;

    TEST_START("dupsaddr IPv6");

    make_inet6(&sin6, "fe80::1", 4500);

    copy = dupsaddr((struct sockaddr *)&sin6);
    if (!copy) TEST_FAIL("dupsaddr returned NULL");

    struct sockaddr_in6 *csin6 = (struct sockaddr_in6 *)copy;
    if (csin6->sin6_family != AF_INET6)
        TEST_FAIL("family mismatch");
    if (csin6->sin6_port != htons(4500))
        TEST_FAIL("port mismatch");

    racoon_free(copy);
    TEST_PASS();
    return 0;
}

/* --- saddr2str tests --- */

int test_saddr2str_ipv4()
{
    struct sockaddr_in sin;
    char *str;

    TEST_START("saddr2str IPv4");

    make_inet4(&sin, "192.168.1.1", 500);

    str = saddr2str((const struct sockaddr *)&sin);
    if (!str) TEST_FAIL("saddr2str returned NULL");
    if (strstr(str, "192.168.1.1") == NULL)
        TEST_FAIL("expected IP in string");

    TEST_PASS();
    return 0;
}

int test_saddr2str_unspec()
{
    struct sockaddr sa = { 0 };
    char *str;

    TEST_START("saddr2str AF_UNSPEC");

    sa.sa_family = AF_UNSPEC;

    str = saddr2str(&sa);
    if (!str) TEST_FAIL("saddr2str returned NULL");
    if (strcmp(str, "anonymous") != 0)
        TEST_FAIL("expected 'anonymous'");

    TEST_PASS();
    return 0;
}

int test_saddr2str_null()
{
    TEST_START("saddr2str NULL");

    if (saddr2str(NULL) != NULL)
        TEST_FAIL("expected NULL for NULL input");

    TEST_PASS();
    return 0;
}

int test_saddrwop2str_ipv4()
{
    struct sockaddr_in sin;
    char *str;

    TEST_START("saddrwop2str IPv4");

    make_inet4(&sin, "10.0.0.1", 500);

    str = saddrwop2str((const struct sockaddr *)&sin);
    if (!str) TEST_FAIL("saddrwop2str returned NULL");
    if (strstr(str, "10.0.0.1") == NULL)
        TEST_FAIL("expected IP in string");

    TEST_PASS();
    return 0;
}

int test_saddrwop2str_null()
{
    TEST_START("saddrwop2str NULL");

    if (saddrwop2str(NULL) != NULL)
        TEST_FAIL("expected NULL for NULL input");

    TEST_PASS();
    return 0;
}

/* --- naddrwop2str tests --- */

int test_naddrwop2str_any()
{
    struct netaddr na = { 0 };
    char *str;

    TEST_START("naddrwop2str any");

    str = naddrwop2str(&na);
    if (!str) TEST_FAIL("naddrwop2str returned NULL");
    if (strcmp(str, "any") != 0)
        TEST_FAIL("expected 'any'");

    TEST_PASS();
    return 0;
}

int test_naddrwop2str_with_prefix()
{
    struct netaddr na = { 0 };
    char *str;

    TEST_START("naddrwop2str with prefix");

    make_inet4((struct sockaddr_in *)&na.sa.sin, "192.168.0.0", 0);
    na.prefix = 24;

    str = naddrwop2str(&na);
    if (!str) TEST_FAIL("naddrwop2str returned NULL");
    if (strstr(str, "192.168.0.0") == NULL)
        TEST_FAIL("expected IP in string");
    if (strstr(str, "/24") == NULL)
        TEST_FAIL("expected /24 in string");

    TEST_PASS();
    return 0;
}

int test_naddrwop2str_null()
{
    TEST_START("naddrwop2str NULL");

    if (naddrwop2str(NULL) != NULL)
        TEST_FAIL("expected NULL for NULL input");

    TEST_PASS();
    return 0;
}

/* --- saddr2str_fromto tests --- */

int test_saddr2str_fromto_ipv4()
{
    struct sockaddr_in sin1, sin2;
    char *str;

    TEST_START("saddr2str_fromto IPv4");

    make_inet4(&sin1, "192.168.1.1", 500);
    make_inet4(&sin2, "10.0.0.1", 500);

    str = saddr2str_fromto("%s <-> %s", (const struct sockaddr *)&sin1,
                           (const struct sockaddr *)&sin2);
    if (!str) TEST_FAIL("saddr2str_fromto returned NULL");
    if (strstr(str, "192.168.1.1") == NULL)
        TEST_FAIL("expected src IP in string");
    if (strstr(str, "10.0.0.1") == NULL)
        TEST_FAIL("expected dst IP in string");

    TEST_PASS();
    return 0;
}

int test_saddr2str_fromto_unspec()
{
    struct sockaddr sa1 = { 0 }, sa2 = { 0 };
    char *str;

    TEST_START("saddr2str_fromto AF_UNSPEC");

    sa1.sa_family = AF_UNSPEC;
    sa2.sa_family = AF_UNSPEC;

    str = saddr2str_fromto("%s <-> %s", &sa1, &sa2);
    if (!str) TEST_FAIL("saddr2str_fromto returned NULL");
    if (strstr(str, "anonymous") == NULL)
        TEST_FAIL("expected 'anonymous' in string");

    TEST_PASS();
    return 0;
}

int test_saddr2str_fromto_custom_format()
{
    struct sockaddr_in sin1, sin2;
    char *str;

    TEST_START("saddr2str_fromto custom format");

    make_inet4(&sin1, "10.0.0.1", 500);
    make_inet4(&sin2, "10.0.0.2", 500);

    str = saddr2str_fromto("from %s to %s", (const struct sockaddr *)&sin1,
                           (const struct sockaddr *)&sin2);
    if (!str) TEST_FAIL("saddr2str_fromto returned NULL");
    if (strstr(str, "from") == NULL)
        TEST_FAIL("expected 'from' in output");
    if (strstr(str, "to") == NULL)
        TEST_FAIL("expected 'to' in output");

    TEST_PASS();
    return 0;
}

/* --- naddrwop2str_fromto tests --- */

int test_naddrwop2str_fromto_both_any()
{
    struct netaddr na1 = { 0 }, na2 = { 0 };
    char *str;

    TEST_START("naddrwop2str_fromto both any");

    str = naddrwop2str_fromto("%s -> %s", &na1, &na2);
    if (!str) TEST_FAIL("naddrwop2str_fromto returned NULL");
    if (strstr(str, "any") == NULL)
        TEST_FAIL("expected 'any' in string");

    TEST_PASS();
    return 0;
}

int test_naddrwop2str_fromto_with_prefix()
{
    struct netaddr na1 = { 0 }, na2 = { 0 };
    char *str;

    TEST_START("naddrwop2str_fromto with prefix");

    make_inet4((struct sockaddr_in *)&na1.sa.sin, "192.168.0.0", 0);
    na1.prefix = 24;
    make_inet4((struct sockaddr_in *)&na2.sa.sin, "10.0.0.0", 0);
    na2.prefix = 8;

    str = naddrwop2str_fromto("%s -> %s", &na1, &na2);
    if (!str) TEST_FAIL("naddrwop2str_fromto returned NULL");
    if (strstr(str, "192.168.0.0") == NULL)
        TEST_FAIL("expected src IP in string");
    if (strstr(str, "/24") == NULL)
        TEST_FAIL("expected /24 in string");
    if (strstr(str, "10.0.0.0") == NULL)
        TEST_FAIL("expected dst IP in string");

    TEST_PASS();
    return 0;
}

int test_naddrwop2str_fromto_custom_format()
{
    struct netaddr na1 = { 0 }, na2 = { 0 };
    char *str;

    TEST_START("naddrwop2str_fromto custom format");

    str = naddrwop2str_fromto("src=%s dst=%s", &na1, &na2);
    if (!str) TEST_FAIL("naddrwop2str_fromto returned NULL");
    if (strstr(str, "src=") == NULL)
        TEST_FAIL("expected 'src=' in output");
    if (strstr(str, "dst=") == NULL)
        TEST_FAIL("expected 'dst=' in output");

    TEST_PASS();
    return 0;
}

/* --- mask_sockaddr tests --- */

int test_mask_sockaddr_ipv4_full_mask()
{
    struct sockaddr_in sin_src, sin_dst;

    TEST_START("mask_sockaddr IPv4 /32 full mask");

    make_inet4(&sin_src, "192.168.1.100", 500);
    make_inet4(&sin_dst, "192.168.1.200", 500);

    mask_sockaddr((struct sockaddr *)&sin_src,
                  (const struct sockaddr *)&sin_dst, 32);

    /* With /32 the full address is masked — no change to src */
    if (sin_src.sin_addr.s_addr != sin_dst.sin_addr.s_addr)
        TEST_FAIL("expected masked result to match dst");

    TEST_PASS();
    return 0;
}

int test_mask_sockaddr_ipv4_zero_mask()
{
    struct sockaddr_in sin_src, sin_dst;

    TEST_START("mask_sockaddr IPv4 /0 zero mask");

    make_inet4(&sin_src, "192.168.1.100", 500);
    make_inet4(&sin_dst, "10.0.0.1", 4500);

    mask_sockaddr((struct sockaddr *)&sin_src,
                  (const struct sockaddr *)&sin_dst, 0);

    /* /0 means the entire address portion is zeroed out */
    if (sin_src.sin_addr.s_addr != 0)
        TEST_FAIL("expected address to be zeroed with /0 mask");

    TEST_PASS();
    return 0;
}

int test_mask_sockaddr_ipv4_24_mask()
{
    struct sockaddr_in sin_src, sin_dst;

    TEST_START("mask_sockaddr IPv4 /24 subnet mask");

    make_inet4(&sin_src, "0.0.0.0", 0);
    make_inet4(&sin_dst, "192.168.1.200", 500);

    mask_sockaddr((struct sockaddr *)&sin_src,
                  (const struct sockaddr *)&sin_dst, 24);

    /* /24 should keep first 3 bytes, zero last byte */
    if (memcmp(&sin_src.sin_addr, &(struct in_addr){ htonl(0xc0a80100) }, sizeof(struct in_addr)) != 0)
        TEST_FAIL("expected 192.168.1.0 after /24 mask");

    TEST_PASS();
    return 0;
}

int test_mask_sockaddr_ipv4_16_mask()
{
    struct sockaddr_in sin_src, sin_dst;

    TEST_START("mask_sockaddr IPv4 /16 subnet mask");

    make_inet4(&sin_src, "0.0.0.0", 0);
    make_inet4(&sin_dst, "10.20.30.40", 500);

    mask_sockaddr((struct sockaddr *)&sin_src,
                  (const struct sockaddr *)&sin_dst, 16);

    if (memcmp(&sin_src.sin_addr, &(struct in_addr){ htonl(0x0a140000) }, sizeof(struct in_addr)) != 0)
        TEST_FAIL("expected 10.20.0.0 after /16 mask");

    TEST_PASS();
    return 0;
}

int test_mask_sockaddr_ipv4_8_mask()
{
    struct sockaddr_in sin_src, sin_dst;

    TEST_START("mask_sockaddr IPv4 /8 subnet mask");

    make_inet4(&sin_src, "0.0.0.0", 0);
    make_inet4(&sin_dst, "172.20.30.40", 500);

    mask_sockaddr((struct sockaddr *)&sin_src,
                  (const struct sockaddr *)&sin_dst, 8);

    if (memcmp(&sin_src.sin_addr, &(struct in_addr){ htonl(0xac000000) }, sizeof(struct in_addr)) != 0)
        TEST_FAIL("expected 172.0.0.0 after /8 mask");

    TEST_PASS();
    return 0;
}

int test_mask_sockaddr_ipv4_odd_mask()
{
    struct sockaddr_in sin_src, sin_dst;

    TEST_START("mask_sockaddr IPv4 /25 odd mask");

    make_inet4(&sin_src, "0.0.0.0", 0);
    make_inet4(&sin_dst, "192.168.1.200", 500);

    mask_sockaddr((struct sockaddr *)&sin_src,
                  (const struct sockaddr *)&sin_dst, 25);

    /* /25: 3 full bytes + 1 bit of 4th byte. 200 = 0b11001000, mask 0b10000000 = 128 */
    if (memcmp(&sin_src.sin_addr, &(struct in_addr){ htonl(0xc0a80180) }, sizeof(struct in_addr)) != 0)
        TEST_FAIL("expected 192.168.1.128 after /25 mask");

    TEST_PASS();
    return 0;
}

int test_mask_sockaddr_ipv4_preserves_port()
{
    struct sockaddr_in sin_src, sin_dst;

    TEST_START("mask_sockaddr IPv4 preserves port");

    make_inet4(&sin_src, "0.0.0.0", 0);
    make_inet4(&sin_dst, "192.168.1.100", 4500);

    mask_sockaddr((struct sockaddr *)&sin_src,
                  (const struct sockaddr *)&sin_dst, 24);

    if (sin_src.sin_port != htons(4500))
        TEST_FAIL("expected port to be preserved");

    TEST_PASS();
    return 0;
}

int test_mask_sockaddr_ipv6_full_mask()
{
    struct sockaddr_in6 sin6_src, sin6_dst;

    TEST_START("mask_sockaddr IPv6 /128 full mask");

    make_inet6(&sin6_src, "::1", 500);
    make_inet6(&sin6_dst, "fe80::1", 500);

    mask_sockaddr((struct sockaddr *)&sin6_src,
                  (const struct sockaddr *)&sin6_dst, 128);

    /* /128 means exact copy of address */
    if (sin6_src.sin6_addr.s6_addr[15] != 1)
        TEST_FAIL("expected address to match dst");

    TEST_PASS();
    return 0;
}

int test_mask_sockaddr_ipv6_zero_mask()
{
    struct sockaddr_in6 sin6_src, sin6_dst;

    TEST_START("mask_sockaddr IPv6 /0 zero mask");

    make_inet6(&sin6_src, "::1", 500);
    make_inet6(&sin6_dst, "fe80::1", 500);

    mask_sockaddr((struct sockaddr *)&sin6_src,
                  (const struct sockaddr *)&sin6_dst, 0);

    /* /0 means all address bytes zeroed */
    if (memcmp(&sin6_src.sin6_addr, &(struct in6_addr){ 0 }, sizeof(struct in6_addr)) != 0)
        TEST_FAIL("expected address to be zeroed with /0 mask");

    TEST_PASS();
    return 0;
}

int test_mask_sockaddr_ipv6_64_mask()
{
    struct sockaddr_in6 sin6_src, sin6_dst;

    TEST_START("mask_sockaddr IPv6 /64 subnet mask");

    make_inet6(&sin6_src, "::1", 500);
    make_inet6(&sin6_dst, "fe80::dead:beef", 500);

    mask_sockaddr((struct sockaddr *)&sin6_src,
                  (const struct sockaddr *)&sin6_dst, 64);

    /* /64: first 8 bytes preserved, last 8 zeroed */
    if (sin6_src.sin6_addr.s6_addr[7] != 0)
        TEST_FAIL("expected 8th byte to be 0 (start of zeroed portion)");

    TEST_PASS();
    return 0;
}

int test_mask_sockaddr_ipv6_odd_mask()
{
    struct sockaddr_in6 sin6_src, sin6_dst;

    TEST_START("mask_sockaddr IPv6 /65 odd mask");

    make_inet6(&sin6_src, "::", 0);
    make_inet6(&sin6_dst, "0:0:0:0:de00:ffff:beef:cafe", 0);

    mask_sockaddr((struct sockaddr *)&sin6_src,
                  (const struct sockaddr *)&sin6_dst, 65);

    /* /65: 8 full bytes + 1 bit of 9th byte (index 8). 0xde & 0x80 = 0x80 */
    if (sin6_src.sin6_addr.s6_addr[8] != 0x80)
        TEST_FAIL("expected 9th byte to be 0x80 after /65 mask");

    TEST_PASS();
    return 0;
}

/* --- naddr_score tests --- */

int test_naddr_score_null_naddr()
{
    TEST_START("naddr_score NULL naddr");

    struct sockaddr_in sin;
    make_inet4(&sin, "10.0.0.1", 500);

    if (naddr_score(NULL, (const struct sockaddr *)&sin) != -1)
        TEST_FAIL("expected -1 for NULL naddr");

    TEST_PASS();
    return 0;
}

int test_naddr_score_null_saddr()
{
    TEST_START("naddr_score NULL saddr");

    struct netaddr na = { 0 };
    make_inet4((struct sockaddr_in *)&na.sa.sin, "10.0.0.0", 0);
    na.prefix = 24;

    if (naddr_score(&na, NULL) != -1)
        TEST_FAIL("expected -1 for NULL saddr");

    TEST_PASS();
    return 0;
}

int test_naddr_score_both_null()
{
    TEST_START("naddr_score both NULL");

    if (naddr_score(NULL, NULL) != -1)
        TEST_FAIL("expected -1 for both NULL");

    TEST_PASS();
    return 0;
}

int test_naddr_score_wildcard_any()
{
    TEST_START("naddr_score wildcard (all-zeros netaddr)");

    struct netaddr na = { 0 };
    struct sockaddr_in sin;
    make_inet4(&sin, "10.0.0.1", 500);

    if (naddr_score(&na, (const struct sockaddr *)&sin) != 0)
        TEST_FAIL("expected 0 for wildcard netaddr");

    TEST_PASS();
    return 0;
}

int test_naddr_score_family_mismatch()
{
    TEST_START("naddr_score family mismatch");

    struct netaddr na = { 0 };
    struct sockaddr_in6 sin6;

    make_inet4((struct sockaddr_in *)&na.sa.sin, "10.0.0.0", 0);
    na.prefix = 24;
    make_inet6(&sin6, "::1", 500);

    if (naddr_score(&na, (const struct sockaddr *)&sin6) != -1)
        TEST_FAIL("expected -1 for family mismatch");

    TEST_PASS();
    return 0;
}

int test_naddr_score_exact_match_with_port()
{
    TEST_START("naddr_score exact match with port");

    struct netaddr na = { 0 };
    struct sockaddr_in sin;

    make_inet4((struct sockaddr_in *)&na.sa.sin, "10.20.30.40", 500);
    na.prefix = 32;
    make_inet4(&sin, "10.20.30.40", 500);

    int score = naddr_score(&na, (const struct sockaddr *)&sin);
    if (score != 33)
        TEST_FAIL("expected score 33 (32 prefix + 1 port)");

    TEST_PASS();
    return 0;
}

int test_naddr_score_exact_match_no_port()
{
    TEST_START("naddr_score exact match without port");

    struct netaddr na = { 0 };
    struct sockaddr_in sin;

    make_inet4((struct sockaddr_in *)&na.sa.sin, "10.20.30.40", 0);
    na.prefix = 32;
    make_inet4(&sin, "10.20.30.40", 500);

    int score = naddr_score(&na, (const struct sockaddr *)&sin);
    if (score != 32)
        TEST_FAIL("expected score 32 (32 prefix + 0 wildcard port)");

    TEST_PASS();
    return 0;
}

int test_naddr_score_24_prefix_match()
{
    TEST_START("naddr_score /24 prefix match");

    struct netaddr na = { 0 };
    struct sockaddr_in sin;

    make_inet4((struct sockaddr_in *)&na.sa.sin, "10.20.30.0", 0);
    na.prefix = 24;
    make_inet4(&sin, "10.20.30.40", 0);

    int score = naddr_score(&na, (const struct sockaddr *)&sin);
    if (score != 24)
        TEST_FAIL("expected score 24");

    TEST_PASS();
    return 0;
}

int test_naddr_score_16_prefix_match()
{
    TEST_START("naddr_score /16 prefix match");

    struct netaddr na = { 0 };
    struct sockaddr_in sin;

    make_inet4((struct sockaddr_in *)&na.sa.sin, "10.20.0.0", 0);
    na.prefix = 16;
    make_inet4(&sin, "10.20.30.40", 0);

    int score = naddr_score(&na, (const struct sockaddr *)&sin);
    if (score != 16)
        TEST_FAIL("expected score 16");

    TEST_PASS();
    return 0;
}

int test_naddr_score_no_match()
{
    TEST_START("naddr_score no match (wrong network)");

    struct netaddr na = { 0 };
    struct sockaddr_in sin;

    make_inet4((struct sockaddr_in *)&na.sa.sin, "10.10.0.0", 0);
    na.prefix = 16;
    make_inet4(&sin, "10.20.30.40", 0);

    if (naddr_score(&na, (const struct sockaddr *)&sin) != -1)
        TEST_FAIL("expected -1 for non-matching network");

    TEST_PASS();
    return 0;
}

int test_naddr_score_port_mismatch()
{
    TEST_START("naddr_score port mismatch");

    struct netaddr na = { 0 };
    struct sockaddr_in sin;

    make_inet4((struct sockaddr_in *)&na.sa.sin, "10.20.30.40", 500);
    na.prefix = 32;
    make_inet4(&sin, "10.20.30.40", 4500);

    if (naddr_score(&na, (const struct sockaddr *)&sin) != -1)
        TEST_FAIL("expected -1 for port mismatch");

    TEST_PASS();
    return 0;
}

int test_naddr_score_0_prefix_match()
{
    TEST_START("naddr_score /0 prefix match");

    struct netaddr na = { 0 };
    struct sockaddr_in sin;

    /* /0 with non-zero port means address is 0.0.0.0/0 with a specific port */
    make_inet4((struct sockaddr_in *)&na.sa.sin, "0.0.0.0", 500);
    na.prefix = 0;
    make_inet4(&sin, "10.20.30.40", 500);

    int score = naddr_score(&na, (const struct sockaddr *)&sin);
    if (score != 1)
        TEST_FAIL("expected score 1 (0 prefix + 1 port match)");

    TEST_PASS();
    return 0;
}

int test_naddr_score_ipv6_exact()
{
    TEST_START("naddr_score IPv6 exact match");

    struct netaddr na = { 0 };
    struct sockaddr_in6 sin6;

    make_inet6((struct sockaddr_in6 *)&na.sa.sin6, "::1", 500);
    na.prefix = 128;
    make_inet6(&sin6, "::1", 500);

    int score = naddr_score(&na, (const struct sockaddr *)&sin6);
    if (score != 129)
        TEST_FAIL("expected score 129 (128 prefix + 1 port)");

    TEST_PASS();
    return 0;
}

int test_naddr_score_ipv6_64_prefix()
{
    TEST_START("naddr_score IPv6 /64 prefix match");

    struct netaddr na = { 0 };
    struct sockaddr_in6 sin6;

    make_inet6((struct sockaddr_in6 *)&na.sa.sin6, "fe80::", 0);
    na.prefix = 64;
    make_inet6(&sin6, "fe80::dead:beef", 0);

    int score = naddr_score(&na, (const struct sockaddr *)&sin6);
    if (score != 64)
        TEST_FAIL("expected score 64");

    TEST_PASS();
    return 0;
}

int test_naddr_score_ipv6_no_match()
{
    TEST_START("naddr_score IPv6 no match");

    struct netaddr na = { 0 };
    struct sockaddr_in6 sin6;

    make_inet6((struct sockaddr_in6 *)&na.sa.sin6, "fe80::", 0);
    na.prefix = 64;
    make_inet6(&sin6, "fe81::dead:beef", 0);

    if (naddr_score(&na, (const struct sockaddr *)&sin6) != -1)
        TEST_FAIL("expected -1 for non-matching IPv6 network");

    TEST_PASS();
    return 0;
}

int main(void)
{
    int failures = 0;

    printf("=== sockmisc unit tests ===\n");

    /* cmpsaddr */
    failures += test_cmpsaddr_both_null() < 0;
    failures += test_cmpsaddr_one_null() < 0;
    failures += test_cmpsaddr_ipv4_exact_match() < 0;
    failures += test_cmpsaddr_ipv4_port_mismatch() < 0;
    failures += test_cmpsaddr_ipv4_addr_mismatch() < 0;
    failures += test_cmpsaddr_ipv4_wildcard_port_any() < 0;
    failures += test_cmpsaddr_ipv4_wildcard_port_both() < 0;
    failures += test_cmpsaddr_ipv6_exact_match() < 0;
    failures += test_cmpsaddr_ipv6_addr_mismatch() < 0;
    failures += test_cmpsaddr_family_mismatch() < 0;
    failures += test_cmpsaddr_unspec() < 0;

    /* extract_port */
    failures += test_extract_port_ipv4() < 0;
    failures += test_extract_port_ipv6() < 0;
    failures += test_extract_port_null() < 0;
    failures += test_extract_port_unspec() < 0;

    /* set_port / get_port_ptr */
    failures += test_set_port_ipv4() < 0;
    failures += test_set_port_ipv6() < 0;
    failures += test_get_port_ptr_ipv4() < 0;
    failures += test_get_port_ptr_null() < 0;

    /* newsaddr */
    failures += test_newsaddr_ipv4() < 0;
    failures += test_newsaddr_ipv6() < 0;

    /* dupsaddr */
    failures += test_dupsaddr_ipv4() < 0;
    failures += test_dupsaddr_ipv6() < 0;

    /* saddr2str */
    failures += test_saddr2str_ipv4() < 0;
    failures += test_saddr2str_unspec() < 0;
    failures += test_saddr2str_null() < 0;
    failures += test_saddrwop2str_ipv4() < 0;
    failures += test_saddrwop2str_null() < 0;

    /* naddrwop2str */
    failures += test_naddrwop2str_any() < 0;
    failures += test_naddrwop2str_with_prefix() < 0;
    failures += test_naddrwop2str_null() < 0;

    /* saddr2str_fromto */
    failures += test_saddr2str_fromto_ipv4() < 0;
    failures += test_saddr2str_fromto_unspec() < 0;
    failures += test_saddr2str_fromto_custom_format() < 0;

    /* naddrwop2str_fromto */
    failures += test_naddrwop2str_fromto_both_any() < 0;
    failures += test_naddrwop2str_fromto_with_prefix() < 0;
    failures += test_naddrwop2str_fromto_custom_format() < 0;

    /* mask_sockaddr */
    failures += test_mask_sockaddr_ipv4_full_mask() < 0;
    failures += test_mask_sockaddr_ipv4_zero_mask() < 0;
    failures += test_mask_sockaddr_ipv4_24_mask() < 0;
    failures += test_mask_sockaddr_ipv4_16_mask() < 0;
    failures += test_mask_sockaddr_ipv4_8_mask() < 0;
    failures += test_mask_sockaddr_ipv4_odd_mask() < 0;
    failures += test_mask_sockaddr_ipv4_preserves_port() < 0;
    failures += test_mask_sockaddr_ipv6_full_mask() < 0;
    failures += test_mask_sockaddr_ipv6_zero_mask() < 0;
    failures += test_mask_sockaddr_ipv6_64_mask() < 0;
    failures += test_mask_sockaddr_ipv6_odd_mask() < 0;

    /* naddr_score */
    failures += test_naddr_score_null_naddr() < 0;
    failures += test_naddr_score_null_saddr() < 0;
    failures += test_naddr_score_both_null() < 0;
    failures += test_naddr_score_wildcard_any() < 0;
    failures += test_naddr_score_family_mismatch() < 0;
    failures += test_naddr_score_exact_match_with_port() < 0;
    failures += test_naddr_score_exact_match_no_port() < 0;
    failures += test_naddr_score_24_prefix_match() < 0;
    failures += test_naddr_score_16_prefix_match() < 0;
    failures += test_naddr_score_no_match() < 0;
    failures += test_naddr_score_port_mismatch() < 0;
    failures += test_naddr_score_0_prefix_match() < 0;
    failures += test_naddr_score_ipv6_exact() < 0;
    failures += test_naddr_score_ipv6_64_prefix() < 0;
    failures += test_naddr_score_ipv6_no_match() < 0;

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}
