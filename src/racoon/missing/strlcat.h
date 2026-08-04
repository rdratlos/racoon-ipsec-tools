/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Fallback strlcat() for platforms lacking it (HAVE_STRLCAT unset by
 * configure). Shared single-source implementation: include this header
 * wherever strlcat() is needed instead of embedding a private copy.
 *
 * This replaces the earlier `strncat(d,s,(l)-strlen(d)-1)` macro, which
 * underflowed to a huge size_t (and so lost its bound entirely) whenever
 * strlen(d) >= l.
 */

#ifndef _MISSING_STRLCAT_H
#define _MISSING_STRLCAT_H

#include <string.h>

#ifndef HAVE_STRLCAT
static size_t __attribute__((noinline))
strlcat(char *dst, const char *src, size_t siz)
{
    register char *d = dst;
    const register char *s = src;
    size_t n = siz;
    size_t dlen;

    /* Find the end of dst and adjust bytes left but don't go past end. */
    while (n-- != 0 && *d != '\0')
        d++;
    dlen = d - dst;
    n = siz - dlen;

    if (n == 0)
        return dlen + strlen(s);

    while (*s != '\0') {
        if (n != 1) {
            *d++ = *s;
            n--;
        }
        s++;
    }
    *d = '\0';

    return dlen + (s - src); /* count does not include NUL */
}
#endif /* !HAVE_STRLCAT */

#endif /* _MISSING_STRLCAT_H */
