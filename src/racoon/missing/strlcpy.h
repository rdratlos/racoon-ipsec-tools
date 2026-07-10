/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Fallback strlcpy() for platforms lacking it (HAVE_STRLCPY unset by
 * configure). Shared single-source implementation: include this header
 * wherever strlcpy() is needed instead of embedding a private copy.
 */

#ifndef _MISSING_STRLCPY_H
#define _MISSING_STRLCPY_H

#include <string.h>

#ifndef HAVE_STRLCPY
static size_t __attribute__((noinline))
strlcpy(char *dst, const char *src, size_t siz)
{
    register char *d = dst;
    const register char *s = src;
    size_t n = siz;

    if (n != 0) {
        while (--n != 0) {
            if ((*d++ = *s++) == '\0')
                return s - src - 1;
        }
    }

    if (n == 0 && siz)
        *d = '\0';
    return s - src + strlen(s);
}
#endif /* !HAVE_STRLCPY */

#endif /* _MISSING_STRLCPY_H */
