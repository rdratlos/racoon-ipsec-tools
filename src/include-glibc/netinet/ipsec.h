/*	$NetBSD: ipsec.h,v 1.4 2006/09/09 16:22:09 manu Exp $	*/

#ifdef __linux__
#include <linux/pfkeyv2.h>
#include <linux/ipsec.h>
#else
#include <net/pfkeyv2.h>
#endif
