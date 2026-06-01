/*
 * Minimal stub implementations for symbols that rsalist.o (via
 * sockmisc.o) needs at link time but which are never exercised by
 * the rsalist unit tests in test_rsa_comprehensive.c.
 *
 * privsep.o is deliberately NOT linked in: on builds with XAUTH/CFG
 * support enabled it drags in isakmp_cfg_ and xauth_ symbols from
 * isakmp_cfg.c/isakmp_xauth.c, which would pull in most of racoon.
 * Stubbing the small privsep_* API used by sockmisc.c avoids that.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stddef.h>
#include "vmbuf.h"
#include "localconf.h"
#include "admin.h"
#include "privsep.h"

struct localconf *lcconf = NULL;

void
monitor_fd(int fd, int (*callback)(void *, int), void *ctx, int priority)
{
}

int
script_exec(char *script, int name, char *const envp[])
{
	return -1;
}

vchar_t *
getpsk(const char *str, const int len)
{
	return NULL;
}

vchar_t *
privsep_getpsk(const char *str, const int keylen)
{
	return NULL;
}

int
privsep_socket(int domain, int type, int protocol)
{
	return socket(domain, type, protocol);
}

int
privsep_bind(int s, const struct sockaddr *addr, socklen_t addrlen)
{
	return bind(s, addr, addrlen);
}

int
privsep_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	return setsockopt(s, level, optname, optval, optlen);
}
