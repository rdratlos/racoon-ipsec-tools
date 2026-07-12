/*
 * Minimal, test-only stand-ins for plog.c's global logging state.
 *
 * vmbuf.o is reused pre-built from src/racoon/ (not compiled with
 * -ffunction-sections here), so --gc-sections cannot cherry-pick
 * vmalloc()/vfree() out of it in isolation: the whole object comes in
 * as one unit, including vdup()'s plog(LLV_ERROR, LOCATION, ...) call.
 * f_logoutusr() never calls vdup() (or plog() itself), so these are
 * never exercised at runtime -- they exist only to satisfy the linker
 * without pulling in the real plog.o, whose own `char *pname` (plog.c)
 * would otherwise collide with racoonctl.c's own `char *pname` (both
 * are definitions of the single `extern char *pname` declared in
 * plog.h) when both objects are listed directly on the same link line.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plog.h"

u_int32_t loglevel = LLV_ERROR;

void
_plog(int pri, const char *fmt_location, struct sockaddr *sa,
    const char *fmt, ...)
{
	/* unreachable from f_logoutusr()'s call graph; intentionally empty */
}
