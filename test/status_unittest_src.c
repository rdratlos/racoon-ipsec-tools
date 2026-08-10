/* status.c has no static functions a test would need an ENABLE_UNITTEST
 * accessor for -- this wrapper exists only so status_test_stubs.c's
 * enumph1()/enumph2() stand-ins are what status_dump() (below) resolves
 * to at link time, instead of the real handler.c versions (and their
 * large dependency closure), matching the pattern admin_unittest_src.c/
 * isakmp_unittest_src.c use elsewhere in this suite. */
#include "../src/racoon/status.c"
