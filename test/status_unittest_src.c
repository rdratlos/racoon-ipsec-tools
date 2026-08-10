/* This wrapper exists so status_test_stubs.c's enumph1()/enumph2()
 * stand-ins are what status_dump() (below) resolves to at link time,
 * instead of the real handler.c versions (and their large dependency
 * closure), matching the pattern admin_unittest_src.c/isakmp_unittest_src.c
 * use elsewhere in this suite. status.c's own ENABLE_UNITTEST accessors
 * (ph1_state_name_unittest()/ph2_state_name_unittest(), at the bottom of
 * status.c) are declared inside status.c itself, not here. */
#include "../src/racoon/status.c"
