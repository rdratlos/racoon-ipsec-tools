/* Wrapper so this object is local to test/, keeping its .Po dependency
 * file under test/.deps/ instead of a cross-directory path that some
 * automake versions (e.g. Ubuntu Bionic's 1.15.1) fail to track when
 * subdir-objects reaches into another top-level directory.
 *
 * racoonctl.c defines its own K&R-style main(); rename it out of the
 * way since this translation unit is linked into a test binary with
 * its own main() and we only ever call f_logoutusr_unittest() (issue
 * #68), never racoonctl's CLI dispatch loop. */
#define main racoonctl_main_unused
#include "../src/racoon/racoonctl.c"
