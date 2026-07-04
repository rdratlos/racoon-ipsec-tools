/* Wrapper so this object is local to test/, keeping its .Po dependency
 * file under test/.deps/ instead of a cross-directory path that some
 * automake versions (e.g. Ubuntu Bionic's 1.15.1) fail to track when
 * subdir-objects reaches into another top-level directory. */
#include "../src/racoon/vendorid.c"
