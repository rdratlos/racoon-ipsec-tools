/* kmpstat.c defines no main() of its own, so this file can include it
 * directly to reach com_recv()'s admin-socket fd (`so`, a static,
 * file-scope variable) via the ENABLE_UNITTEST-only com_set_fd_unittest()
 * accessor it defines, without adding new production API surface. */
#include "../src/racoon/kmpstat.c"
