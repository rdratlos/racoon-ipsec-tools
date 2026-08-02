/* admin.c defines no main() of its own, so this file can include it
 * directly to reach admin_check_sockpath()/admin2pfkey_proto() (already
 * exported) and mkdir_p_unittest()/admin_process_unittest() (new
 * ENABLE_UNITTEST-only accessors for mkdir_p()/admin_process(), both
 * static/file-scope), without adding new production API surface. */
#include "../src/racoon/admin.c"
