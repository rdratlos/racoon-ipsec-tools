/* privsep.c defines no main() of its own, so this file can include it
 * directly to reach privsep_sigterm_forward()/privsep_child_pid (both
 * static/file-scope) via the ENABLE_UNITTEST-only accessors it defines,
 * without adding new production API surface. */
#include "../src/racoon/privsep.c"
