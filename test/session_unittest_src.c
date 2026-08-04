/* session.c defines no main() of its own, so this file can include it
 * directly to reach monitor_fd()/unmonitor_fd() (already exported) and
 * prune_stale_monitored_fds_unittest() (a new ENABLE_UNITTEST-only
 * accessor for prune_stale_monitored_fds(), static/file-scope), without
 * adding new production API surface. */
#include "../src/racoon/session.c"
