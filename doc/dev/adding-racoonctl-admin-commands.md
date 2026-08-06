# Adding a new racoonctl <-> racoon admin command

`racoonctl` talks to the running `racoon` daemon over a UNIX-domain admin
socket using a small fixed wire protocol (`struct admin_com`, `admin.h`).
Adding a new command touches more files than it looks like it should, and
skipping one of them fails in a place that gives no hint about which file
you forgot. This guide is the checklist; the "Why this bites" sections
below it are the actual failure modes, kept next to the step that avoids
them.

## The round trip

A new command is one addition in each of these six places:

1. **`src/racoon/admin.h`** -- allocate an `ADMIN_*` command constant in
   the free slot of whichever range fits (no-proto `0x00xx`, proto-bearing
   `0x01xx`, indexed `0x02xx`; see the existing comments above each block).
2. **`src/racoon/admin.c`** -- add the `case ADMIN_*:` to `admin_process()`'s
   switch, doing whatever work the command needs and setting `l_ac_errno`
   on failure. If this case needs a helper that doesn't exist yet, decide
   which existing `.c` file it belongs in (usually `handler.c` for
   phase1/phase2 state, `pfkey.c` for SADB, `evt.c` for events) -- see step
   6 before you pick a name.
3. **`src/racoon/racoonctl.c`** -- three separate additions here, easy to
   do two of three and miss the third:
   - an `f_*()` handler function that builds the request via
     `make_request()` and returns its `vchar_t *`,
   - an entry in `cmdtab[]` mapping the command name(s) to that handler,
   - a `case ADMIN_*:` in `handle_recv()` that prints the daemon's reply.
     **Every command that returns data needs this case.** There is no
     default handler for reply data -- an unhandled `ac_cmd` in
     `handle_recv()` falls into `default: /* IGNORE */` and the reply is
     silently discarded. If you add `ADMIN_FOO` and `ADMIN_FOO_VERBOSE`
     as two separate wire commands, `handle_recv()` needs a case for
     *both*, even if they share every other code path -- forgetting the
     second one means the verbose flag on your new command silently
     prints nothing, with no error anywhere.
4. **`src/racoon/racoonctl.1`** (or wherever the manpage/usage string
   lives) -- document the new subcommand and its options.
5. **`test/admin_test_stubs.c`** and **`test/test_admin_process_dispatch.c`**
   -- see "Why this bites #1" below. Required the moment step 2's case
   calls anything not already linked into the admin test binaries.
6. **A unit test for whatever step 2's case actually calls** -- the
   dispatch test above only proves `admin_process()` reached your case and
   called the right function; it does not exercise that function's own
   logic. If step 2 needed new logic (not just calling something that
   already has its own tests), that logic needs its own test file the same
   way `handler.c`, `pfkey.c`, etc. already have theirs (see
   `test/README.md`).

## Why this bites #1: the admin-test-stub trap

`admin_process()` (`admin.c`) is **one C function containing every
`ADMIN_*` case**. The test suite links it for real (`test/admin_unittest_src.c`
`#include`s `admin.c` directly) rather than re-implementing its dispatch
logic, and several test binaries build it with
`-ffunction-sections -fdata-sections -Wl,--gc-sections` so that only the
functions a given test path actually reaches get linked.

That optimization works *between* functions, not *within* one. Because
every case lives inside the single `admin_process()` function body, the
linker cannot drop the cases a test never drives at runtime -- **every
symbol referenced anywhere in the switch must resolve**, whether or not
the test that's failing to link ever sends that command. If your new
case calls a function with no existing stub, every one of these binaries
fails at the *link* step, not the compile step, with an error like:

```
/usr/bin/ld: test_admin_init-admin_unittest_src.o: in function `admin_process':
admin_unittest_src.c:(.text.admin_process+0x69a): undefined reference to `your_new_function'
collect2: error: ld returned 1 exit status
make[2]: *** [Makefile:NNNN: test_admin_init] Error 1
```

repeated across `test_admin_init`, `test_admin_handler`,
`test_admin_delete_all_sa_dst`, `test_admin_process_dispatch`,
`test_admin_establish_sa_psk`, and `test_admin_close` -- every target that
links `admin_test_stubs.c`. Nothing in that error, or in the source files
it names, points at the actual fix: none of them mention
`admin_test_stubs.c` by name, and `admin_test_stubs.c`'s own header
comment (worth reading once) explains the mechanism but not "you're the
one who needs to add to this file."

**The fix:** add a stub for your new symbol to `test/admin_test_stubs.c`,
following the pattern already used for every other case's dependencies
(`sched_dump()`, `evt_dump()`, `dumpph1()`, `pfkey_dump_sadb()`, ...): a
call counter global, a minimal body that lets the test control the
return value. Then add a dispatch test for your new `ADMIN_*` case to
`test/test_admin_process_dispatch.c`, asserting the stub was called (and,
if relevant, called with the right arguments) and that `admin_process()`
put the right `ac_errno` on the wire -- see any `test_show_*`/`test_flush_*`
function in that file for the pattern.

If your case's logic is entirely self-contained (no new external
symbol), you won't hit this -- it only fires when `admin_process()`
references something that isn't already linked into these binaries.

## Why this bites #2: the missing return type

`f_*()` handlers in `racoonctl.c` (step 3) are typically declared
`static vchar_t *`. If a new one is typed (or copy-pasted) without that
prefix, the compiler falls back to an implicit `int` return type -- a
hard error under this project's `-Werror=implicit-int` /
`-Werror=int-conversion`, but easy to introduce by starting from an
existing function body and forgetting the line above the function name
came along with it. It breaks the main `racoon`/`racoonctl` build itself
(not just tests), since `racoonctl.o` fails to compile at all.

## Why this bites #3: silently dropped replies

Covered in step 3 above, repeated here because it's the easiest one to
miss: a new `ADMIN_*` reply needs its own `case` in `handle_recv()`
(`racoonctl.c`). There is no compiler warning for an unhandled case in
that switch -- it just falls through to `default: /* IGNORE */` and the
command appears to succeed (exit code 0, no error message) while printing
nothing at all.
