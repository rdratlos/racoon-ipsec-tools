# Contributing

## Developer Setup

After cloning the repository, run the setup script once to configure
required local Git settings:

```bash
bash scripts/setup-dev-env.sh
```

This configures the `merge.ours.driver` needed for clean rebases of
Ubuntu LTS branches onto develop. Without it, Git will error when a
rebase touches `debian/control`, `debian/compat`, or `debian/rules`.

## Running the Test Suite

```bash
./bootstrap && ./configure && make
cd test && make check
```

Full details (coverage, valgrind, the wrapped-static-function pattern,
etc.) are in `test/README.md`. This section covers one thing specifically:
**a handful of tests need real root, and behave differently depending on
who runs `make check`.**

### Why some tests need root

`test_privsep_client_wrappers`, `test_privsep_hybrid_client_wrappers`, and
part of `test_privsep_init` exercise `privsep.c`'s client-side wrapper
functions (`privsep_socket()`, `privsep_bind()`, `privsep_script_exec()`,
etc.) over their real wire protocol. Each of those wrappers only takes the
wire-protocol branch when the *calling* process is not root
(`if (geteuid() == 0) return <real syscall/function>(...)`), so exercising
that branch means the test process must `seteuid()` itself to an
unprivileged account (`nobody`) partway through, then back to root
afterwards, around a still-root forked child that plays the privileged
side for real. Two of `test_privsep_init`'s own scenarios go further and
need a real forked child to itself `setgid()`/`setuid()` to that account.
`seteuid()`/`setuid()` to a *different* account (not one the process
already held) needs `CAP_SETUID` — which only a process that started as
root has. There is no way around this: the whole point is testing what
happens when privilege is dropped, which requires having it to drop from.
(`test_privsep_init_fork_failure` is the one privsep test that needs none
of this — its one scenario forces `fork()` itself to fail via a linker-level
wrap, so no real fork or privilege drop ever happens, and it always runs
in full regardless of who invokes `make check`.)

**Run as root** (locally via `sudo`, or a container set aside specifically
for it) and every test runs and is asserted on — this is the only way to
get full coverage of `test_privsep_client_wrappers`,
`test_privsep_hybrid_client_wrappers`, and `test_privsep_init`. This is a
deliberate, manual step (`sudo make check`/`sudo make check-valgrind`),
not what this project's CI does by default — see below.

**Run as an ordinary user** — this project's own CI's normal mode, and
the recommended default even for a local run — and the two binaries where
*every* case needs root (`test_privsep_client_wrappers`,
`test_privsep_hybrid_client_wrappers`) detect that up front and report
`SKIP` (exit code 77 — automake's own convention for "this test doesn't
apply here", distinct from a failure) instead of failing. `test_privsep_init`
is different: two of its four scenarios (the `lcconf->uid == 0` no-op, and
the missing-cert/script-path refusal) don't touch privilege at all and
always run; its other two (a `chroot()`-setup-failure case, and the real
fork/privilege-drop/dispatch-loop round trip) check root themselves and
print `SKIPPED (needs real root ...)` without failing the binary. Either
way, `make check`'s summary distinguishes `SKIP` from `FAIL` — a `SKIP`
here is expected and not a problem to chase down; a `FAIL` is.
`make check-valgrind`'s own driver (`test/Makefile.am`) honors the same
exit-77 convention `make check`'s automake-generated driver does, so a
binary that legitimately skips reports as skipped there too, rather than
aborting the whole `check-valgrind` run.

**Why CI itself doesn't run as root:** running a full CI pipeline with
real root is a larger blast radius (a bug in a test, or in whatever it
exercises, now runs unconfined) than the coverage gap skipping these few
root-only scenarios leaves — they are exercised locally, deliberately,
by a human running `sudo make check`/`sudo make check-valgrind`, or on a
runner set aside specifically for that purpose, not on every push. This
is the common shape for privilege-dependent test suites generally: default
CI runs unprivileged and treats "needs root" as a first-class `SKIP`
outcome (not a failure to route around), with full-privilege coverage
reserved for an explicit, separately-gated job or a manual run.

### `fakeroot` does not help here

`fakeroot` (and similar `LD_PRELOAD` shims) intercepts and fakes
*file-ownership* library calls (`chown()`, `stat()`, and friends) so
package-building tools can produce root-owned archive entries without
actually being root. It does not change the process's real, effective, or
saved uid at the kernel level, and does not grant `CAP_SETUID` or
`CAP_NET_BIND_SERVICE`. Since these tests need a genuine `seteuid()` to a
different account to succeed (and, for `privsep_bind()`'s authorized case,
a genuine `bind()` to a privileged port), `fakeroot` would not make any of
this pass — the tests would still hit real `EPERM`s from the kernel, just
with confusing extra layers involved. A Linux user namespace
(`unshare -U --map-root-user`, which grants real capabilities within the
namespace) would work as a local sandbox alternative to actually being
root, but is not something this project's build sets up or requires; real
root (or root-in-a-container, which is what CI already provides) remains
the straightforward option.

### Two tests skip under whole-program LTO

`test_admin_establish_sa_psk` and `test_getcertsbyname_helpers` each rely
on `-Wl,--wrap=` (of `vfree()`/`free()` respectively) to count allocator
calls the code under test makes. On a toolchain built with whole-program
LTO (`-flto=auto -ffat-lto-objects`, a `dpkg-buildflags` hardening default
as of Ubuntu 26.04 "Resolute") the compiler can inline or eliminate those
calls entirely before the linker ever gets a chance to redirect them --
both binaries detect this with a startup canary and report `SKIP` (exit
77) rather than a false `FAIL`. See
`doc/dev/wrap-based-tests-vs-lto.md` for the full mechanism and why a
build-time exclusion (this project's `SANITIZER_BUILD` precedent) wasn't
used instead.

## Reporting Issues

Please include:

- Operating system and version
- Racoon version or Git commit
- Configuration snippets relevant to the issue
- Log output with sensitive information removed
- Steps to reproduce the problem

## Submitting Changes

Please submit changes as GitHub pull requests.

Small, focused commits with clear commit messages are preferred.

## Branch Maintenance

### Tree-separation policy (`main` vs `develop`)

`main` and `develop` are two independent integration lines (`main`: the
GitHub CI/workflow location; `develop`: where day-to-day feature and test
work happens), not a small delta of each other — so some paths are
intentionally branch-specific and never cross between them:

- `.claude/` (Claude Code developer tooling) is `develop`-owned and must
  never appear on `main`.
- Each branch owns its own `.github/workflows/` *files* — not the
  directory as a whole, which legitimately exists on both. `develop`'s CI
  files (`develop-build-test.yml`, `guard-branch-purity.yml`,
  `legacy-cflags-canary.yml`, `racoon-hooks.yml`) and `main`'s
  (`build-test.yml`, `guard-tree-purity.yml`, `netbsd-build-test.yml`,
  `openssl-deprecation-canary.yml`) are named so their sets never collide
  on a shared path, and neither branch's set is meant to reach the other.
  `develop-build-test.yml` exists here — rather than `develop` just
  relying on `main`'s `build-test.yml` — because GitHub Actions only
  evaluates a workflow file that already exists on the branch an event
  targets: a `pull_request` event whose base is `develop` never even
  looks at `main`'s tree, no matter how `build-test.yml`'s triggers are
  scoped. That's a structural GitHub Actions constraint, not a
  convention, so it isn't something a future cleanup should try to
  collapse back into one file.
- `develop`-only test infrastructure (`test/expected-skips.yml`,
  `test/check-expected-skips.sh` — see "Two tests skip under
  whole-program LTO" above) stays off `main`.

**Automated, both directions:** `.github/workflows/guard-branch-purity.yml`
(this branch) rejects any PR or push into `develop` that touches a
`main`-owned path; `.github/workflows/guard-tree-purity.yml` on `main`
rejects the mirror direction. Both inspect the diff being introduced, not
just the final tree, and both fail the check (not just a warning) on a
violation. This replaced the previous manual instruction to run
`git diff --stat` by hand before merging `main` into `develop` — a step
that depended on remembering to run it and was never actually enforced.

## Security

Please do not attach executable files or binary patches (such as ZIP, APK,
EXE, or DLL files) to issues or pull requests.

Source code changes should be submitted as Git commits, pull requests,
or plain-text patches so they can be reviewed and tested.

## AI-Assisted Development

This project is maintained by a single maintainer.
Development, code review, and documentation are supported
by AI tooling (Claude by Anthropic / Claude Code).

Contributions and bug reports from human collaborators
are very welcome — see the issue tracker.
