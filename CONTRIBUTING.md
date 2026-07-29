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
side for real. `seteuid()` to a *different* account (not one the process
already held) needs `CAP_SETUID` — which only a process that started as
root has. There is no way around this: the whole point is testing what
happens when privilege is dropped, which requires having it to drop from.

**Run as root** (the containers/CI this project targets, or locally via
`sudo`) and every test runs and is asserted on — this is the only way to
get full coverage of these three binaries.

**Run as an ordinary user** and the two binaries where *every* case needs
root (`test_privsep_client_wrappers`, `test_privsep_hybrid_client_wrappers`)
detect that up front and report `SKIP` (exit code 77 — automake's own
convention for "this test doesn't apply here", distinct from a failure)
instead of failing. `test_privsep_init` is different: two of its three
scenarios (the `lcconf->uid == 0` no-op, and the missing-cert/script-path
refusal) don't touch privilege at all and always run; only its third
scenario (the real fork/privilege-drop/dispatch-loop round trip) checks
root itself and prints `SKIPPED (needs real root ...)` without failing the
binary. Either way, `make check`'s summary distinguishes `SKIP` from
`FAIL` — a `SKIP` here is expected and not a problem to chase down; a
`FAIL` is.

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

Some paths are intentionally branch-specific:

- `.github/` (CI workflows) lives on `main` only.
- `.claude/` (Claude Code developer tooling) lives on `develop` only.

**Manual step (not automated):** before merging `main` into `develop`,
run `git diff --stat` and confirm that **no `.github/` paths appear** in
the merge. If any do, back them out so `.github/` stays off `develop`.

```bash
git checkout develop
git merge --no-commit --no-ff main
git diff --stat --cached        # inspect: no .github/ paths should appear
```

There is no automated guard for this direction — the `.claude/`-on-`main`
guard is enforced in CI, but keeping `.github/` off `develop` is a manual
review responsibility at merge time.

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
