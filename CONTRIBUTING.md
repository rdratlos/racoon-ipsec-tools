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
