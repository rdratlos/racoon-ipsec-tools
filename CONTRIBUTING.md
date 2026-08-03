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

## Architecture Changes: the RFC Workflow

Significant architectural changes go through a lightweight **RFC** (Request
for Comments) process so that design decisions are reviewed in the open and
recorded permanently in Git history. The full rules live in
[`docs/rfcs/README.md`](docs/rfcs/README.md); the end-to-end flow is:

```
Idea
  └─▶ Discussion            (GitHub Issue / discussion)
        └─▶ RFC Pull Request  (docs/rfcs/NNNN-*.md, reviewed publicly)
              └─▶ Merge         (RFC Accepted — decision is now permanent)
                    └─▶ Implementation Issue(s)   (reference the RFC)
                          └─▶ Implementation Pull Request(s)
                                └─▶ Release
```

In short:

1. **Idea** — you have a change in mind. If it is a bug fix, portability
   fix, docs, or a small improvement, skip straight to a pull request; no
   RFC is needed.
2. **Discussion** — for anything larger (protocol/on-wire behaviour,
   `racoon.conf` surface, cryptography, `libipsec`/CLI interfaces, build or
   packaging structure), open an Issue to discuss the problem first.
3. **RFC Pull Request** — copy
   [`docs/rfcs/0000-template.md`](docs/rfcs/0000-template.md) to
   `docs/rfcs/NNNN-short-title.md`, fill it in, and open a pull request.
   Open it early as a **Draft** to invite comments — external reviewers and
   domain experts are welcome.
4. **Merge** — when the maintainer accepts the design, the RFC PR is merged
   into the default development branch. The merge is the record of the
   decision. (Draft RFCs are developed in ordinary feature branches; there
   is no separate design branch.)
5. **Implementation Issue(s)** — accepted RFCs are broken into concrete
   tasks using the
   [implementation issue template](.github/ISSUE_TEMPLATE/implementation.md),
   each referencing the RFC number.
6. **Implementation Pull Request(s)** — code changes reference the RFC
   (the PR template has an *"Implements RFC ####"* checkbox). Design review
   is thus kept separate from implementation review.
7. **Release** — merged, tested work ships in a release.

Not sure whether your change needs an RFC? Open an Issue and ask, or just
open a Draft RFC — it is cheap, and the discussion will tell you.

## Branch Maintenance

### Tree-separation policy (`main` vs `develop`)

`main` and `develop` are two independent integration lines (`main`: the
GitHub CI/workflow location; `develop`: where day-to-day feature and test
work happens), not a small delta of each other — so some paths are
intentionally branch-specific and never cross between them:

- `.claude/` (Claude Code developer tooling) is `develop`-owned and must
  never appear on `main`.
- Each branch owns its own `.github/workflows/` *files* — not the
  directory as a whole, which legitimately exists on both. `main`'s CI
  files (`build-test.yml`, `guard-tree-purity.yml`,
  `netbsd-build-test.yml`, `openssl-deprecation-canary.yml`) and
  `develop`'s (`develop-build-test.yml`, `develop-netbsd-build-test.yml`,
  `guard-branch-purity.yml`, `legacy-cflags-canary.yml`,
  `racoon-hooks.yml`) are named so their sets
  never collide on a shared path, and neither branch's set is meant to
  reach the other. (This is why `develop` runs its own build-and-test
  workflow rather than `main`'s `build-test.yml` reaching across branches
  to cover it — see `develop`'s `CONTRIBUTING.md` for why that split is
  structural, not just convention: GitHub Actions only evaluates a
  workflow file that already exists on the branch an event targets.)
- `develop`-only test infrastructure (`test/expected-skips.yml`,
  `test/check-expected-skips.sh`) stays off `main`.

**Automated, both directions:** `.github/workflows/guard-tree-purity.yml`
(this branch) rejects any PR or push into `main` that touches a
`develop`-owned path; `.github/workflows/guard-branch-purity.yml` on
`develop` rejects the mirror direction. Both inspect the diff being
introduced, not just the final tree, and both fail the check (not just a
warning) on a violation. This replaced a manual `git diff --stat`
inspection step that relied on remembering to run it before merging.

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
