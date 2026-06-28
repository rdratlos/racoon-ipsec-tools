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
