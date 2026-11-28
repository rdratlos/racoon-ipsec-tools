# coi test-spec automation (slice 1: discovery, G1, G2)

Run on the workstation, from a scratch project directory (not a real repo):

    tools/coi-spec/run.sh discover   # records build + coi --help + schema; then calibrate adapter.sh
    tools/coi-spec/run.sh g1
    tools/coi-spec/run.sh g2
    tools/coi-spec/run.sh cleanup

Results: `results/<ID>.txt` in the spec's result-sheet format, `results/_summary.tsv`.
`adapter.sh` is the only file that knows coi's CLI. It uses `coi run --profile P -- CMD`
(from `coi --help`); whether `coi run` reuses a persistent container and which slot it
takes is still unverified (G1.2 records `coi list`). Override with COI_EXEC_TEMPLATE.

Calibrated from the discovery output (`coi schema profile`):
- `persistent` and `session_name` are under `[container]`; `session_name` is trusted-scope only.
- `env_commands` is a top-level table, trusted-scope only (not `[defaults.env_commands]`).
- `[[mounts]]` and `[[mounts.default]]` are both accepted (answers G2.7 by schema); entries
  have `host`, `container`, `readonly`, `shift`. `coi trust` approves out-of-workspace
  mounts from a project config.
- Sessions use slots (`--slot`); this may mean one container per slot, not per profile.
Not automated here (need manual variants): G2.6, G2.7, G2.9, G2.5 as a second host user.
Self-test of the harness only (stubs, no coi semantics): see selftest/.
