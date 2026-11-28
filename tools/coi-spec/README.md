# coi test-spec automation (slice 1: discovery, G1, G2)

Run on the workstation, from a scratch project directory (not a real repo):

    tools/coi-spec/run.sh discover   # records build + coi --help + schema; then calibrate adapter.sh
    tools/coi-spec/run.sh g1
    tools/coi-spec/run.sh g2
    tools/coi-spec/run.sh cleanup

**Before g1/g2:** `run.sh discover` must show no uid/gid warning. On the first discovery run
`coi health` failed with "Not enough uid/gid available for the container" (four times), so a
new container could not be created while the existing `coi-7abad93b-1` is present. Read
`results/discovery/idmap.txt` first. Tests only use containers that are not in
`results/_baseline_containers`; existing containers are never touched or deleted.
`coi run` stops (does not delete) a persistent container after each command, so
`incus_exec` steps only work while a container is running; they report that otherwise.

**uid/gid evidence (2nd discovery):** root has one usable subuid/subgid block (`root:100000:65536`)
shared by all existing containers; `coi health` still failed to create containers. Do not run g1/g2
until `coi health` shows no "Not enough uid/gid". Confirmation check (creates and deletes only `t-probe`):
`incus launch images:alpine/edge t-probe` (shared range, expected to work) and
`incus launch images:alpine/edge t-probe2 -c security.idmap.isolated=true` (expected to show the same error if
coi asks for an exclusive range); then `incus delete -f t-probe t-probe2`.

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
