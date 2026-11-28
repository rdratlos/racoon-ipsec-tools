# coi test-spec automation (slice 1: discovery, G1, G2)

Run on the workstation, from a scratch project directory (not a real repo):

    tools/coi-spec/run.sh discover   # records build + coi --help + schema; then calibrate adapter.sh
    tools/coi-spec/run.sh g1
    tools/coi-spec/run.sh g2
    tools/coi-spec/run.sh cleanup

Results: `results/<ID>.txt` in the spec's result-sheet format, `results/_summary.tsv`.
`adapter.sh` is the only file that knows coi's CLI; its non-interactive
`coi shell --profile P -- CMD` form is a GUESS (set COI_EXEC_TEMPLATE if wrong).
Table names in `tests/fixtures.sh` and g2.sh follow the spec; the schema wins.
Not automated here (need manual variants): G2.6, G2.7, G2.9, G2.5 as a second host user.
Self-test of the harness only (stubs, no coi semantics): see selftest/.
