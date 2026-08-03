# RFC 0004: Coverage Policy Domains ("covpaws")

## Status

Draft

## Authors

- Thomas (@rdratlos)

## Reviewers

- @rdratlos (decision)
- (open — reviewers welcome)

## Motivation

The current `genhtml` coverage report (`coverage_filtered.info` → `coverage/`)
applies one uniform pass/fail visualization to every file touched directly
or indirectly by the unit test suite. This does not reflect project policy:

- New and heavily modernized/extended code must hit **≥50% line / ≥75%
  function** coverage from unit tests.
- Nearly-untouched legacy code is validated primarily through use-case flow
  integration tests, not unit coverage, and should not be graded against
  the same bar.

Two concrete files currently at the center of active development —
`kernelpaws.c` (RFC-0002, PF_KEY→XFRM migration) and `resolvpaws.c`
(RFC-0003, async DNS resolution) — have branching logic (kernel vtable
dispatch, fd-driven resolver state machines) where line coverage alone is
a weak signal; branch coverage matters more for these two files than
project-wide.

Today classification of "new/modernized" vs "legacy" is implicit and
manual (informed by the author's judgement of what changed), and coverage
enforcement is not gated in CI — reports are generated ad hoc via `make
coverage`. This RFC proposes a reproducible classification pipeline, a
report structure that reflects the two-tier policy, and a CI gate on
`develop`.

The existing flat/mixed report is not being removed — it remains available
as a holistic view — this RFC adds policy-scoped reports alongside it.

## Goals

- Split coverage reporting into distinct **domains**: new/modernized code
  (unit-test gated) and legacy code (informational, integration-test
  covered).
- Track and report **branch coverage** specifically for `kernelpaws.c` and
  `resolvpaws.c`, in addition to line/function coverage.
- Provide **automatic, reproducible classification** of existing/modified
  files into "heavily modernized" vs "legacy" via `git diff` against a
  pinned baseline.
- Provide **manual classification** (a maintained manifest) for wholly new
  files, where diff-percentage heuristics don't apply.
- Configure genhtml limits correctly per coverage type (line/function/branch)
  where the installed lcov/genhtml supports it, with a fallback for older
  installations (Ubuntu Bionic).
- Add a **CI gate** enforcing the policy on the `develop` branch.

## Non-goals

- Retroactively writing unit tests for legacy code — that remains the
  domain of use-case/integration testing per existing policy.
- Mandating 100% coverage anywhere, or raising the 50%/75% thresholds.
- Solving PF_KEY-vs-XFRM dual-stack coverage — `kernelpaws.c` is covered
  here only as a branch-coverage example file, not as a scope item of
  RFC-0002 itself.
- Migrating coverage reporting off self-hosted GitHub Actions to a SaaS
  coverage service (see Alternatives).

## Current design

`make coverage` produces `coverage_filtered.info` (post `lcov --remove`
filtering of system/generated headers and Flex/Bison output), then:

```make
genhtml "coverage_filtered.info" \
    --output-directory "coverage" \
    --title $(COVERAGE_TITLE) \
    --legend \
    --rc genhtml_hi_limit=$(COVERAGE_HI_LIMIT) \
    --rc genhtml_med_limit=$(COVERAGE_MED_LIMIT);
```

This is a single scalar `hi`/`med` limit pair applied uniformly across
every file and every coverage type (line, function, branch — where branch
capture is even enabled, which it currently isn't by default). There is no
notion of "this file is new, this file is legacy" — the report colors
`admin.c` (0% coverage, attacker-adjacent, Tier 1 target) the same way it
colors an untouched 2003-era KAME code path that will never see a unit
test. Nothing in CI currently consumes this report to fail a build; it's
generated and reviewed manually.

## Proposed design

### 1. Classification pipeline (`scripts/coverage-classify.sh`)

Produces `coverage/classification/new-files.txt`, the union of two sources:

**a. Manual manifest** — `coverage/new-code-manifest.txt`, a plain
newline-delimited list of paths for files that are wholly new and thus
have no meaningful pre-existing baseline to diff against, e.g.:

```
src/racoon/kernelpaws.c
src/racoon/resolvpaws.c
src/racoon/openssl_compat.c
src/racoon/openssl_compat.h
src/racoon/privsep_priv.c
```

Checked into the repo, updated by hand as part of normal review (same
discipline as the existing Lessons-Learned register).

**b. Git-diff-derived list** — computed against a pinned baseline
reference, `COVERAGE_BASELINE_REF` (see Open Questions for what this
should point to). For every tracked `*.c`/`*.h` file not already in the
manual manifest:

```bash
changed=$(git diff --ignore-all-space --stat "$COVERAGE_BASELINE_REF" -- "$f" \
            | awk '{print $4+$6}')
total=$(wc -l < "$f")
pct=$(( changed * 100 / total ))
[ "$pct" -ge "$COVERAGE_MODERNIZED_THRESHOLD" ] && echo "$f"
```

`--ignore-all-space` avoids inflating the "heavily modernized" set with
pure reformatting/K&R-modernization commits. The threshold
(`COVERAGE_MODERNIZED_THRESHOLD`, proposed default 30%) is a Makefile
variable, tunable without touching the script.

### 2. Splitting the `.info` file

```make
lcov --extract  coverage_filtered.info $$(cat coverage/classification/new-files.txt) \
     -o coverage_new.info
lcov --remove   coverage_filtered.info $$(cat coverage/classification/new-files.txt) \
     -o coverage_legacy.info
```

### 3. Branch coverage for kernelpaws.c / resolvpaws.c

Branch coverage capture is enabled globally at `lcov --capture` time
(`--rc lcov_branch_coverage=1`) since gcov emits it regardless once
requested, but it is only **gated** for these two files — general branch
coverage on the rest of the "new" domain is reported informationally, not
enforced, since retrofitting meaningful branch coverage everywhere is a
larger and separate effort. A third split isolates them:

```make
lcov --extract coverage_new.info \
     'src/racoon/kernelpaws.c' 'src/racoon/resolvpaws.c' \
     -o coverage_branchwatch.info
```

### 4. Version-aware genhtml limits

Ubuntu Bionic ships an older genhtml (scalar `genhtml_hi_limit`/
`genhtml_med_limit` only); Ubuntu Resolute's lcov 2.x supports
type-specific limits. Makefile detects and branches:

```make
GENHTML_MAJOR := $(shell genhtml --version | grep -oP '\d+' | head -1)

ifeq ($(shell test $(GENHTML_MAJOR) -ge 2; echo $$?),0)
RC_OPTS = \
    --rc genhtml_line_hi_limit=$(COVERAGE_LINE_HI) \
    --rc genhtml_line_med_limit=$(COVERAGE_LINE_MED) \
    --rc genhtml_function_hi_limit=$(COVERAGE_FUNC_HI) \
    --rc genhtml_function_med_limit=$(COVERAGE_FUNC_MED) \
    --rc genhtml_branch_hi_limit=$(COVERAGE_BRANCH_HI) \
    --rc genhtml_branch_med_limit=$(COVERAGE_BRANCH_MED)
else
RC_OPTS = \
    --rc genhtml_hi_limit=$(COVERAGE_LINE_HI) \
    --rc genhtml_med_limit=$(COVERAGE_LINE_MED)
endif
```

Proposed defaults, distinct per domain:

| Domain             | Line hi/med | Function hi/med | Branch hi/med |
|---------------------|-------------|------------------|----------------|
| `coverage_new`      | 75 / 50     | 90 / 75          | n/a (informational) |
| `coverage_branchwatch` | 75 / 50  | 90 / 75          | 60 / 40 |
| `coverage_legacy`   | 90 / 60     | 90 / 60          | n/a |

(Legacy limits set loose/high — coloring there is only meant to flag
genuinely dead code, not to gate anything.)

### 5. Report layout

```
coverage/
  index.html          <- small hand-written/templated landing page, links below + policy summary
  new/                 <- coverage_new.info, gated
  branchwatch/          <- coverage_branchwatch.info, gated (kernelpaws.c, resolvpaws.c)
  legacy/               <- coverage_legacy.info, informational
  all/                  <- existing flat/mixed report, unchanged, kept as-is
```

### 6. CI gate (`scripts/coverage-gate.sh` + workflow)

New `coverage-gate.yml` GitHub Actions workflow, triggered on push/PR
**to `develop` only** (consistent with the existing convention that
CI-affecting config like `.claude/settings.json` lives on `develop`, not
`main`). Parses `lcov --summary` output for `coverage_new.info` and
`coverage_branchwatch.info`, exits non-zero on violation:

```bash
check() {
  local info=$1 metric=$2 threshold=$3
  local pct
  pct=$(lcov --summary "$info" 2>/dev/null \
        | awk -v m="$metric" '$0 ~ m {gsub("%","",$2); print $2; exit}')
  awk -v p="$pct" -v t="$threshold" 'BEGIN{exit !(p>=t)}' \
    || { echo "FAIL: $info $metric ${pct}% < ${threshold}%"; return 1; }
}

check coverage_new.info        lines     50 || fail=1
check coverage_new.info        functions 75 || fail=1
check coverage_branchwatch.info branches 40 || fail=1
[ -z "$fail" ]
```

## Alternatives considered

- **lcov diff/annotate (line-granularity classification against a unified
  diff)**: more precise than whole-file classification, but availability
  is version-dependent and Bionic's lcov is too old to rely on — would
  reintroduce the same cross-distro fragility already seen with the GCC
  diagnostic-format canary work. Deferred; revisit once Bionic support is
  dropped project-wide.
- **Single unified threshold with a manual per-file waiver list**:
  rejected — the policy explicitly differentiates unit-test vs
  integration-test-covered code by design, a waiver list would just be
  the manifest under a different name with worse auditability (waivers
  tend to accumulate silently; a positive "this file is new/modernized"
  list does not).
- **Third-party coverage SaaS (Codecov/Coveralls)**: rejected for now —
  adds an external dependency and account/token management for a project
  that otherwise runs entirely on self-hosted GitHub Actions workflows
  (openssl-deprecation-canary, legacy-cflags-canary); the self-contained
  script approach is consistent with existing tooling and keeps coverage
  data local to the repo.
- **Do nothing (keep single mixed report)**: keeps the report honest about
  raw numbers but makes it impossible to see policy compliance at a
  glance, and blocks any CI gating — was the status quo motivating this
  RFC.

## Compatibility

- No effect on IKEv1 wire behavior, `racoon.conf` semantics, or any
  runtime interface — this is build/CI tooling only.
- Requires a consistent lcov/genhtml version per CI runner image; Focal/
  Jammy/Noble runners should be checked for `lcov_branch_coverage`
  support the same way GCC diagnostic format was checked per-version.
- Not a breaking change for downstream packagers — coverage artifacts are
  not shipped in any package.

## Migration

No existing deployments are affected. For the repo itself:

1. Add `coverage/new-code-manifest.txt` seeded with the files listed
   under Proposed design §1a.
2. Pick and tag `COVERAGE_BASELINE_REF` (see Open Questions).
3. Land `scripts/coverage-classify.sh`, `scripts/coverage-gate.sh`, and
   the Makefile changes on `develop`.
4. Add `coverage-gate.yml` as a required check on `develop` once the
   first green run is confirmed manually (avoid flipping it to
   "required" blind).
5. `main` is untouched until the gate has run cleanly on `develop` for a
   full development cycle.

## Risks

- **Diff-heuristic misclassification**: high-churn-but-low-behavior-change
  commits (further K&R modernization passes, whitespace-sensitive
  reformatting) could inflate the "heavily modernized" set even with
  `--ignore-all-space`. Mitigation: periodic manual review of the
  generated classification list; the manifest takes precedence for
  human-reviewed edge cases.
- **Manifest staleness**: a genuinely new file is never added to the
  manifest and silently falls into the legacy/loose-limit domain.
  Mitigation: add a CI check that any file under known "new work"
  directories (e.g. anything touched in a PR whose branch is
  `claude/`-prefixed, per existing quarantine convention) not already
  present in either classification source fails the gate with an
  actionable message rather than silently passing.
- **Branch coverage capture overhead/flakiness**: enabling
  `lcov_branch_coverage=1` project-wide increases gcov instrumentation
  cost; if this proves flaky under the sanitizer-build matrix (ASan/UBSan,
  11/16 targets currently), branch capture may need to be restricted to a
  dedicated non-sanitizer coverage build.
- **CI gate false confidence**: a green gate on `coverage_new.info` says
  nothing about legacy code correctness — must be documented clearly on
  the report landing page so the legacy/informational report isn't
  mistaken for a quality signal.

## Open questions

- What should `COVERAGE_BASELINE_REF` be? Candidates: the `v0.9.0` tag
  (clean release point, but predates the autotools modernization and
  early `openssl_compat.c` work from Oct 2025–May 2026, which would then
  never register as "modernized" via diff); or the original KAME/
  ipsec-tools fork point (captures everything since divergence, but is a
  much larger and noisier diff surface). Leaning toward `v0.9.0` for
  simplicity and adding pre-v0.9.0 files to the manual manifest instead
  where warranted — open for review.
- Is 30% changed-lines the right "heavily modernized" threshold, or
  should it be lower (e.g. 15–20%) given how much of this codebase is
  intentionally style-only K&R cleanup rather than logic change?
- Should the branch coverage threshold for `kernelpaws.c`/`resolvpaws.c`
  (proposed 40% low / 60% high) be uniform, or does `resolvpaws.c`'s
  fd-driven state machine warrant a higher bar than `kernelpaws.c`'s
  vtable dispatch?
- Should `coverage-gate.yml` block merge (required status check) from
  day one, or run in report-only/annotate mode for one release cycle
  first to calibrate thresholds against real numbers?
- Does `coverage/legacy` need to run in CI at all, or is it sufficient as
  a `make coverage-legacy` local/manual target?

## Acceptance criteria

- [ ] `scripts/coverage-classify.sh` produces a deterministic, reviewable
      `new-files.txt` from manifest + git-diff heuristic given a pinned
      `COVERAGE_BASELINE_REF`.
- [ ] `make coverage` produces four report trees: `coverage/all`,
      `coverage/new`, `coverage/branchwatch`, `coverage/legacy`, each with
      correct domain-specific genhtml limits.
- [ ] genhtml invocation correctly falls back to scalar `hi_limit`/
      `med_limit` on lcov < 2.0 (Bionic) and uses type-specific limits on
      lcov ≥ 2.0 (Resolute), verified on both.
- [ ] `kernelpaws.c` and `resolvpaws.c` branch coverage is captured and
      reported, with the gate threshold from Open Questions resolved and
      encoded in `scripts/coverage-gate.sh`.
- [ ] `coverage-gate.yml` runs on push/PR to `develop`, fails the build
      on policy violation in `coverage_new.info`/`coverage_branchwatch.info`,
      and does not run on `main`.
- [ ] `coverage/index.html` landing page clearly labels which reports are
      gated (policy-enforced) vs informational.
