# Terminology pass: "phase1-up/phase1-down scripts" leads, "hooks" demoted

Records the `grep -rn -i 'hook'` worklist this pass was built from and the disposition
of every hit, per the maintainer's brief: lead user-facing prose (man pages, `--help`
text, the Admin Guide) with "the phase1-up/phase1-down scripts," introduce "(also
called hooks)" once per document at first mention, and leave "hook" exactly as-is in
code identifiers, file names, and developer-facing documentation.

Bucket key: **(a)** prose rewritten to lead with "scripts" · **(b)** filename/identifier
correctly left alone · **(c)** config key correctly left alone · **(d)** ambiguous,
flagged for the maintainer rather than guessed at.

## doc/admin/split-dns.html

The primary document most operators will read; given the most careful pass.

- `<title>`, `<h1>` — (a) "...Routing Hooks" → "...Routing Scripts".
- Header intro paragraph — (a) added "(also called hooks)" at the first mention of
  `phase1-up.sh`/`phase1-down.sh` — the one and only place this document introduces
  the synonym.
- §1 Overview bullets (4 sentences) — (a) "the hooks" → "the scripts" throughout,
  including a subject-verb agreement fix ("The hook installs... records... tears"
  → "The scripts install... record... tear"); one bullet renamed to `phase1-up.sh`
  directly since it's specifically that script's own refusal behavior.
- §2 Installation — (a) "The hook scripts are..." → "These scripts are...";
  "Point racoon at the hooks..." → "Point racoon at phase1-up.sh/phase1-down.sh...";
  the installed-files code block's own comments ("# racoon phase1-up hook" /
  "# racoon phase1-down hook") → "# racoon phase1-up script" / "# ...down script".
- §3 Configuration — (a) opening sentence restructured to name `phase1-up.sh`/
  `phase1-down.sh` as the readers of `hooks.conf`, per the rule that the first real
  mention of the filename should explain what it configures; "let the hook detect
  one" → "let phase1-up.sh detect one" (backend detection is specifically its job,
  not phase1-down.sh's); "a hook's exit code" → "phase1-up.sh's exit code".
- §4 Backends — (a) three instances of "the hook reports/says" → named `phase1-up.sh`
  directly (all three describe its plan-building behavior specifically); "this hook
  set" → "these scripts".
- §5 Diagnosing — (a) "what would the hooks do" → "what would phase1-up.sh do"
  (`racoon-dns-detect --dry-run` previews phase1-up.sh's plan specifically, per its
  own man page — more precise, not just a synonym swap).
- §6 State — (a) "out of scope for the hooks themselves" → "...the scripts
  themselves".
- §8 Troubleshooting — (a) "The hook reports this" → "phase1-up.sh reports this";
  "not a bug in the hook" → "...in the scripts".
- Footer — (a) "these hooks are held to" → named `phase1-up.sh`/`phase1-down.sh`.
- `hooks.conf` (filename, ToC + prose), `RACOON_HOOK_DEBUG`/`RHOOK_HOOK_DEBUG`,
  `racoon-hook-lib.sh`, `/run/racoon/hook-state.*`, `/run/racoon/hook.trace`,
  `tests/hooks/` — (b), left exactly as-is; these are real file/path/env-var names,
  not the generic word being demoted.

## src/racoon/scripts/racoon-dns-detect.8

- NAME (`.Nd`) — (a) "the split-DNS/routing hooks'" → "...scripts'".
- DESCRIPTION intro — (a) restructured as the parenthetical-synonym sentence (first,
  and only, mention in this document): "the phase1-up.sh/phase1-down.sh scripts (also
  called hooks) and their shared library, racoon-hook-lib.sh"; two further "the hooks
  would select/conclude" → named `phase1-up.sh` directly (backend classification and
  plan preview are specifically its behavior).
- SEE ALSO / HISTORY — (a) "the split-DNS/routing hooks admin guide" and "the
  split-DNS/routing hook set" → "...scripts...", matching the Admin Guide's own
  renamed title.
- `racoon-hook-lib.sh`, `hooks.conf` (FILES section) — (b), left as-is.

Validated with `mandoc -T lint` and `-T ascii` after editing; only pre-existing
"referenced manual not found" style noise (same baseline as before this pass).

## src/racoon/scripts/racoon-dns-detect (the script itself)

Checked `rd_usage()`'s `--help` heredoc and the header usage-comment block first, per
the brief's instruction (in case a separate hand-edit was already in flight): neither
uses the word "hook" anywhere in its user-facing text already — the `--help` output
names `phase1-up.sh`/`phase1-down.sh`/backend/DNS concepts directly and never says
"hook." **No change needed or made to this file.**

## src/racoon/racoon.8

- FILES entry for `/etc/racoon/scripts` — (a), added during this project's split-DNS
  work (commit `53a8f53`): "phase1_up/phase1_down hook scripts" → "...scripts (also
  called hooks)... their configuration file, hooks.conf" (also applies rule 3's
  "explain hooks.conf at first mention," which the original phrasing skipped).

## src/racoon/racoon.conf.5 -- (d) ambiguous, NOT edited, flagged for the maintainer

Three hits, all pre-existing upstream text (confirmed via `git log -S`, all trace to
`c6f91f0 Imported Upstream version 0.8.0`, predating this project's whole split-DNS
feature and never touched by any commit of this work):

- Line 137: "...launching hook scripts, and validating passwords..." (privilege
  separation section)
- Line 173: "The PSK file, the private keys, and the hook scripts are accessed
  through the privileged instance..."
- Line 219: "will search this directory for scripts hooks." (`path script` directive)

These describe racoon's own **generic** `script "..." phase1_up/phase1_down/phase1_dead;`
mechanism -- a broader, pre-existing racoon feature that any script can be wired into,
not specifically the phase1-up.sh/phase1-down.sh pair this project ships. Renaming
"hook scripts" to "phase1-up/phase1-down scripts" here would be actively wrong (it
would narrow a general-purpose config directive's documentation to name two specific
scripts), and rewording to something else is a separate editorial decision this brief
didn't ask for. Left untouched rather than guessed at.

The already-correct paragraph just below (line ~703-712, this project's own addition
in commit `53a8f53`) already leads with "phase1_up/phase1_down script pair" and never
says "hook" at all -- no change needed there.

## Elsewhere: user-visible log/report strings in the scripts themselves

Out of scope for renaming the scripts/library themselves, but their *printed* output
is read by the same operator audience this pass is for. Found and fixed:

- `racoon-hook-lib.sh`: "racoon does not reject a tunnel based on a hook's exit
  status" (an `on_dns_failure=abort` deprecation warning) → "...the script's exit
  status".
- `racoon-hook-lib.sh`, `rhook_ensure_dummy_iface()`: "...is not a dummy-type
  interface this hook set created" → "...phase1-up.sh created".
- `racoon-hook-lib.sh`, same function's reuse warning: "see the Admin Guide's
  Split-DNS & Routing Hooks section" → "...Routing Scripts section" -- this one
  wasn't optional-but-nicer, it was about to go stale the moment the Admin Guide's
  own `<h1>` changed in this same pass.
- `RHOOK_HOOK_NAME:-hook` fallback (4 sites: the syslog tag, the report header line
  x2, the summary syslog line) — `${RHOOK_HOOK_NAME:-script}`. In normal operation
  `RHOOK_HOOK_NAME` is always set to `phase1-up`/`phase1-down.sh` by the scripts
  themselves, so this fallback almost never actually surfaces -- fixed anyway since
  it's the one place the literal word could still reach an operator's terminal.

Not touched, deliberately: `racoon-hook-lib.sh`/`phase1-up.sh`/`phase1-down.sh`'s own
internal comments (developer-facing regardless of which file they live in, per the
brief), `RHOOK_HOOK_NAME`/`RACOON_HOOK_LOGGER`/`rhook_*`/`RHOOK_*` identifiers
throughout (code, stays exactly as-is), and `tools/racoon-hook-integration-test.sh`
(not in this pass's stated scope -- a developer/tester tool, not admin-facing prose).

## Positioning check (re-read before finishing, per the brief)

No comparison to strongSwan/Libreswan/other IPsec implementations was added or
touched by this pass; none of the edited sentences characterize any other project.
The word "Swans" does not appear anywhere in the diff.
