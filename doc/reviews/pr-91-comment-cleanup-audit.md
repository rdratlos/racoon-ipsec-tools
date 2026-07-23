# Comment & Log Message Cleanup Audit
**Repository:** racoon-ipsec-tools  
**Files Audited:** `racoon-hook-lib.sh`, `phase1-up.sh`, `phase1-down.sh`, `racoon-dns-detect`, `hooks.conf.sample`  
**Date:** 2025-07-23  
**Status:** Planning phase — no edits applied

---

## Summary

| Category | Items | Action |
|----------|-------|--------|
| Historical narrative → technical rationale | 18 | Trim, keep only verified technical reasoning |
| Internal jargon in user-facing text | 10 | Replace `rhook_*`, `survey/plan/apply`, `§X`, `Rn`, `F1/F4`, "Bionic" with plain English |
| Debugging/testing artifacts | 6 | Remove entirely |
| Admin help text jargon | 4 | Simplify to user-friendly language |
| **Already clean (keep as-is)** | 4 | — |

**Total actionable items: 38**

---

## Category 1: Historical Narrative → Technical Rationale (18 items)

| File | Lines | Key Issue |
|------|-------|-----------|
| `racoon-hook-lib.sh` | 15–16 | `§E`, `R2'`, `brief 1's R2`, "engagement history" phrasing |
| `racoon-hook-lib.sh` | 115–122 | "Found live (Ubuntu Bionic roadwarrior, no reboot between test runs)", trace logs |
| `racoon-hook-lib.sh` | 1490–1491 | `§0 rule 5 hard-won detail preserved verbatim in spirit` |
| `racoon-hook-lib.sh` | 1511–1512 | `§7`, "survey" jargon |
| `racoon-hook-lib.sh` | 1540–1547 | `§K`, `brief 3` references |
| `racoon-hook-lib.sh` | 1554–1578 | `§K`, "Xubuntu Bionic 32-bit — a supported target", "previous version assumed `resctl`", "fixed here" |
| `racoon-hook-lib.sh` | 1742–1775 | "§6 point 6", "confirmed, previously-live bug", "reported by users as 'the VPN killed my internet'" |
| `racoon-hook-lib.sh` | 1849–1852 | `UNVERIFIED` block with NEWS file audit history |
| `racoon-hook-lib.sh` | 2007–2019 | `F3 (brief 3)`, `F4 reconnect loop`, "fixed by branching" |
| `racoon-hook-lib.sh` | 2212–2255 | "Found live (Ubuntu Bionic roadwarrior, no reboot between test runs)", trace logs |
| `racoon-hook-lib.sh` | 2353–2395 | "Found live (Ubuntu Bionic and Arch/Manjaro roadwarriors)", "Brief 1's own history", trade-off narrative |
| `racoon-hook-lib.sh` | 2487–2500 | "Found live on Ubuntu Bionic (NetworkManager 1.10.6)", source file audit trail |
| `phase1-up.sh` | 18–30 | `R2' (brief 3 §E, superseding brief 1's R2)`, `F1/F4 reconnect loop`, `grep -r` audit trail |
| `phase1-up.sh` | 66–79 | `§E`, "single highest-severity injection vector", validation detail with C source references |
| `phase1-up.sh` | 99–110 | `§3.4/brief-3 §D`, `FIFO matching`, "deliberate:", "reap step" |
| `phase1-up.sh` | 128–143 | `§4 / R3`, `isakmp_cfg_iplist_to_str()`, `splitnet_list_2str()`, C source audit details |
| `phase1-up.sh` | 215–220 | `§3.2/§3.3/§5.3`, "journals each successful step's undo command" |
| `phase1-up.sh` | 230–250 | `§H`, `script_hook()`, `privsep_script_exec()`, three-choice policy breakdown |

---

## Category 2: Internal Jargon → Plain English (10 items)

| File | Lines | Jargon to Replace |
|------|-------|-------------------|
| `racoon-hook-lib.sh` | 245 | `rhook_state_reset()`, `RHOOK_STATE_GENERATION` |
| `racoon-hook-lib.sh` | 276–280 | "live (not yet consumed) generation", "phase1-down.sh to undo" |
| `racoon-hook-lib.sh` | 282–291 | "generation", `mkdir lock`, "phase1-up runs racing", "wedging", "hook problem must never block a real VPN connection" |
| `racoon-hook-lib.sh` | 319–329 | "oldest (lowest generation number)", `mtime`, `ls`, "FIFO matching", "orphaned generation", `rhook_state_own_generation()` |
| `racoon-hook-lib.sh` | 1488–1501 | `RcManager`, `Mode`, `busctl get-property`, `dbus-daemon`, `systemctl is-active` |
| `racoon-hook-lib.sh` | 1530–1547 | `§K`, "DNS handler", `auto-manages`, `udev/unmanaged-devices=`, `dummy interface`, `bookkeeping` |
| `racoon-hook-lib.sh` | 1877–1886 | `survey`, `classify`, `hooks.conf`, `auto`, `override` |
| `racoon-hook-lib.sh` | 1946–1953 | `dns=`, `D-Bus Mode property`, `--print-config`, `compiled-in distro default`, `union both` |
| `racoon-hook-lib.sh` | 2326–2336 | `auto-manage`, `unmanaged-devices=`, `bookkeeping`, `nmcli device delete`, `fallback` |
| `phase1-up.sh` | 215–220 | `rhook_build_plan()`, `rhook_apply_plan()`, `journals`, `state file`, `phase1-down.sh`, `re-derive` |

---

## Category 3: Debugging/Testing Artifacts — Remove Entirely (6 items)

| File | Lines | Content |
|------|-------|---------|
| `racoon-hook-lib.sh` | 1562–1568 | Xubuntu Bionic 32-bit, `resctl` fallback, "silently no-op'd", "fixed here" |
| `racoon-hook-lib.sh` | 1849–1852 | `UNVERIFIED: exact byte-for-byte table layout`, `NEWS file across v234-v260`, "rendering-format rewrite" |
| `racoon-hook-lib.sh` | 2007–2019 | `F3 (brief 3)`, `F4 reconnect loop`, "confirmed live", "fixed by branching" |
| `racoon-hook-lib.sh` | 2487–2500 | "Found live on Ubuntu Bionic", `NM_SETTING_IP6_CONFIG_METHOD_DISABLED`, source file audit |
| `phase1-up.sh` | 18–30 | Full historical narrative with `grep -r` audit trail |
| `phase1-up.sh` | 66–79 | Full injection-vector narrative with C source references |

---

## Category 4: Admin Help Text — Simplify (4 items)

| File | Lines | Current → Proposed |
|------|-------|---------------------|
| `racoon-dns-detect` | 23–24 | "Survey, classify, and dry-run the split-DNS & routing hooks..." → "Dry-run the split-DNS & routing hooks to show what they would do." |
| `racoon-dns-detect` | 35–36 | "Detects the DNS resolver backend..., runs the survey/classify logic, builds the plan..." → "Detects DNS resolver backend, runs survey/classify logic, builds the plan phase1-up.sh would execute, and prints it read-only. No system changes." |
| `racoon-dns-detect` | 42–43 | "Implied and locked on: this tool never applies changes (the survey/plan/apply pipeline runs through 'plan' only)." → "Implied: this tool never applies changes (runs through plan phase only)." |
| `racoon-dns-detect` | 55–56 | "The 'survey' is the read-only data collection phase..." → "Survey = read-only data collection; Plan = pure construction (no changes); Apply = execution (phase1-up.sh only). This tool stops at Plan." |

---

## Category 5: Already Clean — No Changes (4 items)

| File | Lines | Note |
|------|-------|------|
| `hooks.conf.sample` | 15–37 | Backend config with clear user-facing explanations |
| `hooks.conf.sample` | 40–73 | `on_dns_failure` with plain-English policy descriptions |
| `hooks.conf.sample` | 76–88 | `debug_level` with clear level names |
| `hooks.conf.sample` | 91–121 | `dummy_iface`, `allow_resolv_conf_overwrite` with rationale |

---

## Execution Plan

1. **Create backup** of all 5 files before editing
2. **Edit `racoon-hook-lib.sh`** — 24 edits (Categories 1–3)
3. **Edit `phase1-up.sh`** — 6 edits (Categories 1–3)
4. **Edit `phase1-down.sh`** — 0 edits (no actionable items found)
5. **Edit `racoon-dns-detect`** — 4 edits (Category 4)
6. **Verify `hooks.conf.sample`** — no edits needed
7. **Run lint/syntax check** on all modified shell scripts
8. **Verify no functional changes** via `diff -u` against backups

---

## Clarifying Questions

1. **Category 2 items**: Some `rhook_*` function references appear in comments explaining *internal* logic (not user-facing logs). Should these be:
   - (a) Kept as-is (technical reference for maintainers)
   - (b) Replaced with generic terms ("state generation", "survey function")
   - (c) Removed entirely

2. **`phase1-down.sh`**: No actionable items found. Confirm no edits needed?

3. **Verification**: Should I run the project's test suite (if any) or just shell syntax checks (`bash -n`)?

4. **Output format**: This audit as Markdown (created). Want a machine-readable JSON version too?