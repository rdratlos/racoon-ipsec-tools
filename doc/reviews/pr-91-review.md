# PR #91 Formal Code Review Report
## Split-DNS/Routing Hooks for Racoon Roadwarrior Connections

**PR:** #91  
**Target Branch:** `develop`  
**Repository:** `rdratlos/racoon-ipsec-tools`  
**Review Date:** 2026-07-23  
**Reviewer:** OpenCode Assistant  

---

## Executive Summary

PR #91 introduces a comprehensive hook system for managing split-DNS and routing configuration during Racoon IKEv1 roadwarrior connections. The implementation addresses Issue #90 (orphaned session teardown) and introduces SPD ownership to prevent traffic leakage.

**Overall Assessment:** **APPROVE WITH CONDITIONS** — Strong architecture with good separation of concerns, but several pre-merge items need resolution.

---

## Architecture Review

### Core Design (✅ Strong)

| Component | Purpose | Assessment |
|-----------|---------|------------|
| `racoon-hook-lib.sh` | Shared library: backend detection, DNS tool probing, plan generation, apply/undo state machine | ✅ Well-structured, single source of truth |
| `phase1-up.sh` | Thin wrapper: validates Mode Config input, exports env, calls `rhook_plan_apply` | ✅ Minimal, correct delegation |
| `phase1-down.sh` | Thin wrapper: reads session cookie, calls `rhook_plan_undo` | ✅ Correct replay-only undo |
| `racoon-dns-detect` | Admin CLI for dry-run preview and diagnostics | ✅ Useful operational tool |
| C integrations (`isakmp.c`, `isakmp_unity.c`, `isakmp_cfg.c`) | Export `IKE_COOKIE`, `INTERNAL_SPLITDNS_DOMAINS` | ✅ Minimal, focused changes |

### Key Architectural Decisions (✅ Validated)

1. **Feature probing over version gating** — Backend classification (`rhook_survey_classify_backend`) and DNS tool detection (`rhook_dns_tool_detect`) use capability detection, not version checks. Correct approach.

2. **State machine with undo journal** — `phase1-up.sh` writes plan + undo journal; `phase1-down.sh` replays journal exactly. Eliminates config re-derivation bugs.

3. **SPD ownership** — Hooks install/own SPD entries via `setkey`. Prevents `ACQUIRE` storms and F1/F4 reconnect loops from split-include routes.

4. **IKE cookie exact-match** (Issue #90 fix) — Session token changed from oldest-generation to exact `IKE_COOKIE` (initiator:responder hex pair). Sidecar `.cookie` file enables precise teardown.

5. **DNS-group transactional rollback** — In-transaction rollback for DNS steps only; failed required step triggers reverse-order undo of applied DNS steps.

---

## Security Review

### SPD Leakage Prevention (✅ Addressed)
- Hooks install SPD entries for split-include networks before traffic flows
- SPD entries removed on teardown via undo journal
- **Risk:** If `phase1-up.sh` crashes mid-apply, SPD entries may leak. **Mitigation:** Transactional rollback in `rhook_plan_apply` handles DNS steps; SPD steps need same treatment.

### IKE Cookie Exposure (✅ Acceptable)
- `IKE_COOKIE` exported as hex initiator:responder pair
- Only used for session matching in hook scripts
- No sensitive key material exposed

### Privilege Separation (⚠️ Review Needed)
- Hooks run as root (required for `setkey`, `resolvectl`, `ip route`)
- `racoon-dns-detect` also requires root for backend surveys
- **Recommendation:** Document privilege requirements; consider capability-based restriction

---

## Correctness Review

### Issue #90 Fix Validation (✅ Correct)
**Old logic:** `phase1-down.sh` picked oldest generation file → matched orphaned sessions
**New logic:** 
1. `isakmp.c` exports `IKE_COOKIE` in `script_hook()`
2. `phase1-up.sh` writes `.cookie` sidecar with exact cookie
3. `phase1-down.sh` reads cookie, finds matching session directory
4. Exact hex string match prevents orphan pickup

### DNS Backend Classification (✅ Comprehensive)
```
Backend Priority: systemd-resolved > NetworkManager > resolvconf > dnsmasq > static > none
Tool Priority:    resolvectl > systemd-resolve > networkmanager > resolvconf > dnsmasq > fallback
```
All 6 backends handled with feature probes. Fallback to `/etc/resolv.conf` edit as last resort.

### Route Scoping (✅ Correct)
- Only `systemd-resolved` supports per-link default routes via `resolvectl`/`systemd-resolve`
- Other backends: global default route or no default route
- Dummy interface owner: `nm` if NetworkManager active, else `iproute`

### Configuration Validation (✅ Present)
`rhook_validate_config()` in `phase1-up.sh` validates:
- `INTERNAL_IP4_ADDRESS` (required)
- `INTERNAL_SPLITDNS_DOMAINS` format (optional, space-separated)
- `UNITY_SPLITDNS_NAME` → `INTERNAL_SPLITDNS_DOMAINS` mapping verified

---

## Testing Review

### Test Coverage (⚠️ Gaps Identified)

| Test File | Coverage | Gaps |
|-----------|----------|------|
| `test-phase1-roundtrip.sh` | End-to-end up/down cycle | No multi-backend matrix, no concurrent sessions |
| `test-dns-detect-cli.sh` | Admin CLI dry-run | Missing error condition tests |
| `test-plan-builder.sh` | Plan generation | Limited domain/route permutations |
| `test-survey-fixtures.sh` | 15 survey scenarios | Fixtures cover backends but not dynamic changes |
| `test-lib-smoke.sh` | Library function smoke | Minimal edge cases |

**Missing Test Scenarios:**
1. Concurrent roadwarrior sessions (multiple cookies)
2. Backend transition during active session (e.g., NM → systemd-resolved)
3. Partial apply failure → rollback verification
4. SPD leakage under crash conditions
5. IPv6 split-DNS/routes (currently IPv4-only)
6. Malformed `INTERNAL_SPLITDNS_DOMAINS` input fuzzing

### Fixtures (✅ Good)
15 survey fixtures in `tests/hooks/fixtures/` covering backend combinations. Well-structured.

---

## CI/CD Review

### Current Workflow (✅ Baseline)
`.github/workflows/racoon-hooks.yml` runs:
- `shellcheck` on all hook scripts
- Test suite execution for `tests/hooks/`

### Gaps (⚠️ Needs Enhancement)
1. **No integration test** with actual Racoon daemon
2. **No matrix testing** across distros (systemd-resolved vs NM vs resolvconf)
3. **No rootless test mode** for CI (currently requires root)
4. **No performance benchmark** for hook latency

---

## Documentation Review

### ARCHITECTURE.md (✅ Comprehensive)
Covers hook flow, backend detection, state machine, SPD ownership, rollback semantics. Good reference.

### hooks.conf.sample (✅ Complete)
All configuration options documented with examples.

### Inline Comments (✅ Adequate)
Key functions in `racoon-hook-lib.sh` have header comments explaining purpose, args, return codes.

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| SPD leak on mid-apply crash | Medium | High (traffic leakage) | Extend transactional rollback to SPD steps |
| Concurrent session cookie collision | Low | High (wrong teardown) | Cookie is ISAKMP cookie pair — cryptographically unique |
| Backend detection race | Low | Medium (wrong DNS config) | Survey runs at apply time, not cached |
| IPv6 unsupported | Medium | Medium (feature gap) | Document limitation; track as follow-up |
| Root privilege escalation | Low | High | Document; consider `CAP_NET_ADMIN` + `CAP_DAC_OVERRIDE` |

---

## Pre-Merge Checklist

### 🔴 Critical (Must Fix Before Merge)

- [ ] **Extend transactional rollback to SPD steps** in `rhook_plan_apply` — Currently only DNS-group steps roll back. If SPD install fails mid-sequence, earlier SPD entries remain. Add SPD steps to rollback journal.

- [ ] **Add IPv6 support** or explicitly document as IPv4-only — `INTERNAL_IP4_ADDRESS` used throughout; no `INTERNAL_IP6_ADDRESS` handling. At minimum, add TODO comments and validation.

- [ ] **Fix shellcheck warnings** — Run `shellcheck` locally and resolve all warnings before merge. CI will fail otherwise.

- [ ] **Validate `INTERNAL_SPLITDNS_DOMAINS` parsing** — Current split on space may break with malformed input. Add input sanitization in `phase1-up.sh`.

### 🟡 High Priority (Should Fix Before Merge)

- [ ] **Add concurrent session test** to `test-phase1-roundtrip.sh` — Simulate 2+ simultaneous roadwarriors with different cookies; verify correct teardown isolation.

- [ ] **Add partial failure rollback test** — Mock DNS tool failure at step N; verify steps 1..N-1 rolled back in reverse order.

- [ ] **Document privilege requirements** in `ARCHITECTURE.md` and `hooks.conf.sample` — List required capabilities for each backend.

- [ ] **Add SPD cleanup verification** in `phase1-down.sh` — After undo, verify no orphaned SPD entries remain via `setkey -D`.

### 🟢 Medium Priority (Follow-up Issues)

- [ ] **Create CI matrix** for Ubuntu (systemd-resolved), Fedora (NetworkManager), Debian (resolvconf) — Use Docker images in workflow.

- [ ] **Add rootless test mode** — Mock `setkey`, `resolvectl`, `ip` for CI without root.

- [ ] **Add IPv6 split-DNS support** — Parse `INTERNAL_IP6_ADDRESS` and `INTERNAL_SPLITDNS_DOMAINS` for IPv6.

- [ ] **Add fuzz test** for malformed `INTERNAL_SPLITDNS_DOMAINS` — Empty, trailing spaces, special chars, very long domains.

- [ ] **Performance benchmark** — Measure hook latency (target < 500ms for apply+undo).

### 🔵 Nice to Have

- [ ] **Man pages** for `phase1-up.sh`, `phase1-down.sh`, `racoon-dns-detect`

- [ ] **systemd service template** for automatic hook registration

- [ ] **NetworkManager dispatcher script** alternative for NM-backed deployments

---

## Code Quality Observations

### Strengths
- Clean separation: C code exports data → shell implements policy
- Undo journal eliminates config drift
- Comprehensive backend probing
- Good fixture-based testing approach

### Areas for Improvement
1. **Error handling consistency** — Some functions return non-zero without stderr context; standardize on `rhook_log_error` pattern.

2. **Magic strings** — Backend names (`resolved`, `networkmanager`, etc.) repeated; consider associative array or constants.

3. **Function length** — `rhook_plan_apply` > 200 lines; consider splitting into `apply_dns_group`, `apply_spd_group`, `apply_route_group`.

4. **Global state** — Several `RHOOK_*` globals; consider namespacing or single config struct.

---

## Recommendations Summary

1. **Merge after Critical items resolved** — Core architecture is solid; Critical items are safety fixes.

2. **Create follow-up issues** for Medium/Nice-to-Have items — Track separately to avoid blocking this PR.

3. **Consider incremental merge** — If Critical items take time, split SPD rollback fix into separate PR on top of this one.

---

## Appendix: Files Reviewed

```
src/racoon/scripts/racoon-hook-lib.sh        (core library)
src/racoon/scripts/phase1-up.sh              (up hook)
src/racoon/scripts/phase1-down.sh            (down hook)
src/racoon/scripts/racoon-dns-detect         (admin CLI)
src/racoon/isakmp.c                          (IKE_COOKIE export)
src/racoon/isakmp_unity.c                    (UNITY_SPLITDNS_NAME parsing)
src/racoon/isakmp_cfg.c                      (INTERNAL_SPLITDNS_DOMAINS export)
etc/racoon/hooks.conf.sample                 (configuration)
doc/dev/ARCHITECTURE.md                      (architecture doc)
.github/workflows/racoon-hooks.yml           (CI workflow)
tests/hooks/test-phase1-roundtrip.sh         (e2e test)
tests/hooks/test-dns-detect-cli.sh           (CLI test)
tests/hooks/test-plan-builder.sh             (plan test)
tests/hooks/test-survey-fixtures.sh          (survey test)
tests/hooks/test-lib-smoke.sh                (smoke test)
tests/hooks/fixtures/*                       (15 survey fixtures)
```

---

*Assisted-by: OpenCode:kitch/KITCH-Coder*