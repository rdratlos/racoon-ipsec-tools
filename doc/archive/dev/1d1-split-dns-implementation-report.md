> **Archived.** Superseded by [doc/dev/v0.9.1-hardening-spec.md](../../dev/v0.9.1-hardening-spec.md)#55-early-nm-dummy-interface-track--abandoned as of 2026-08-04; retained for provenance. See also git tag `archive/pre-doc-consolidation`.

# Split DNS NetworkManager Integration — Development Report

**Branch:** `feature/dns-nm-integration`
**Base Commit:** `89efb95` ("samples: fix server cert path, listen binding, client sainfo, script fallbacks")
**Current HEAD:** `095a142` ("roadwarrior: redesign NM split-DNS with dummy interface racoon-vpn0")

---

## Objective

Implement robust split DNS support for racoon-ipsec-tools roadwarrior clients using a dedicated NetworkManager dummy interface (`racoon-vpn0`), with proper resolver detection and clean teardown — avoiding the previous approach of modifying the active physical connection which caused VPN route loss on roadwarrior notebooks.

**Key design constraints:**
- Never touch the physical connection
- All NM properties set in single `nmcli conn add` before activation (no modify-while-active races)
- DNS servers always routed as /32s regardless of `SPLIT_INCLUDE_CIDR`
- Resolver detection via `/etc/resolv.conf` symlink target (canonical source of truth)
- Split-DNS search domains prefixed with `~` for routing-domain semantics
- Validate NM `dns=` backend is `systemd-resolved` or `dnsmasq` (reject `dns=default`)

---

## What Has Been Done

### 1. New Shared Helper: `phase1-common.sh`
Created at `src/racoon/samples/roadwarrior/client/phase1-common.sh` with:
- `resolve_target()` — resolves `/etc/resolv.conf` to final symlink target
- `detect_resolver()` — identifies active resolver from symlink path:
  - `/run/systemd/resolve/*` → `systemd-resolved`
  - `/run/NetworkManager/*` → `networkmanager`
  - `/run/resolvconf/*` → `resolvconf`
  - `/lib/systemd/resolve/*` (fallback) → `systemd-resolved`
  - else → `fallback`
- `validate_nm_dns_backend()` — checks NM `dns=` setting via `nmcli general print` or config file; returns success for `systemd-resolved`/`dnsmasq`, failure for `default`
- `racoon_vpn0_ifname()` → `racoon-vpn0`
- `racoon_vpn_connname()` → `racoon-vpn`

### 2. Redesigned `phase1-up.sh`
- Collects internal networks from `SPLIT_INCLUDE_CIDR` > `SPLIT_INCLUDE` > hardcoded fallback (`10.0.12.0/24`)
- Installs per-network routes with `src=INTERNAL_ADDR4` on real outbound interface
- SPD via `setkey` with bidirectional tunnel selectors
- **DNS server /32 routes** always installed (independent of split routes)
- Resolver-specific setup:
  - **systemd-resolved:** `resolvectl dns/domain` with `~`-prefix, `default-route false`
  - **NetworkManager:** single `nmcli conn add type dummy` with all properties (`manual`, `169.254.0.1/32`, DNS, `~`-search, `ignore-auto-dns`, `never-default`, `autoconnect=no`), then `conn up`
  - **resolvconf:** `resolvconf -a`
  - **dnsmasq:** `/etc/dnsmasq.d/racoon-vpn`
  - **fallback:** direct `/etc/resolv.conf` write with backup

### 3. Redesigned `phase1-down.sh`
- Flushes SPD (`setkey -F`)
- Removes split routes and DNS server /32 routes
- Removes `INTERNAL_ADDR4/32` from real interface
- Resolver-specific cleanup:
  - **systemd-resolved:** `resolvectl revert`
  - **NetworkManager:** `nmcli conn down` → `nmcli conn delete` → `ip link del racoon-vpn0` (force cleanup)
  - **resolvconf:** `resolvconf -d`
  - **dnsmasq:** remove config + HUP
  - **fallback:** restore `/etc/resolv.conf` from backup

---

## What Has Been Achieved

| Aspect | Before (active-connection mod) | After (dummy interface) |
|--------|-------------------------------|-------------------------|
| Physical connection touched | Yes (DNS modified in-place) | Never |
| Modify-while-active race | Frequent (reject modify) | Eliminated (single conn add) |
| Route loss on notebook | Observed | Prevented by design |
| DNS server reachability | Implicit (often failed) | Explicit /32 routes always |
| Resolver detection | Binary presence (fallible) | Symlink target (canonical) |
| Split-DNS domain semantics | None (leakage possible) | `~` prefix = routing domains only |
| NM backend validation | None | Enforced (rejects `dns=default`) |
| Teardown reliability | Incomplete (stale state) | Full cleanup (conn + link) |

All three scripts pass `sh -n` syntax check. No dead references to old `vpn0`/`racoon-vpn` (without `-0`) logic remain.

---

## Challenges Faced

1. **Route loss on roadwarrior notebook** — The original approach modified the active physical connection's DNS, which triggered interface state changes that flushed VPN routes. Root cause: NM's internal handling of DNS changes on active connections.

2. **Modify-while-active race** — `nmcli conn modify` on an active connection is rejected by NM. Previous attempts worked around this with complex ordering but remained fragile.

3. **Resolver detection ambiguity** — Checking for binary presence (`systemctl is-active`, `which`) is unreliable; distros may have multiple resolvers installed but only one active. The symlink target of `/etc/resolv.conf` is the definitive indicator.

4. **NM `dns-search` separator** — `nmcli conn add` takes space-separated values; `conn modify` uses `;`. The single-command approach avoids this by using `conn add` with space separation.

5. **DNS servers outside split routes** — Gateway may provide internal DNS servers not covered by `SPLIT_INCLUDE_CIDR`. Without explicit /32 routes, queries follow default route and bypass tunnel.

---

## What Needs to Be Done Further

### High Priority
- [ ] **End-to-end testing** on target platforms (Ubuntu 18.04+, Arch Linux) with:
  - systemd-resolved backend
  - NetworkManager + dnsmasq backend
  - Fallback (no resolver)
- [ ] Verify DNS server /32 routing works when DNS IPs are *outside* `SPLIT_INCLUDE_CIDR`
- [ ] Verify split-DNS search domains are correctly applied as routing domains only

### Medium Priority
- [ ] Add unit tests for `detect_resolver()` symlink logic (mock `/etc/resolv.conf` targets)
- [ ] Test NM `dns=default` fallback path (should fall back to resolv.conf method)
- [ ] Verify `autoconnect=no` prevents dummy activation on boot
- [ ] Check IPv6 support (currently IPv4-only)

### Low Priority
- [ ] Document usage in README or sample config
- [ ] Consider adding `ipv6.method ignore` to dummy connection for explicit IPv6 disable
- [ ] Evaluate whether `ipv4.ignore-auto-router yes` is needed (already set)

### Known Limitations
- **IPv6 not implemented** — Scripts are IPv4-only per roadwarrior sample scope
- **Single dummy interface** — Concurrent VPNs would need distinct names (not addressed)
- **NM version dependency** — `nmcli general print` requires NM ≥ 1.22; fallback to config file parsing handles older versions

---

## Files Changed

```
src/racoon/samples/roadwarrior/client/phase1-common.sh   (new)
src/racoon/samples/roadwarrior/client/phase1-up.sh       (rewritten)
src/racoon/samples/roadwarrior/client/phase1-down.sh     (rewritten)
```

---

## License

All new files: **BSD-3-Clause** — Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors.