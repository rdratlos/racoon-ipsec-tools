# On-demand roadwarrior client (Arch Linux, SSSD/autofs, Dynamic DNS gateway)

This sample wires up racoon so that:

- the tunnel comes up **automatically**, in the background, without a
  user running anything, ideally within seconds of boot if a network is
  already available;
- if no network is available at boot, the tunnel comes up **on the
  first attempt** to reach one of the protected internal networks
  (e.g. an SSSD LDAP lookup or an autofs NFS mount), as soon as
  connectivity (e.g. WLAN) returns -- no polling loop, no manual
  reconnect;
- the VPN gateway is reachable only via a **Dynamic DNS** hostname
  (`nepomuc.selfhost.eu`), and the client's own address changes on
  every WLAN reconnect (DHCP roaming) -- both addresses are numeric
  literals that racoon/setkey cannot resolve themselves.

It differs from `../client/` (the existing hybrid-auth + mode_cfg
roadwarrior sample, started manually via `racoonctl vc`): this one
uses plain X.509 certificate authentication, protects a fixed set of
internal subnets instead of a mode_cfg-assigned virtual address, and
is fully unattended.

## How the auto-connect actually works

racoon/setkey do not offer a "connect on demand" flag -- the mechanism
is the kernel's own IPsec Security Policy Database (SPD). A `setkey`
policy with action `... require` is a *trap*: as soon as any local
process sends a packet toward a protected network and no matching SA
exists yet, the kernel emits a PF_KEY `ACQUIRE` to racoon, which then
runs Phase 1/2 on its own. No dispatcher script has to "notice" the
connection attempt -- SSSD's or autofs' own first packet *is* the
trigger.

The catch: `setkey`'s tunnel-mode policies need the *literal* local and
remote IP addresses baked into the SPD entry (`esp/tunnel/LOCAL-REMOTE/require`),
and racoon's `remote` block needs a literal peer IP too -- both reject
hostnames outright (verified against this project's source: `str2saddr()`
in `src/racoon/sockmisc.c` resolves with `AI_NUMERICHOST`, and
`src/libipsec/policy_parse.y`'s tunnel-endpoint grammar rejects the
`me`/`any` wildcard for anything but transport mode). So neither the
Dynamic DNS gateway address nor this laptop's roaming WLAN address can
be written into the config once and forgotten.

`resolve-gateway.sh` is the bridge:

1. resolves `nepomuc.selfhost.eu` to its current IP,
2. asks the kernel routing table for the local source address that
   would be used to reach it (`ip route get`),
3. if either value changed since the last run, regenerates
   `/etc/racoon/gateway.conf` (the `remote { ... }` block) and
   `/etc/racoon/spd.conf` (the three `require` trap policies) with the
   current literals, reloads racoon, and asks it to start Phase 1
   immediately (best effort -- see below),
4. otherwise does nothing, so a live tunnel is never disturbed.

It is run:

- once at boot, before `racoon.service` starts (`racoon-gw-resolve.service`),
- immediately whenever an interface comes up or gets a new DHCP lease
  (NetworkManager dispatcher hook `90-racoon-vpn`) -- this is what
  makes reconnect-after-WLAN-roaming immediate instead of waiting for
  the next SSSD/autofs access attempt,
- every 10 minutes (`racoon-gw-resolve.timer`), to catch the case where
  the *gateway's* Dynamic DNS address changes while the laptop itself
  stays on the same network.

`racoon.service` itself starts unconditionally at boot
(`After=racoon-gw-resolve.service`, deliberately **not**
`After=network-online.target`): racoon only binds UDP sockets at
startup, it doesn't need a route to do that. This is what makes "zügig
beim Booten verbinden, falls möglich" work -- the trap policies and the
best-effort `racoonctl es` priming call happen as early as boot allows,
independent of whether WLAN has already associated.

## Files

| File | Installed as | Purpose |
|---|---|---|
| `racoon.conf` | `/etc/racoon/racoon.conf` | Static part: listen/timer, `include "gateway.conf"`, the three `sainfo` blocks |
| `gateway.conf.example` | (reference only) | What `resolve-gateway.sh` generates as `gateway.conf`; copy it manually only for the first-boot-without-network case below |
| `resolve-gateway.sh` | `/etc/racoon/resolve-gateway.sh` (mode 0700, root) | Generates `gateway.conf`/`spd.conf`, reloads racoon |
| `phase1-up.sh`, `phase1-down.sh` | `/etc/racoon/` (mode 0700, root) | Diagnostic hooks (`script ... phase1_up/phase1_down;`) |
| `systemd/racoon.service` | `/etc/systemd/system/racoon.service` | Starts racoon; no packaged systemd unit ships for Arch, see `packaging/arch/PKGBUILD` |
| `systemd/racoon-gw-resolve.service` | `/etc/systemd/system/racoon-gw-resolve.service` | Runs `resolve-gateway.sh` |
| `systemd/racoon-gw-resolve.timer` | `/etc/systemd/system/racoon-gw-resolve.timer` | Periodic Dynamic-DNS re-check |
| `NetworkManager/90-racoon-vpn` | `/etc/NetworkManager/dispatcher.d/90-racoon-vpn` (mode 0755, root) | Re-run resolve script on interface up/DHCP change |

## Install (Arch Linux)

```sh
install -d -m 0700 /etc/racoon/certs
install -m 0644 client.crt ca.crt /etc/racoon/certs/
install -m 0600 client.key         /etc/racoon/certs/

install -m 0644 racoon.conf                         /etc/racoon/racoon.conf
install -m 0700 resolve-gateway.sh phase1-up.sh phase1-down.sh /etc/racoon/

install -m 0644 systemd/racoon.service systemd/racoon-gw-resolve.service \
                 systemd/racoon-gw-resolve.timer     /etc/systemd/system/
install -m 0755 NetworkManager/90-racoon-vpn         /etc/NetworkManager/dispatcher.d/

systemctl daemon-reload
systemctl enable --now racoon-gw-resolve.timer
systemctl enable --now racoon.service
```

Requires racoon built with `--enable-natt --enable-frag --enable-dpd
--enable-adminport` (all already default in `packaging/arch/PKGBUILD`).

### First boot without a network

`racoon.conf`'s `include "gateway.conf";` needs that file to exist, but
`resolve-gateway.sh` can only create it once it has *both* resolved the
Dynamic DNS name and found a route to it. On a machine that has never
had connectivity yet, seed it once by hand from the example, using
whatever IP `nepomuc.selfhost.eu` currently resolves to:

```sh
sed 's/203.0.113.1/<current-gateway-ip>/' gateway.conf.example \
    > /etc/racoon/gateway.conf
```

`resolve-gateway.sh` will overwrite it correctly as soon as it gets a
chance to run with connectivity present.

## Why `hash_algorithm sha256` / `authentication_algorithm hmac_sha256` here, but not everywhere

The known "iOS can't get traffic through with SHA-256" problem (see
`docs/admin-guide/racoon-admin-guide.html`, section 7.5, "iOS:
HMAC-SHA256 Pitfall in sainfo") is specifically an **ESP Phase 2**
truncation mismatch: iOS truncates `hmac_sha256` to 128 bit per RFC
4868, racoon expects the classic 96-bit truncation, so Quick Mode
completes but every ESP packet is silently dropped at the receiver.
That bug lives in iOS' ESP stack, not in racoon or the Linux kernel,
and it does not affect the IKE Phase 1 `hash_algorithm`, only the
Phase 2 `authentication_algorithm` in `sainfo`.

Since both ends of this tunnel are racoon/Linux XFRM, that mismatch
does not apply, so this sample uses `sha256`/`hmac_sha256` throughout
for the stronger algorithm. The important part if this gateway *also*
serves iOS clients: keep this client's `sainfo` blocks scoped to these
three specific subnets (as done here), and make sure no iOS-facing
`sainfo anonymous`/subnet block on the gateway ever lists
`hmac_sha256` -- it must stay `hmac_sha1`-only for iOS, per the admin
guide.

## SSSD / autofs tuning

Both SSSD and autofs are what actually triggers the tunnel (their
first LDAP/NFS packet toward one of the three subnets hits the SPD
trap). Two timeouts matter so they don't give up before Phase 1/2
finishes (typically 1-3 s with RSA certs, more on a slow link):

```ini
# /etc/sssd/sssd.conf
[domain/example]
ldap_network_timeout = 10
dns_resolver_timeout = 10
# keep this short so SSSD retries promptly once the tunnel is up again
offline_timeout = 15
```

For autofs, raise the NFS mount timeout similarly in
`/etc/autofs.conf` (`MOUNT_WAIT`) if indirect maps mount internal NFS
shares.

If internal hostnames (not just IPs) are used by SSSD/autofs, the
internal DNS server needs to be reachable *through* the tunnel and
routed correctly by `systemd-resolved` (`resolvectl domain <if>
~internal.example.com`) -- otherwise name resolution fails before the
SPD trap is ever hit.

## Troubleshooting

See `docs/admin-guide/racoon-admin-guide.html`, section 9
(Troubleshooting): `setkey -PD`, `setkey -D`, `racoonctl show-sa
isakmp`, and `journalctl -u racoon -u racoon-gw-resolve`. Phase 1/2
failures are also logged by `phase1-up.sh`/`phase1-down.sh` via
`logger` (visible in `journalctl -t racoon-phase1-up`).

### racoon.conf fails to parse: "compression_algorithm none" rejected

`sainfo`'s `compression_algorithm` (RFC 3173 IP Payload Compression) is
mandatory in every `sainfo` block, and its only valid values are
`deflate` and `lzs` -- there is no `none`/off value (a previous
revision of `docs/admin-guide/racoon-admin-guide.html` incorrectly
listed `none` as valid; fixed there too). This sample uses `deflate`
throughout.

### SPD looks correct, but nothing ever negotiates ("send error")

Symptom: `setkey -DP` shows the three `require` trap policies, but no
traffic (ping, autofs mount, SSSD lookup) triggers a negotiation, and a
manual `racoonctl es isakmp inet <local-ip> <gateway-ip>` (or
`racoonctl vc <gateway-ip>`) immediately logs:

```
ERROR: phase1 negotiation failed due to send error. <cookie>:0000000000000000
```

This means racoon *is* being triggered (by the kernel ACQUIRE or by
racoonctl) but fails at the very first step, before sending a single
packet on the wire. Root cause: an explicit `listen { isakmp 0.0.0.0
[500]; isakmp_natt 0.0.0.0 [4500]; }` block (as shown in the admin
guide's generic NAT-T example) binds racoon to the *literal* address
`0.0.0.0` rather than to the machine's real addresses. racoon looks up
which socket to send from by an exact address comparison
(`grabmyaddr.c: myaddr_getfd()` -> `sockmisc.c: cmpsaddr()`, a plain
`memcmp` with no 0.0.0.0 wildcard special-case) against the specific
local address it negotiated with -- `0.0.0.0` never equals a real
interface address, so the lookup fails every single time and every
negotiation dies immediately.

Fix: remove the `listen { ... }` block entirely (see the comment in
`racoon.conf` in this directory). With no `listen` directive, racoon
enumerates the machine's real addresses itself and opens both an
isakmp and an isakmp_natt socket bound to each one -- and keeps that
list live across WLAN/DHCP roaming via a netlink route-change
subscription, no script required. If you deliberately need to restrict
racoon to specific interfaces, use their concrete addresses (not
`0.0.0.0`) in the `listen` block, and be aware that address then has
to be kept in sync manually the same way `gateway.conf`/`spd.conf` are.
