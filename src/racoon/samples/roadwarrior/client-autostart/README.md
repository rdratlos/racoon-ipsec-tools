# On-demand roadwarrior client (Arch Linux, SSSD/autofs, Dynamic DNS gateway)

This sample wires up racoon so that:

- the tunnel comes up **automatically**, in the background, without a
  user running anything, ideally within seconds of boot if a network is
  already available;
- if no network is available at boot, the tunnel comes up shortly after
  connectivity (e.g. WLAN) returns -- no polling loop, no manual
  reconnect;
- the VPN gateway is reachable only via a **Dynamic DNS** hostname
  (`nepomuc.selfhost.eu`), and the client's own address changes on
  every WLAN reconnect (DHCP roaming) -- both addresses are numeric
  literals that racoon/setkey cannot resolve themselves;
- the gateway (`vpngateway.racoon.conf`, the real production config)
  authenticates with `xauth_rsa_server` and assigns each client a
  `mode_cfg` pool address (e.g. `192.168.66.5`) -- it is tuned for
  iOS/macOS Cisco IPSec clients, and this sample must not break that
  while adding an unattended Linux client.

## Revision history / why this isn't the site-to-site sample it started as

An earlier revision of this sample used a *static-subnet* model: fixed
`sainfo`/SPD entries for the three networks, plain `rsasig`
authentication, no `mode_cfg`. That was an unverified assumption about
the gateway's shape -- modelled after the admin guide's generic
X.509/rsasig site-to-site example -- made without ever looking at the
actual `vpngateway.racoon.conf`. It happened to get far enough to
produce real, confusing symptoms (see Troubleshooting below) before the
actual gateway config surfaced the real mismatch:

- the gateway's `remote anonymous` block uses
  `authentication_method xauth_rsa_server` -- Phase 1 authentication is
  still RSA certificates, but the gateway also expects an **XAuth
  username/password** exchange afterward. A plain `rsasig` client
  proposal doesn't match this at all.
- the gateway's `sainfo anonymous` only offers
  `authentication_algorithm hmac_sha512, hmac_sha1;` -- no
  `hmac_sha256`, at all (its own comment: `# hmac_sha256 does not
  interwork with iOS`). A client offering only `hmac_sha256` for Phase 2
  -- which is what this sample used to do, reasoning that the iOS
  truncation pitfall doesn't apply between two racoon/Linux endpoints
  -- would never get a matching Quick Mode proposal against *this*
  gateway, regardless of how correct that reasoning was in the
  abstract.
- the gateway's `mode_cfg` block assigns each client a pool address
  (`network4 192.168.66.20; pool_size 200;`). A mode_cfg client has no
  fixed Phase 2 selector to pre-install a kernel-ACQUIRE trap policy
  for -- the pool address doesn't exist until Phase 1 + Mode Config
  actually completes. The previous static-SPD-trap design is
  structurally incompatible with this gateway, independent of any of
  the bugs fixed along the way.

Fixed along the way, and still valid under the current design:
`compression_algorithm none` isn't a real value (see Troubleshooting),
an explicit `listen { isakmp 0.0.0.0 ...}` block breaks send()
(Troubleshooting), and strict reverse-path filtering drops decapsulated
replies without an explicit route to each protected network
(Troubleshooting). Those were real, independent bugs -- fixing them was
necessary but not sufficient, because the authentication method and
the whole "pre-install a static trap policy" strategy were wrong for
this gateway from the start.

## How the auto-connect actually works now

Because the client's usable Phase 2 selector (the mode_cfg pool
address) doesn't exist until after Phase 1 completes, this sample no
longer relies on a kernel `ACQUIRE`-triggered trap policy to start the
tunnel. Instead:

1. `resolve-gateway.sh` **actively initiates Phase 1** itself (a
   `racoonctl es isakmp` "establish-sa" admin call) whenever it detects
   the gateway's Dynamic DNS address or this laptop's own address has
   changed -- at boot, on every NetworkManager interface-up event, and
   on a periodic timer. This is the primary connect mechanism now, not
   a nice-to-have.
2. racoon runs Phase 1 (RSA cert auth) then, because `mode_cfg on;` is
   set, an XAuth exchange (username from `xauth_login`, password
   looked up in `psk.txt` by that same login -- see "Credentials"
   below) followed by the Mode Config Pull exchange, which assigns this
   session's pool address (`INTERNAL_ADDR4`).
3. Once that completes, racoon calls the `phase1_up` script hook
   (`phase1-up.sh`), which is where the SPD entries for the three
   protected networks actually get installed, using `INTERNAL_ADDR4` as
   the tunnel's inner source selector and the just-negotiated
   `LOCAL_ADDR`/`REMOTE_ADDR` as the outer tunnel endpoints.
4. Phase 2 (Quick Mode) then proceeds normally, triggered by the SPD
   entries `phase1-up.sh` just installed matching the first real
   packet (or immediately, since racoon can also initiate Quick Mode
   right after Mode Config for policies it just created).

racoon's `remote` block still needs a *literal* peer IP (`str2saddr()`
in `src/racoon/sockmisc.c` resolves with `AI_NUMERICHOST`, hostnames
are rejected at parse time), so `resolve-gateway.sh` still resolves
`nepomuc.selfhost.eu` and rewrites `/etc/racoon/gateway.conf` (the
`remote { ... }` block) whenever the resolved address changes, exactly
as before.

It is run:

- once at boot, before `racoon.service` starts (`racoon-gw-resolve.service`),
- immediately whenever an interface comes up or gets a new DHCP lease
  (NetworkManager dispatcher hook `90-racoon-vpn`) -- this is what
  makes reconnect-after-WLAN-roaming prompt,
- every 10 minutes (`racoon-gw-resolve.timer`), to catch the case where
  the *gateway's* Dynamic DNS address changes while the laptop itself
  stays on the same network.

Separately, and on *every* run regardless of whether the address
changed, it also installs an explicit route to each protected network
via the current outbound interface (`ip route replace <net> dev
<iface>`) -- this is unrelated to Phase 1/mode_cfg and exists purely to
satisfy strict reverse-path filtering; see Troubleshooting.

`racoon.service` itself starts unconditionally at boot
(`After=racoon-gw-resolve.service`, deliberately **not**
`After=network-online.target`): racoon only binds UDP sockets at
startup, it doesn't need a route to do that.

## Credentials

This gateway requires an LDAP-backed `vpnuser` account for XAuth, in
addition to the X.509 client certificate. Two files carry this,
neither of which this sample can populate for you:

- `/etc/racoon/xauth-login` -- a single line, the login name (matches
  an LDAP `uid` the gateway's `ldapcfg` looks up).
- `/etc/racoon/psk.txt` -- normally racoon's PSK file, but also where
  XAuth passwords are looked up: add a line `<login>	<password>`
  (tab-separated, see `racoon.conf(5)`, `xauth_login`). This means the
  XAuth password sits in cleartext on disk -- unavoidable for
  fully unattended/headless operation with no prompt available at
  boot. Keep both files `0600`, owned by `root` (the install steps
  below do this).

## Files

| File | Installed as | Purpose |
|---|---|---|
| `racoon.conf` | `/etc/racoon/racoon.conf` | Static part: timer, `include "gateway.conf"`, `sainfo anonymous` |
| `gateway.conf.example` | (reference only) | What `resolve-gateway.sh` generates as `gateway.conf`; copy it manually only for the first-boot-without-network case below |
| `resolve-gateway.sh` | `/etc/racoon/resolve-gateway.sh` (mode 0700, root) | Generates `gateway.conf`, installs the reverse-path routes, primes Phase 1 |
| `phase1-up.sh` | `/etc/racoon/` (mode 0700, root) | Installs the SPD for the three networks once `INTERNAL_ADDR4` is assigned |
| `phase1-down.sh` | `/etc/racoon/` (mode 0700, root) | Diagnostic hook only (`script ... phase1_down;`) |
| `systemd/racoon.service` | `/etc/systemd/system/racoon.service` | Starts racoon; no packaged systemd unit ships for Arch, see `packaging/arch/PKGBUILD` |
| `systemd/racoon-gw-resolve.service` | `/etc/systemd/system/racoon-gw-resolve.service` | Runs `resolve-gateway.sh` |
| `systemd/racoon-gw-resolve.timer` | `/etc/systemd/system/racoon-gw-resolve.timer` | Periodic Dynamic-DNS re-check |
| `NetworkManager/90-racoon-vpn` | `/etc/NetworkManager/dispatcher.d/90-racoon-vpn` (mode 0755, root) | Re-run resolve script on interface up/DHCP change |

## Install (Arch Linux)

```sh
install -d -m 0700 /etc/racoon/certs
install -m 0644 client.crt ca.crt /etc/racoon/certs/
install -m 0600 client.key         /etc/racoon/certs/

printf '%s\n' "your-vpnuser-login" | install -m 0600 /dev/stdin /etc/racoon/xauth-login
# then add a matching line to psk.txt yourself:
#   printf 'your-vpnuser-login\tYOUR_PASSWORD\n' >> /etc/racoon/psk.txt
install -m 0600 /dev/null /etc/racoon/psk.txt

install -m 0644 racoon.conf                                    /etc/racoon/racoon.conf
install -m 0700 resolve-gateway.sh phase1-up.sh phase1-down.sh /etc/racoon/

install -m 0644 systemd/racoon.service systemd/racoon-gw-resolve.service \
                 systemd/racoon-gw-resolve.timer     /etc/systemd/system/
install -m 0755 NetworkManager/90-racoon-vpn         /etc/NetworkManager/dispatcher.d/

systemctl daemon-reload
systemctl enable --now racoon-gw-resolve.timer
systemctl enable --now racoon.service
```

Requires racoon built with `--enable-natt --enable-frag --enable-dpd
--enable-hybrid --enable-adminport` -- `--enable-hybrid` is required
for XAuth (`xauth_rsa_client`/`xauth_login`) and is already part of
`packaging/arch/PKGBUILD`'s flag list, so a package built from that
PKGBUILD needs no changes on this front.

### First boot without a network

`racoon.conf`'s `include "gateway.conf";` needs that file to exist, but
`resolve-gateway.sh` can only create it once it has *both* resolved the
Dynamic DNS name and found a route to it. On a machine that has never
had connectivity yet, seed it once by hand from the example, using
whatever IP `nepomuc.selfhost.eu` currently resolves to and your actual
XAuth login:

```sh
sed -e 's/203.0.113.1/<current-gateway-ip>/' -e 's/CHANGEME/<xauth-login>/' \
    gateway.conf.example > /etc/racoon/gateway.conf
```

`resolve-gateway.sh` will overwrite it correctly as soon as it gets a
chance to run with connectivity present.

## Why `hash_algorithm sha256` but `hmac_sha512`/`hmac_sha1` (not `hmac_sha256`) for Phase 2

These are two different things that are easy to conflate:

- `hash_algorithm` in the `remote`/Phase 1 `proposal` block is the
  IKE HASH payload's keyed PRF, computed over the whole payload -- not
  truncated the way ESP authentication is. `sha256` here matches both
  of the gateway's Phase 1 proposals and has no interop problem with
  anything, iOS included.
- `authentication_algorithm` in `sainfo` (Phase 2/ESP) is where the
  well-known "iOS can't get traffic through with SHA-256" truncation
  mismatch lives (see `docs/admin-guide/racoon-admin-guide.html`,
  section 7.5): iOS truncates `hmac_sha256` to 128 bit per RFC 4868,
  racoon expects the classic 96-bit truncation, so Quick Mode completes
  but every ESP packet is silently dropped at the receiver. That bug
  lives in iOS' ESP stack, not racoon or the Linux kernel -- between two
  racoon/Linux endpoints in isolation, `hmac_sha256` would work fine.

But this client doesn't get to make that call unilaterally: the
gateway's own `sainfo anonymous` (shared by every client, there's no
separate block for this one) offers only `hmac_sha512, hmac_sha1` --
`hmac_sha256` isn't in its list at all, presumably removed outright
rather than merely deprioritized once the iOS pitfall was diagnosed.
Proposing only `hmac_sha256` here would make Quick Mode fail with
`NO-PROPOSAL-CHOSEN` against this specific gateway, independent of the
Linux-to-Linux compatibility argument. `racoon.conf` in this directory
therefore mirrors the gateway's `sainfo anonymous` exactly:
`hmac_sha512, hmac_sha1`.

## SSSD / autofs tuning

Two timeouts matter so SSSD/autofs don't give up before Phase
1/XAuth/Mode Config/Phase 2 finishes (can take longer than a plain
cert-only exchange -- budget a few seconds):

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
internal DNS server (`10.66.0.6`, per the gateway's `dns4`) needs to be
reachable *through* the tunnel and routed correctly by
`systemd-resolved` (`resolvectl domain <if> ~nepomuc.de`).

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
throughout, matching the gateway.

### Nothing ever negotiates, `racoonctl es`/priming logs "send error"

```
ERROR: phase1 negotiation failed due to send error. <cookie>:0000000000000000
```

Root cause: an explicit `listen { isakmp 0.0.0.0 [500]; isakmp_natt
0.0.0.0 [4500]; }` block (as shown in the admin guide's generic NAT-T
example) binds racoon to the *literal* address `0.0.0.0` rather than to
the machine's real addresses. racoon looks up which socket to send
from by an exact address comparison (`grabmyaddr.c: myaddr_getfd()` ->
`sockmisc.c: cmpsaddr()`, a plain `memcmp` with no `0.0.0.0` wildcard
special-case) against the specific local address it negotiated with --
`0.0.0.0` never equals a real interface address, so the lookup fails
every single time and every negotiation dies immediately.

Fix: don't add a `listen { ... }` block (this sample doesn't). With no
`listen` directive, racoon enumerates the machine's real addresses
itself and opens both an isakmp and an isakmp_natt socket bound to each
one -- and keeps that list live across WLAN/DHCP roaming via a netlink
route-change subscription, no script required.

### ESP counters increase both ways, but a reply never reaches the application

Symptom: `setkey -D`/`ip -s xfrm state` show `state=mature` SAs in
*both* directions with growing, non-zero byte counters -- the tunnel
is genuinely up and passing traffic -- and the ICMP echo reply from a
protected host is even visible in Wireshark/tcpdump, yet `ping` itself
never prints a reply and hangs/times out. `/proc/net/xfrm_stat` is
clean (`XfrmInError` and friends stay at 0): IPsec decapsulation itself
succeeded, so this is not an SPD/SA problem.

This is Linux's **strict reverse-path filtering**
(`net.ipv4.conf.*.rp_filter`, `1` on many distro defaults) rejecting
the decapsulated packet *after* IPsec processing but *before* socket
delivery: with no explicit route to the protected network (e.g.
`10.66.0.0/24`) via the interface the ESP packet arrived/was decrypted
on, the kernel cannot verify that a reply to that source address would
symmetrically leave via the same interface, treats it as a spoofed
("martian") source, and silently drops it. This never shows up in the
XFRM counters because it happens one layer up, in generic IPv4 input
processing.

Confirm:
```sh
sysctl -w net.ipv4.conf.all.log_martians=1
journalctl -k -f          # watch for "IPv4: martian source ..." while pinging
```

Fix: an explicit route to each protected network via the interface
used to reach the gateway satisfies the symmetric-routing check
without weakening `rp_filter` globally -- `resolve-gateway.sh` does
this unconditionally on every run (`ip route replace <net> dev
"$IFACE"`), independent of Phase 1/Mode Config, so it's in place even
before the tunnel first comes up.

**Caveat learned the hard way**: fixing this (and the two issues
above) is necessary but was not, on its own, sufficient against the
real gateway -- see "Revision history" above. If Phase 1 never gets
past authentication at all (rather than negotiating fine and then
losing traffic), the routing/rp_filter layer isn't the problem; check
XAuth/mode_cfg next.

### Phase 1 completes but no XAuth/Mode Config happens, or Quick Mode never starts

Check `journalctl -u racoon` for the XAuth and Mode Config exchange
after Phase 1 finishes. If nothing happens: confirm `mode_cfg on;` and
`xauth_login "..."` are actually present in the generated
`/etc/racoon/gateway.conf` (i.e. `/etc/racoon/xauth-login` existed and
was readable *before* `resolve-gateway.sh` last ran -- it silently
skips writing `gateway.conf` otherwise, see its log via
`journalctl -t racoon-gw-resolve`), and that `/etc/racoon/psk.txt`
has a line for that exact login. If XAuth is rejected specifically,
double-check the password and that the LDAP account is a member of the
gateway's `auth_groups "vpnuser"`.

`phase1-up.sh` only installs the SPD (and therefore only Phase 2 can
start) once `INTERNAL_ADDR4` is actually set -- if Mode Config didn't
complete, `journalctl -t racoon-phase1-up` will show "no mode_cfg pool
address assigned -- not installing SPD".
