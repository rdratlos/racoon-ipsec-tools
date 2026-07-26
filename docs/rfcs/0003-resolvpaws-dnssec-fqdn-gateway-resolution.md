# RFC 0003: Resolvpaws — DNSSEC-Validated FQDN Resolution for Roadwarrior Gateways

## Status

Draft

## Authors

- Drafted via Claude Code at the request of @rdratlos

## Reviewers

- @rdratlos (decision)
- (open to community and domain-expert review — DNS/DNSSEC, resolver library maintainers)

## Motivation

Racoon's `remote` directive requires a numeric IP address. `str2saddr()`
(`sockmisc.c:804`) resolves it via `getaddrinfo()` with `AI_NUMERICHOST` set,
so a hostname is rejected outright at config-parse time — this is not a
resolve-once-and-cache behavior, it is a hard refusal of non-numeric input.

Roadwarrior/road-warrior VPN clients frequently connect to a gateway whose
public IP address is not stable — residential and small-business uplinks are
commonly assigned dynamic addresses that change on the order of once a day.
Administrators work around this today with Dynamic DNS, but Racoon cannot
consume a Dynamic DNS name at all: the client has to be reconfigured (or
wrapped in an external script that rewrites `racoon.conf` and reloads the
daemon) every time the address changes.

Resolving a hostname to an address and trusting it outright would introduce a
new spoofing surface: an attacker able to inject a forged DNS response (or
compromise/coerce a recursive resolver on-path) could redirect a roadwarrior
client to an address of their choosing. Racoon already ships DNSSEC-adjacent
code (`dnssec.c`, `getcertsbyname.c`) that fetches DNS CERT resource records
(RFC 2538) for peer identity validation, but this is unrelated machinery: it
does not resolve A/AAAA records, and it depends on `getrrsetbyname()` /
`lwres_getrrsetbyname()`, an API tied to the pre-RFC 4033 (RFC 2535-era)
KEY/SIG/CERT DNSSEC design that most modern resolvers and libraries no longer
implement.

This RFC defines "resolvpaws" — a DNSSEC-validating hostname-resolution
abstraction layer, named and structured after RFC 0002's "kernelpaws" — that
lets `remote` accept an FQDN and resolves it to an address only when DNSSEC
validation proves the zone operator authorized that address. Racoon must
refuse to connect, not fall back to an unvalidated address, whenever
validation does not come back definitively secure.

## Goals

- Allow `remote` in `racoon.conf` to specify a hostname (FQDN) instead of a
  numeric IP address.
- Resolve that hostname's current address only when DNSSEC validation of the
  A/AAAA record returns a definitively secure result; every other outcome
  (bogus, indeterminate, resolution error/timeout) is a hard failure with no
  fallback to an unvalidated address.
- Track the record's TTL and re-resolve near expiry so a Dynamic-DNS address
  change is picked up without requiring a config reload or daemon restart.
- Preserve Racoon's low footprint and lean dependency profile: DNSSEC
  validation strength is a compile-time choice (`--with-libunbound`), not a
  mandatory new hard dependency for everyone who builds Racoon.
- Provide a pluggable backend interface (`resolvpaws_ops`) so a stronger or
  weaker validation strategy can be swapped in without touching call sites in
  `isakmp.c` or `cfparse.y`.
- Make address-family selection for dual-stack FQDNs deterministic and
  operator-controlled, not dependent on race timing or on which family
  happens to be reachable on the network Racoon is currently attached to.

## Non-goals

- Runtime backend switching — selection is compile-time, mirroring
  `kernelpaws`'s `--enable-xfrm` precedent. Falling back from a strong
  validator to a weaker one at runtime is a silent security downgrade and is
  explicitly rejected (see Risks).
- A systemd-resolved (`io.systemd.Resolve1` D-Bus) backend in this RFC's
  implementation scope. It is named as a future backend and the ops interface
  is designed to accommodate it, but it is not built here — Racoon commonly
  runs privileged/chrooted, and D-Bus socket reachability under Racoon's
  privilege-drop model needs its own investigation before committing to it.
- Redesigning the existing CERT-RR peer-identity DNSSEC code in `dnssec.c` /
  `getcertsbyname.c`. That mechanism is orthogonal (peer identity, not gateway
  address) and out of scope. It is, however, a natural follow-up once
  `resolvpaws_backend` exists: `getrrsetbyname()` is BIND8-era and gives no
  access to a validating resolver's already-computed validation state, so
  `dnssec.c`/`getcertsbyname.c` doing DNSSEC-adjacent work on top of a legacy
  API duplicates effort that resolvpaws will already be doing. Because it
  touches peer-identity verification — a security-sensitive area that
  deserves its own design and review pass rather than riding along as a
  footnote here — this is called out as a candidate for a dedicated RFC 0004,
  not folded into this RFC or RFC 0002.
- IKEv2 — scope is IKEv1 only, consistent with the rest of Racoon.
- Re-resolving or redirecting an already-established Phase 1/Phase 2 SA mid-
  session. See Proposed Design for the chosen policy (existing SAs ride out;
  only new/rekey negotiations use a freshly resolved address).
- Racing IPv4 and IPv6 against each other (Happy-Eyeballs-style) to pick a
  gateway address. Address-family selection is a deterministic, operator-set
  preference with sequential (not raced) fallback — see Proposed Design and
  Alternatives Considered.
- Racoon managing its own DNSSEC root trust anchor lifecycle (RFC 5011
  rollover handling). Resolvpaws consumes whatever trust anchor the host
  system already maintains — see Proposed Design.

## Current design

- `remote` is parsed in `cfparse.y` (`remote_spec` / `remote_index` /
  `ike_addrinfo_port`, `cfparse.y:1821-1850`), which calls `str2saddr()`
  synchronously during config parsing.
- `str2saddr()` (`sockmisc.c:804`) sets `hints.ai_flags = AI_NUMERICHOST`
  before calling `getaddrinfo()` — hostnames fail parsing with a
  `getaddrinfo` error, they are not silently resolved.
- The resolved (or rejected) address is stored once in
  `struct remoteconf.remote` (`remoteconf.h:89`) and never re-resolved. There
  is no timer, TTL tracking, or refresh path anywhere in the codebase for
  this field.
- Phase 1 initiation reads `rmconf->remote` directly:
  `isakmp_ph1begin_i(rmconf, remote, local)` (`isakmp.c:1043`), called from
  `isakmp.c:1981` (retransmission of an existing exchange, using
  `iph1->remote`) and `isakmp.c:2213` (new exchange, using `iph2->dst`, which
  is itself derived from `rmconf->remote` at policy-lookup time). There is no
  single choke point today where "get the address to dial" is separated from
  "the address is already known" — introducing resolvpaws requires adding
  that separation.
- Racoon's only existing DNSSEC-adjacent code (`dnssec.c:58` `dnssec_getcert`)
  fetches DNS CERT RRs for `IPSECDOI_ID_FQDN` peer identities via
  `getcertsbyname()` (`getcertsbyname.c`), built on `getrrsetbyname()` /
  `lwres_getrrsetbyname()`. This has no A/AAAA resolution capability and does
  not perform RRSIG/DNSKEY/DS chain-of-trust validation — it depends on
  RFC 2538/2535-era record types that predate the modern DNSSEC design.
- Racoon's timer/event subsystem is `schedule.c`/`schedule.h`: `struct sched`
  with a `func` callback, scheduled via `sched_schedule(sched, timeout, func)`
  and cancelled via `sched_cancel(sched)` (`schedule.h:70-94`). No existing
  scheduled task touches DNS resolution.
- Precedent for compile-time-optional dependencies already exists in
  `configure.ac`: `--with-libldap` (`configure.ac:551-596`) is the closest
  structural match — probes for the library, allows a `DIR` override, defines
  a `HAVE_*` macro, and conditionally adds to `LIBS`/`CPPFLAGS`.
- Racoon already has a precedent for deterministic, single-owner runtime
  state over coexistence/racing alternatives: `kernelpaws` (RFC 0002)
  deliberately uses host-wide `FLUSHSA`/`FLUSHPOLICY` and assumes exclusive
  ownership of the XFRM tables rather than tracking per-daemon state for
  coexistence, "a deliberate trade-off: simplicity over coexistence,
  consistent with Racoon's lightweight design philosophy." Resolvpaws'
  address-family selection follows the same theme: one deterministic path
  per attempt, not a race.

## Proposed design

### Architecture

```
+-----------------------+
|   racoon daemon       |
|                       |
|  resolvpaws.h         |  <-- unified ops interface
|  resolvpaws_ops       |  <-- function pointer table, compile-time selected
|                       |
|  +-------------------+|
|  | resolvpaws_glibc  ||  <-- res_query()/getaddrinfo() + AD-bit check
|  | .c                ||      (default backend when resolvpaws is enabled)
|  +-------------------+|
|                       |
|  +-------------------+|
|  | resolvpaws_unbound||  <-- libunbound: full RRSIG/DNSKEY/DS validation
|  | .c                ||      (--with-libunbound)
|  +-------------------+|
+-----------------------+
         |
         v
   resolvpaws_resolve()  --  sched_schedule() refresh near TTL expiry
```

`resolvpaws_sdresolved.c` (systemd-resolved D-Bus backend) is named here as a
future backend per Non-goals; no code is written for it in this RFC.

Resolvpaws itself is a compile-time-optional component (`--disable-resolvpaws`
for truly minimal builds that never need FQDN gateways at all; enabled by
default). When disabled, a hostname in `remote` is a config-parse-time fatal
error — the same hard-refusal behavior `AI_NUMERICHOST` already gives today,
just with a clearer diagnostic. When enabled, the `glibc` backend is always
available with zero extra library dependencies; `libunbound` is additionally
available only when `--with-libunbound` was used at build time.

### resolvpaws_ops interface

A single `resolve()` call fetches and validates **both** address families up
front — one round trip to the backend, not one per family and not a second
round trip when a fallback is later needed. Family *selection* is a separate,
synchronous step over the already-fetched result, keeping "resolve" and
"select" cleanly divided:

```c
enum resolvpaws_status {
	RESOLVPAWS_SECURE,        /* DNSSEC validation succeeded: use this address */
	RESOLVPAWS_INSECURE,      /* zone is unsigned / opts out of DNSSEC */
	RESOLVPAWS_BOGUS,         /* validation failed: signature/chain broken */
	RESOLVPAWS_INDETERMINATE, /* could not build a chain of trust */
	RESOLVPAWS_ERROR,         /* NXDOMAIN, timeout, transport failure, etc. */
	RESOLVPAWS_NODATA,        /* name resolved but no record for this family */
};

struct resolvpaws_addr {
	enum resolvpaws_status status;
	struct sockaddr *addr;   /* NULL unless status == RESOLVPAWS_SECURE */
	time_t ttl_expiry;       /* absolute time; used to schedule refresh */
};

struct resolvpaws_result {
	struct resolvpaws_addr inet;   /* AF_INET  */
	struct resolvpaws_addr inet6;  /* AF_INET6 */
};

struct resolvpaws_ops {
	const char *name;

	int  (*init)(void);
	void (*cleanup)(void);

	/* fetches + validates A and AAAA together in one call */
	int  (*resolve)(const char *hostname, struct resolvpaws_result *out);
};

extern const struct resolvpaws_ops *const resolvpaws_backend;

/* selection is backend-independent, operates purely on an already-fetched
 * resolvpaws_result; never triggers a new DNS query */
enum resolvpaws_af_pref { RESOLVPAWS_AF_INET, RESOLVPAWS_AF_INET6, RESOLVPAWS_AF_ANY };

struct sockaddr *resolvpaws_select(const struct resolvpaws_result *result,
                                    enum resolvpaws_af_pref pref);
```

Backend selection mirrors `kernelpaws`'s pattern exactly
(`0002-kernelpaws...md`, "Backend Selection"):

```c
#ifdef HAVE_LIBUNBOUND
const struct resolvpaws_ops *const resolvpaws_backend = &resolvpaws_unbound_ops;
#else
const struct resolvpaws_ops *const resolvpaws_backend = &resolvpaws_glibc_ops;
#endif
```

### Config grammar

`remote` gains the ability to take a quoted hostname anywhere it currently
takes `ike_addrinfo_port`'s numeric-address form. Three new directives
control it — one global, two per-remote:

```
# top-level, applies to all "remote" blocks unless overridden
dnssec_verify off;             # off | on  (default: off)
dnssec_trust_anchor_file "/var/lib/unbound/root.key";   # optional; probed if unset
dnssec_af_preference inet;     # inet | inet6 | any     (default: inet)

remote "vpn.example.com" {
	dnssec_verify on;       # unset | on | off — inherits the global
	                         # default above when not given here
	dnssec_af_preference inet6;   # per-remote override, same tri-state shape
	exchange_mode main;
	...
}
```

`dnssec_verify` is tri-state per `remote` (`unset` / `on` / `off`), inheriting
the top-level default when unset — the same override shape Racoon already
uses elsewhere for per-remote settings. The global default is `off` for
backward compatibility: an existing config with only numeric `remote`
addresses must not suddenly require a resolvpaws backend or perform any DNS
validation it didn't ask for. The admin guide will recommend `on` as best
practice for any FQDN-based `remote`, but the shipped default stays
conservative.

There is no "best-effort" DNSSEC mode. Whatever `dnssec_verify` resolves to
for a given `remote` (explicit or inherited), `on` means Racoon refuses to
use a resolved address unless validation is definitively secure — matching
the request that motivated this RFC.

Config-parse-time fatal errors (fail closed, never a silent downgrade):

- A hostname `remote` when Racoon was built with `--disable-resolvpaws`.
- `dnssec_verify` resolving to `on` for a hostname `remote` when
  `dnssec_trust_anchor_file` (or every well-known per-distro default; see
  below) cannot be found/read — checked at startup, not deferred to first
  use.

### Trust anchor sourcing

Resolvpaws does not implement RFC 5011 root-key-rollover tracking itself —
that long-lived, security-critical state is deliberately left to whatever the
host system already maintains (e.g. Debian/Ubuntu's `unbound-anchor`-managed
`/var/lib/unbound/root.key`, or a distro's `dns-root-data` package). The
`libunbound` backend is pointed at that file. If `dnssec_trust_anchor_file` is
not set, the backend probes a short list of well-known per-distro paths (to be
finalized during implementation, e.g. `/var/lib/unbound/root.key`,
`/etc/unbound/root.key`, `/usr/share/dns/root.key`); if none exist and none
was explicitly configured, startup fails for any `remote` resolving to
`dnssec_verify on` rather than silently resolving without validation.

No fallback anchor is bundled in the Racoon source tree. A hardcoded anchor is
a reasonable one-time bootstrap trick (both `getdns` and `unbound` do this),
but it becomes a liability the moment a root key rollover happens and nobody
remembers Racoon is carrying its own stale copy — the whole point of
delegating to the system-maintained anchor is to have exactly one place that
needs to stay current on the box.

### Address-family selection

`dnssec_af_preference` (`inet` / `inet6` / `any`, default `inet`) is
tri-state per `remote` the same way `dnssec_verify` is, inheriting the global
default when unset.

Rationale for defaulting to sequential preference rather than racing both
families (as a browser's Happy Eyeballs would):

- Roadwarrior clients are frequently on networks with asymmetric or absent
  IPv6 (mobile hotspots, CGNAT, hotel wifi). "First secure wins" in practice
  means "whichever family the current network happens to support today,"
  so the same config picks a different gateway address on different
  networks — a debugging nightmare in the field.
- Racoon's existing reconnect-loop and NAT-T hardening around hotspot/conntrack
  churn already assumes a single deterministic address path per Phase 1
  attempt. A resolver layer that can nondeterministically flip between an A
  and AAAA record on retry reintroduces exactly the kind of extra variable
  that turns a one-line bug into a multi-day repro problem.
- IKEv1/NAT-T over IPv4 is Racoon's best-tested path; unconditionally racing
  to AAAA on a fresh network would exercise the least-tested path
  unpredictably in production.

Because `resolve()` already fetched and validated both families in one call,
selecting `inet` vs. `inet6` vs. `any` (first securely-validated family found,
in `inet`-then-`inet6` order) is a pure, synchronous, no-I/O step via
`resolvpaws_select()`. If the preferred family's negotiation subsequently
fails at the IKE layer (not a DNS failure — the resolved address simply
didn't establish), Racoon falls back to the other already-validated family
from the same `resolvpaws_result` rather than issuing a second resolvpaws
query. `RESOLVPAWS_AF_ANY` uses this same fallback behavior from the first
attempt rather than only after a failure.

### Resolution timing

Parse-time resolution (today's model) cannot track a Dynamic DNS change, so
hostname entries are resolved lazily instead:

- First resolution happens on first use, immediately before
  `isakmp_ph1begin_i()` is called for that `remoteconf` (new call sites at
  `isakmp.c:1981` and `isakmp.c:2213`, both of which currently read
  `rmconf->remote` / `iph1->remote` directly).
- A `sched_schedule()` task refreshes the resolution as the record's TTL
  approaches expiry, independent of any active negotiation.
- On resolution failure (`resolve()` fails, or `resolvpaws_select()` finds no
  family satisfying the configured preference at `RESOLVPAWS_SECURE`), Phase 1
  initiation for that `remoteconf` fails closed — no address substitution, no
  retry against a cached stale address.

### Address-change policy

If TTL-driven re-resolution or a new-negotiation resolution returns a
different address than an active Phase 1/Phase 2 SA is using: the existing
SA is left alone (no forced teardown). Only a *new* negotiation — a fresh
Phase 1 the peer initiates or Racoon initiates after the old SA expires or
DPD detects it's gone — uses the freshly resolved address. This avoids
disruptive teardown on every Dynamic DNS TTL cycle while still ensuring the
next reconnect goes to the current address.

### Build integration

`configure.ac`:

- `--with-libunbound=DIR`, structured like `--with-libldap`
  (`configure.ac:551-596`) — probe for `ub_resolve`/`ub_ctx_create`, allow a
  directory override, define `HAVE_LIBUNBOUND`, and error out (not silently
  disable) if explicitly requested but not found.
- `--disable-resolvpaws` (enabled by default) — fully removes FQDN/`remote`
  support and the `glibc` backend from the build for minimal deployments that
  only ever use numeric addresses. Distinct from backend selection: this
  toggle removes hostname support entirely rather than choosing how it's
  validated.

## Alternatives considered

- **Trust the OS resolver's `AD` bit unconditionally, no pluggable
  abstraction.** Rejected as the *only* option — it's kept as the `glibc`
  backend precisely because it has zero new dependencies, but it is only as
  trustworthy as the channel to the configured nameserver. Making it the sole
  option would mean "DNSSEC verified" secretly means "my possibly-unvalidated
  resolver said so," which is weaker than what this RFC's motivation calls
  for.
- **libunbound only, no abstraction layer.** Rejected because it forces every
  Racoon build to take on a real embedded validating-resolver dependency
  (root trust anchor management, cache/threading behavior) even for
  deployments that don't need FQDN gateways at all, contradicting Racoon's
  lean-footprint design principle (explicitly called out in RFC 0002's
  "Design Scope" for the same reason).
- **Runtime fallback chain (glibc → libunbound → systemd-resolved,
  automatically cascading on failure).** This was the initial framing
  discussed and explicitly rejected during design: a silent downgrade from a
  strong validator to a weaker one when the strong one fails to initialize
  defeats the purpose of a `dnssec_verify on` guarantee. Backend choice is
  compile-time only; a misconfigured/unavailable chosen backend is a hard
  startup error, not a fallback trigger.
- **Resolve once at parse time, accept staleness until restart.** Rejected —
  this is close to a no-op relative to the motivating problem (Dynamic DNS
  addresses changing daily); it would require an external reload mechanism,
  which is exactly the workaround this RFC exists to remove.
- **First-secure-wins / Happy-Eyeballs-style racing between A and AAAA.**
  Rejected as the default. It suits a browser picking between two equally
  acceptable web-server addresses; it is actively harmful for a roadwarrior
  VPN gateway, where it turns "which address did we connect to" into a
  function of momentary network conditions rather than operator intent, and
  reintroduces nondeterminism into a reconnect/NAT-T path that Racoon has
  already spent real effort hardening into a single deterministic flow. Kept
  as a possible future opt-in mode (`RESOLVPAWS_AF_ANY` gives ordered
  fallback, not racing) rather than the default.
- **Racoon manages its own DNSSEC root trust anchor.** Rejected — duplicating
  RFC 5011 rollover handling in a second place on the same box is exactly the
  kind of long-lived security-critical state that should have one owner.
  Resolvpaws consumes the system-maintained anchor instead (see Proposed
  Design, "Trust anchor sourcing").

## Compatibility

- **racoon.conf**: purely additive. Existing numeric `remote` addresses are
  unaffected — `str2saddr()`'s `AI_NUMERICHOST` path is unchanged for them.
  New syntax (hostname + `dnssec_verify on;`) is opt-in, and the global
  `dnssec_verify` default (`off`) preserves today's behavior for anyone who
  doesn't touch the new directives.
- **On-wire/IKEv1 behavior**: unaffected. Resolvpaws only changes how Racoon
  picks the destination address before opening a negotiation; it does not
  touch IKE payload construction or peer authentication, which remain the
  actual cryptographic trust boundary between peers.
- **Platform/build**: `--with-libunbound` is optional; a build without it is
  functionally identical to today for hostname-less configs, and still gets
  the `glibc` backend for anyone who opts into `dnssec_verify` without
  building against libunbound. `--disable-resolvpaws` removes hostname
  support entirely for minimal builds.

## Migration

None required. Existing configurations using numeric `remote` addresses need
no changes. Administrators who want FQDN gateways opt in by changing
`remote <ip>` to `remote "fqdn"` plus `dnssec_verify on;` (or setting the
global default once if they run several FQDN gateways).

## Risks

- **DNS zone compromise**: if the zone's DNSSEC signing key is compromised,
  a forged-but-validly-signed address would still be accepted. This is an
  accepted trust boundary — DNSSEC proves the zone operator authorized the
  record, not that the zone operator is uncompromised. IKE Phase 1 peer
  authentication (certs/PSK) remains the actual defense against connecting to
  an attacker; resolvpaws is a gate on *automated* address discovery, not a
  replacement for peer auth.
- **glibc backend's trust boundary is easy to misjudge**: `dnssec_verify on`
  reads as an absolute guarantee, but under the `glibc` backend it is only as
  strong as trust in the configured nameserver and the path to it. Mitigation:
  document this loudly in `racoon.conf.5` and recommend `--with-libunbound`
  for any deployment where "verified" needs to mean something under an
  untrusted network.
- **Increased DNS query volume / latency on negotiation**: resolving before
  every fresh Phase 1 could add latency. Mitigated by TTL-driven caching via
  the `sched_schedule()` refresh path — resolution only happens fresh at
  first use and at TTL expiry, not on every negotiation attempt.
- **Trust anchor availability becomes a hard startup dependency**: with no
  bundled fallback anchor, a `libunbound`-backed `remote` with `dnssec_verify
  on` cannot start if the system anchor file is missing or unreadable. This is
  intentional (fail closed, see Trust anchor sourcing) but is an operational
  change worth flagging clearly in release notes and the admin guide, since it
  can turn a routine OS reinstall/minimal-image choice ("no `unbound-anchor`
  package installed") into a Racoon startup failure.

## Open questions

- Exact probe list and probe order for well-known per-distro trust-anchor
  paths when `dnssec_trust_anchor_file` is unset — to be finalized against
  the actual distros in Racoon's support matrix during implementation.
- If `dnssec_af_preference` names a family for which the FQDN has no record
  at all (e.g. `inet6` preferred but the name is A-only), is that a hard
  failure (operator's preference was unsatisfiable) or an implicit fallback
  to the other family? Leaning toward implicit fallback with a logged
  warning, consistent with `RESOLVPAWS_AF_ANY`'s ordered-fallback behavior,
  but not decided here.

## Acceptance criteria

- [ ] `remote "hostname"` with `dnssec_verify on;` (explicit or inherited
      from the global default) parses successfully; the same hostname with
      `dnssec_verify` resolving to `off` — or with resolvpaws disabled at
      build time — fails config load with a clear, distinct error for each
      case.
- [ ] Global `dnssec_verify`/`dnssec_af_preference` defaults and per-`remote`
      tri-state overrides behave per the inheritance rule described above,
      with the global default itself defaulting to `off`/`inet`.
- [ ] `resolvpaws_ops` interface exists with at least the `glibc` backend
      buildable with zero new required dependencies; `--disable-resolvpaws`
      removes hostname support entirely.
- [ ] `--with-libunbound` configure flag builds the `unbound` backend,
      following the `--with-libldap` structural precedent (DIR override,
      `HAVE_*` define, explicit error if requested-but-missing).
- [ ] `resolve()` fetches and validates both A and AAAA in a single backend
      call; `resolvpaws_select()` performs family selection with no
      additional DNS query.
- [ ] A resolution returning anything other than `RESOLVPAWS_SECURE` for the
      selected family blocks Phase 1 initiation for that `remoteconf` with no
      address fallback to unvalidated data.
- [ ] `libunbound` backend fails startup (not silent unvalidated resolution)
      when `dnssec_verify on` applies to a `remote` and no readable trust
      anchor file is found, whether explicitly configured or probed.
- [ ] TTL-driven refresh is scheduled via `schedule.c` and observably
      re-resolves near expiry in a test environment using a short-TTL zone.
- [ ] An address change picked up by refresh does not tear down an active
      Phase 1/Phase 2 SA; the next new negotiation uses the updated address.
- [ ] A preferred-family IKE negotiation failure falls back to the other
      already-validated family from the same `resolvpaws_result` without
      issuing a second DNS resolution.
- [ ] `racoon.conf.5` documents the new syntax (`dnssec_verify`,
      `dnssec_af_preference`, `dnssec_trust_anchor_file`) and explicitly
      states the `glibc` backend's trust-boundary caveat and the
      fail-closed trust-anchor behavior.
