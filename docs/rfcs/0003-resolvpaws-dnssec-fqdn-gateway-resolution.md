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
  address) and out of scope, though it may eventually be worth migrating onto
  the same resolvpaws backend rather than `getrrsetbyname()` — noted as an
  open question, not committed here.
- IKEv2 — scope is IKEv1 only, consistent with the rest of Racoon.
- Re-resolving or redirecting an already-established Phase 1/Phase 2 SA mid-
  session. See Proposed Design for the chosen policy (existing SAs ride out;
  only new/rekey negotiations use a freshly resolved address).

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
|  | .c                ||      (always built; the default)
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

### resolvpaws_ops interface

```c
enum resolvpaws_status {
	RESOLVPAWS_SECURE,        /* DNSSEC validation succeeded: use this address */
	RESOLVPAWS_INSECURE,      /* zone is unsigned / opts out of DNSSEC */
	RESOLVPAWS_BOGUS,         /* validation failed: signature/chain broken */
	RESOLVPAWS_INDETERMINATE, /* could not build a chain of trust */
	RESOLVPAWS_ERROR,         /* NXDOMAIN, timeout, transport failure, etc. */
};

struct resolvpaws_result {
	struct sockaddr *addr;   /* NULL unless status == RESOLVPAWS_SECURE */
	time_t ttl_expiry;       /* absolute time; used to schedule refresh */
};

struct resolvpaws_ops {
	const char *name;

	int  (*init)(void);
	void (*cleanup)(void);

	enum resolvpaws_status (*resolve)(const char *hostname, int family,
	                                   struct resolvpaws_result *out);
};

extern const struct resolvpaws_ops *const resolvpaws_backend;
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
takes `ike_addrinfo_port`'s numeric-address form. A new mandatory sub-directive
inside the `remote { }` block, `dnssec_verify on;`/`off;` (default `off`),
gates it:

```
remote "vpn.example.com" {
	dnssec_verify on;
	exchange_mode main;
	...
}
```

If a hostname is given and `dnssec_verify` is not explicitly `on`, config
parsing fails with an explicit error — there is no implicit insecure
fallback. `strict` here is the only mode; there is no "best-effort" DNSSEC
option, matching the request that motivated this RFC (force Racoon to trust
the resolved address only if DNSSEC verifies it, full stop).

### Resolution timing

Parse-time resolution (today's model) cannot track a Dynamic DNS change, so
hostname entries are resolved lazily instead:

- First resolution happens on first use, immediately before
  `isakmp_ph1begin_i()` is called for that `remoteconf` (new call sites at
  `isakmp.c:1981` and `isakmp.c:2213`, both of which currently read
  `rmconf->remote` / `iph1->remote` directly).
- A `sched_schedule()` task refreshes the resolution as the record's TTL
  approaches expiry, independent of any active negotiation.
- On resolution failure (any non-`RESOLVPAWS_SECURE` status), Phase 1
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

`configure.ac`: add `--with-libunbound=DIR`, structured like `--with-libldap`
(`configure.ac:551-596`) — probe for `ub_resolve`/`ub_ctx_create`, allow a
directory override, define `HAVE_LIBUNBOUND`, and error out (not silently
disable) if explicitly requested but not found.

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

## Compatibility

- **racoon.conf**: purely additive. Existing numeric `remote` addresses are
  unaffected — `str2saddr()`'s `AI_NUMERICHOST` path is unchanged for them.
  New syntax (hostname + `dnssec_verify on;`) is opt-in.
- **On-wire/IKEv1 behavior**: unaffected. Resolvpaws only changes how Racoon
  picks the destination address before opening a negotiation; it does not
  touch IKE payload construction or peer authentication, which remain the
  actual cryptographic trust boundary between peers.
- **Platform/build**: `--with-libunbound` is optional; a build without it is
  functionally identical to today for hostname-less configs, and still gets
  the `glibc` backend for anyone who opts into `dnssec_verify` without
  building against libunbound.

## Migration

None required. Existing configurations using numeric `remote` addresses need
no changes. Administrators who want FQDN gateways opt in by changing
`remote <ip>` to `remote "fqdn"` plus `dnssec_verify on;`.

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
- **libunbound root trust anchor maintenance**: an embedded validating
  resolver needs a root trust anchor that itself needs updating over time
  (RFC 5011 rollover). Needs a documented operational story (e.g., depend on
  the system's `unbound-anchor`-maintained anchor file) before this backend
  ships — flagged as an open question below.

## Open questions

- Should `dnssec_verify` be a per-`remote` boolean, or should there also be a
  global default so administrators with many FQDN gateways don't repeat it?
- Root trust anchor sourcing/refresh story for the `libunbound` backend —
  reuse the system's existing anchor file vs. Racoon managing its own?
- Should the existing CERT-RR peer-identity code (`dnssec.c`,
  `getcertsbyname.c`) eventually be migrated onto `resolvpaws_backend`
  instead of `getrrsetbyname()`, given the latter is effectively obsolete? Not
  committed in this RFC; noted for a possible follow-up.
- IPv4/IPv6 dual-stack preference order when both A and AAAA are present and
  both validate securely — first-secure-wins, or an explicit preference
  directive?

## Acceptance criteria

- [ ] `remote "hostname"` with `dnssec_verify on;` parses successfully;
      the same syntax without `dnssec_verify on;` fails config load with a
      clear error.
- [ ] `resolvpaws_ops` interface exists with at least the `glibc` backend
      buildable with zero new required dependencies.
- [ ] `--with-libunbound` configure flag builds the `unbound` backend,
      following the `--with-libldap` structural precedent (DIR override,
      `HAVE_*` define, explicit error if requested-but-missing).
- [ ] A resolution returning anything other than `RESOLVPAWS_SECURE` blocks
      Phase 1 initiation for that `remoteconf` with no address fallback.
- [ ] TTL-driven refresh is scheduled via `schedule.c` and observably
      re-resolves near expiry in a test environment using a short-TTL zone.
- [ ] An address change picked up by refresh does not tear down an active
      Phase 1/Phase 2 SA; the next new negotiation uses the updated address.
- [ ] `racoon.conf.5` documents the new syntax and explicitly states the
      `glibc` backend's trust-boundary caveat.
