# RFC 0003: Resolvpaws — DNSSEC-Validated FQDN Resolution for Roadwarrior Gateways

## Status

Approved

## Authors

- Drafted via Claude Code at the request of @rdratlos

## Reviewers

- @rdratlos (decision)
- (open to community and domain-expert review — DNS/DNSSEC, resolver library maintainers)

## Revision notes

**v3** — merges the non-blocking async resolution model with the
tri-state config and trust-anchor decisions from prior review round
**v2** (an independently produced proposal, reviewed and merged here)
identified a real defect in v1's `resolvpaws_ops`: synchronous
`resolve(hostname, family, out)`, called on the negotiation path, would block
racoon's single-threaded `select()`/`poll()` loop for the duration of a
DNSSEC chain walk — stalling Phase 1 handling for *every* peer, not just the
one being resolved. v2 replaced this with an fd-driven async design
(`resolve_start()`/`resolve_readable()`/`resolve_cancel()`) integrated into
racoon's dispatcher, and separately tightened `resolvpaws_select()`'s
signature to use `sockaddr_storage` out-parameters instead of a
heap-allocated `struct sockaddr *` return, sidestepping an allocation-lifetime
question v1 had left unresolved. Both changes are adopted in this v3.

v2's own text flagged its central assumption — that racoon's dispatch loop
can register an arbitrary fd for read-readiness callbacks — as "inferred, not
yet confirmed against source." It has now been confirmed: `monitor_fd()`/
`unmonitor_fd()` already exist (`session.c:134`) and are the exact mechanism
needed, already used the same way by `isakmp.c:1728`, `admin.c:764`,
`pfkey.c:493`, and `grabmyaddr.c:315`. This de-risks the async redesign
considerably and is reflected in Current Design and Risks below.

v2's Revision Notes also justified the urgency of the async redesign partly
by citing "racoon's parallel DoS-hardening work (`force_aggressive` gate,
half-open rate limiting)." Neither exists anywhere in `src/racoon` — this
was checked directly against source and is not present in any form; every
"aggressive" hit in the codebase refers to IKE Aggressive Mode (the exchange
type), and there is no rate-limiting code at all. This does not weaken the
underlying argument — a stalled single-threaded event loop is a real problem
on its own merits, and arguably *more* concerning given the daemon has no
other mitigation for a slow negotiation path today, not less — but the
citation itself was incorrect and is not repeated in this revision.

Separately, v2 silently reopened three items this RFC had already closed in
an earlier review round, while its own Revision Notes claimed "no goals,
non-goals, or compatibility guarantees changed": the tri-state `dnssec_verify`
(`unset`/`on`/`off`) with a global default; the per-distro trust-anchor probe
order and `dnssec_trust_anchor_file` directive; and the `--disable-resolvpaws`
minimal-build flag. All three are restored in this v3 (Config grammar, Trust
anchor sourcing, Build integration below). v2's own "editorial note" flagged
an apparent tension between the tri-state/global-default mechanism and the
"no implicit insecure fallback" rule; that tension is addressed directly in
Config grammar below — it turns out to be apparent, not real.

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
- Resolve A and AAAA together as one logical operation, with an explicit,
  configurable address-family preference and deterministic (not raced)
  fallback policy shared across all backends via `resolvpaws_select()` — not
  a per-backend or per-call-site decision.
- Never block racoon's single-threaded event loop on DNS/DNSSEC resolution.
  Cold resolution (first use of a hostname `remoteconf`, or an expired cache
  entry) must be a non-blocking, fd-driven operation integrated into
  racoon's existing `monitor_fd()` dispatcher; only an already-cached,
  non-expired result may be consulted synchronously on the negotiation path.
- Track the record's TTL and re-resolve near expiry so a Dynamic-DNS address
  change is picked up without requiring a config reload or daemon restart.
- Preserve Racoon's low footprint and lean dependency profile: DNSSEC
  validation strength is a compile-time choice (`--with-libunbound`), not a
  mandatory new hard dependency for everyone who builds Racoon, and hostname
  support itself is a compile-time-removable feature (`--disable-resolvpaws`)
  for minimal builds that never need it.
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
  is designed to accommodate it — D-Bus connections are themselves fd-based,
  so the async `resolve_start()`/`resolve_readable()` shape below should
  extend to it without another interface revision, though that is an
  untested assumption, not a guarantee. It is not built here regardless:
  Racoon commonly runs privileged/chrooted, and D-Bus socket reachability
  under Racoon's privilege-drop model needs its own investigation before
  committing to it.
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
  that separation, plus a *deferred/pending* variant of that choke point for
  the cold-cache case (see Resolution timing).
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
- Racoon's dispatch loop already has a general-purpose fd-registration
  mechanism: `monitor_fd(fd, callback, ctx, priority)` /
  `unmonitor_fd(fd)` (`session.c:134`, `session.c:158`, declared
  `session.h:40-41`). It is already used the same way resolvpaws needs it:
  `isakmp.c:1728` (per-exchange socket), `admin.c:764` (admin socket),
  `pfkey.c:493` (PF_KEY socket), and `grabmyaddr.c:315` (routing socket).
  This confirms the async `resolve_start()`/`resolve_readable()` design below
  has a real, already-proven integration point — it is not a speculative
  dependency on dispatcher capabilities that don't yet exist.
- Precedent for compile-time-optional dependencies already exists in
  `configure.ac`: `--with-libldap` (`configure.ac:551-596`) is the closest
  structural match — probes for the library, allows a `DIR` override, defines
  a `HAVE_*` macro, and conditionally adds to `LIBS`/`CPPFLAGS`.
- Racoon already has a precedent for deterministic, single-owner runtime
  state over coexistence/racing alternatives: `kernelpaws` (RFC 0002)
  deliberately uses host-wide `FLUSHSA`/`FLUSHPOLICY` and assumes exclusive
  ownership of the XFRM tables rather than tracking per-daemon state for
  coexistence — "a deliberate trade-off: simplicity over coexistence,
  consistent with Racoon's lightweight design philosophy." Resolvpaws'
  address-family selection follows the same theme: one deterministic path
  per attempt, not a race.

## Proposed design

### Architecture

```
+---------------------------+
|   racoon daemon           |
|                           |
|  resolvpaws.h             |  <-- unified ops interface
|  resolvpaws_ops           |  <-- function pointer table, compile-time selected
|  resolvpaws_select()      |  <-- backend-independent AF preference/fallback
|                           |
|  +-----------------------+|
|  | resolvpaws_glibc.c    ||  <-- hand-rolled non-blocking stub resolver
|  |                       ||      (UDP/TCP to resolv.conf nameservers) +
|  |                       ||      manual AD-bit check. getaddrinfo()/
|  |                       ||      res_query() are NOT used — both block,
|  |                       ||      and getaddrinfo() can't expose the AD
|  |                       ||      bit at all. Default backend when
|  |                       ||      resolvpaws is enabled.
|  +-----------------------+|
|                           |
|  +-----------------------+|
|  | resolvpaws_unbound.c  ||  <-- libunbound: ub_resolve_async()/ub_fd()/
|  |                       ||      ub_process(), full RRSIG/DNSKEY/DS
|  |                       ||      validation. (--with-libunbound)
|  +-----------------------+|
+---------------------------+
         |
         v  fd registered via racoon's existing monitor_fd() (session.c:134)
   resolve_start() -> [event loop polls fd] -> resolve_readable() -> cb()
         |
         v
   sched_schedule() refresh timer, armed from min(inet.ttl_expiry,
   inet6.ttl_expiry) across whichever families resolved SECURE
```

`resolvpaws_sdresolved.c` (systemd-resolved D-Bus backend) is named here as a
future backend per Non-goals; no code is written for it in this RFC.

Resolvpaws itself is a compile-time-optional component
(`--disable-resolvpaws` for truly minimal builds that never need FQDN
gateways at all; enabled by default). When disabled, a hostname in `remote`
is a config-parse-time fatal error — the same hard-refusal behavior
`AI_NUMERICHOST` already gives today, just with a clearer diagnostic. When
enabled, the `glibc` backend is always available with zero extra library
dependencies; `libunbound` is additionally available only when
`--with-libunbound` was used at build time.

### resolvpaws_ops interface

A single `resolve_start()` call begins resolution for **both** address
families together — one logical operation, not one per family and not a
second round trip when a fallback is later needed — and returns immediately
without blocking. Family *selection* over the settled result is a separate,
synchronous, no-I/O step (`resolvpaws_select()`), keeping "resolve" and
"select" cleanly divided:

```c
enum resolvpaws_status {
	RESOLVPAWS_SECURE,        /* record present, DNSSEC validation succeeded */
	RESOLVPAWS_NODATA,        /* zone is secure but no record of this type
	                              exists (e.g. AAAA absent on an A-only zone) —
	                              benign, distinct from a validation failure */
	RESOLVPAWS_INSECURE,      /* zone is unsigned / opts out of DNSSEC */
	RESOLVPAWS_BOGUS,         /* validation failed: signature/chain broken */
	RESOLVPAWS_INDETERMINATE, /* could not build a chain of trust */
	RESOLVPAWS_ERROR,         /* NXDOMAIN, timeout, transport failure, etc. */
};

enum resolvpaws_af_pref {
	RESOLVPAWS_AF_INET,   /* prefer A; fall back to AAAA if unusable */
	RESOLVPAWS_AF_INET6,  /* prefer AAAA; fall back to A if unusable */
	RESOLVPAWS_AF_ANY,    /* no operator preference declared; deterministic
	                          default order (A first), no fallback logging */
};

struct resolvpaws_addr {
	enum resolvpaws_status status;
	struct sockaddr_storage addr;  /* valid iff status == RESOLVPAWS_SECURE */
	time_t ttl_expiry;             /* absolute; valid iff status == SECURE */
};

struct resolvpaws_result {
	struct resolvpaws_addr inet;   /* A record outcome, always populated */
	struct resolvpaws_addr inet6;  /* AAAA record outcome, always populated */
};

/* Opaque, backend-owned handle for one in-flight resolution. Caller holds
 * this only to pass back to resolve_readable()/resolve_cancel(); never
 * dereferenced by racoon. */
struct resolvpaws_query;

typedef void (*resolvpaws_cb)(struct resolvpaws_query *q,
                               const struct resolvpaws_result *result,
                               void *userdata);

struct resolvpaws_ops {
	const char *name;

	int  (*init)(void);
	void (*cleanup)(void);

	/*
	 * Begins resolution for both A and AAAA. Returns immediately —
	 * never blocks. *fd_out receives one fd for racoon's monitor_fd()
	 * dispatcher to poll for readability: exactly one, for the life of
	 * the query, regardless of how many underlying transactions the
	 * backend needs internally (A+AAAA in parallel, TCP retry on
	 * truncation, DNSSEC chain walk, etc.). Returns NULL and sets
	 * *fd_out = -1 on a hard backend failure (not initialized, resource
	 * exhaustion) — distinct from a resolution outcome, which always
	 * arrives via cb() instead.
	 */
	struct resolvpaws_query *(*resolve_start)(const char *hostname,
	                                            resolvpaws_cb cb,
	                                            void *userdata,
	                                            int *fd_out);

	/*
	 * Called by racoon's dispatcher when fd_out is readable. May invoke
	 * cb() zero times (partial progress — chain validation mid-flight,
	 * or A arrived but AAAA hasn't) or exactly once (both families
	 * settled, terminal). Never invoked more than once per query.
	 */
	void (*resolve_readable)(struct resolvpaws_query *q);

	/*
	 * Cancels an in-flight query — remoteconf torn down, or racoon's
	 * own bounded timeout (see Resolution timing) expired first.
	 * Releases fd_out (via unmonitor_fd()) and all backend state for
	 * the query. Never invokes cb().
	 */
	void (*resolve_cancel)(struct resolvpaws_query *q);
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

`resolvpaws_unbound_ops` maps directly onto libunbound's existing async API
(`ub_resolve_async()` + `ub_fd()` + `ub_process()`) — that library was
already usable this way; the only change from v1 is that resolvpaws now
actually uses it. `resolvpaws_glibc_ops` requires a small hand-rolled
non-blocking stub resolver (see Risks) since neither `getaddrinfo()` nor
`res_query()` are both non-blocking and AD-bit-visible, and `getaddrinfo_a()`
was considered and rejected (see Alternatives considered).

### resolvpaws_select()

```c
/*
 * Backend-independent: applies dnssec_af_preference to an already-
 * populated resolvpaws_result and selects the address to dial. Lives
 * outside resolvpaws_ops so fallback policy is identical across backends
 * and isn't duplicated at isakmp.c call sites. Pure and synchronous — never
 * triggers a new DNS query.
 *
 * On success: fills *chosen and *ttl_expiry_out, returns 0.
 * *fallback_used_out is set only when an explicit preference (INET or
 * INET6) was overridden — never for AF_ANY, since no preference was
 * violated. When fallback occurred, *skipped_status_out carries the
 * preferred family's status, so the caller can choose log severity:
 * NODATA on the skipped family is a naming/provisioning fact (log at
 * notice); INSECURE/BOGUS/INDETERMINATE is a security-relevant asymmetry
 * (log at warning+) even though the resulting fallback action — dial the
 * other family — is identical either way.
 *
 * Returns -1 if no family is usable at all — caller fails Phase 1
 * initiation closed, unchanged from today's behavior.
 */
int resolvpaws_select(const struct resolvpaws_result *result,
                       enum resolvpaws_af_pref pref,
                       struct sockaddr_storage *chosen,
                       time_t *ttl_expiry_out,
                       int *fallback_used_out,
                       enum resolvpaws_status *skipped_status_out);
```

`fallback_used_out`/`skipped_status_out` exist so a caller — the log line,
and eventually a NetworkManager-style front-end, which is the whole
motivating use case for this feature — can surface *why* a fallback happened,
not just that an address was returned, at zero extra cost since both
families were already fetched together by `resolve_start()`.

### Config grammar

`remote` gains the ability to take a quoted hostname anywhere it currently
takes `ike_addrinfo_port`'s numeric-address form. Three directives control
it — two global with per-remote overrides, one per-remote only:

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
conservative. `dnssec_af_preference` follows the identical tri-state/global-
default shape for the same reason (an admin running several FQDN gateways
shouldn't have to repeat it per block).

**On the apparent tension between a global default and "no implicit insecure
fallback":** these do not conflict. The *unconfigured-anywhere* default is
`off`, matching today's pre-feature behavior exactly — a config that never
mentions `dnssec_verify` at all gets no DNS validation and no hostname
support surprises. A given `remote` resolves to `on` only when *some*
statement in the config said so — either directly on that `remote` block, or
via an explicit `dnssec_verify on;` the admin wrote at the top of the file
and meant to apply everywhere. There is no path by which a hostname `remote`
silently ends up validated when the admin didn't ask for it, nor one where it
silently ends up unvalidated despite the admin having declared a global `on`.
The tri-state/inheritance mechanism exists purely to avoid repeating the
directive across many `remote` blocks; it does not introduce a new implicit-
insecure code path, and config parsing still hard-fails if a hostname
`remote`'s *effective* (post-inheritance) `dnssec_verify` value is anything
but `on`.

Config-parse-time fatal errors (fail closed, never a silent downgrade):

- A hostname `remote` when Racoon was built with `--disable-resolvpaws`.
- A hostname `remote` whose effective `dnssec_verify` (explicit or inherited)
  is not `on`.
- `dnssec_verify` resolving to `on` for a hostname `remote` when
  `dnssec_trust_anchor_file` (or every well-known per-distro default; see
  below) cannot be found/read — checked at startup, not deferred to first
  use.

### Trust anchor sourcing

Resolvpaws does not implement RFC 5011 root-key-rollover tracking itself —
that long-lived, security-critical state is deliberately left to whatever the
host system already maintains. `dnssec_trust_anchor_file`, when set, points
the `libunbound` backend directly at that file. When unset, the backend
probes a short, distro-ordered list of well-known paths and uses the first
one found. This is a startup-time, one-shot check (part of `ub_ctx_create()`
setup, not per-query), so it has no interaction with the async resolution
path above.

There are two distinct lineages of "the root anchor file" on Linux, and
probe order needs to prefer the one that's actually being kept current over a
static distro-package copy:

- The **resolver-self-managed anchor**: written and RFC 5011-tracked by
  `unbound-anchor` itself, wired up via `auto-trust-anchor-file` in the
  distro's default `unbound.conf` when `unbound` is installed.
- The **distro-shared anchor**: a static file installed by a dedicated
  package (`dns-root-data` on Debian/Ubuntu, `dnssec-anchors` on Arch)
  specifically so multiple resolvers/tools on the box can share one
  package-maintained copy, independent of whether `unbound` itself is
  present.

Probe order per distro family (finalized here; verified against each
distro's `unbound-anchor` documentation):

- **Ubuntu (18.04 Bionic through the current LTS) and Debian ≥ 13 (Trixie)**:
  probe both `/var/lib/unbound/root.key` (the `unbound`-package-managed,
  RFC 5011-tracked path) and `/usr/share/dns/root.key` (the `dns-root-data`
  package's static file). Debian's own `unbound-anchor` documentation treats
  `/usr/share/dns/root.key` as its default when `unbound` is installed from
  Debian packaging, while Ubuntu's documents `/var/lib/unbound/root.key` —
  the two distros disagree on which is canonical. Rather than hardcode a
  per-distro order that can drift, use whichever of the two exists and is
  non-empty; if both exist, prefer the more recently modified one, since
  that is the one most likely being kept current by RFC 5011 tracking.
- **Arch Linux**: probe `/etc/unbound/trusted-key.key` first (what Arch's
  `unbound` package config references via `trust-anchor-file:
  trusted-key.key` relative to `directory: "/etc/unbound"`), then
  `/etc/trusted-key.key` (the `dnssec-anchors` package's canonical file,
  which `/etc/unbound/trusted-key.key` is normally a pacman-hook-refreshed
  copy of). Probing the copy first and falling back to the canonical file
  covers both an `unbound`-installed box and a headless Racoon-only box
  that only has `dnssec-anchors` installed.

If none of the probed paths exist (and none was explicitly configured via
`dnssec_trust_anchor_file`), that is a fatal error at startup for any
`remote` resolving to `dnssec_verify on` — "no anchor found" is treated the
same as "explicitly configured anchor unreadable," never as a silent skip
into unvalidated resolution.

No fallback anchor is bundled in the Racoon source tree. A hardcoded anchor is
a reasonable one-time bootstrap trick (both `getdns` and `unbound` do this),
but it becomes a liability the moment a root key rollover happens and nobody
remembers Racoon is carrying its own stale copy — the whole point of
delegating to the system-maintained anchor is to have exactly one place that
needs to stay current on the box.

### Address-family selection

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

Because `resolve_start()` already fetches and validates both families
together, selecting `inet` vs. `inet6` vs. `any` (first securely-validated
family found, in `inet`-then-`inet6` order) via `resolvpaws_select()` is a
pure, synchronous, no-I/O step. If the preferred family's negotiation
subsequently fails at the IKE layer (not a DNS failure — the resolved
address simply didn't establish), Racoon falls back to the other already-
validated family from the same cached `resolvpaws_result` rather than
issuing a second resolvpaws query. `RESOLVPAWS_AF_ANY` uses this same
fallback behavior from the first attempt rather than only after a failure.

An unsatisfiable preference (the preferred family has no usable, securely
validated address) is handled as implicit fallback to the other family with
a logged warning, not a hard failure — consistent with `RESOLVPAWS_AF_ANY`'s
own ordered-fallback semantics rather than introducing a second, different
failure mode for what is fundamentally the same situation (preferred family
unavailable, other family usable). But "unavailable" has two causes that must
not be logged, or surfaced to a future UI, identically:

- **`skipped_status_out == RESOLVPAWS_NODATA`** — the preferred family simply
  has no record published (e.g. `inet6` preferred, the name is A-only). This
  is a naming/provisioning fact, not a security event — exactly the shape of
  the SOHO case where the DDNS provider is IPv4-only. Log at `notice`.
- **`skipped_status_out` is `RESOLVPAWS_BOGUS` or `RESOLVPAWS_INDETERMINATE`**
  — a record exists for the preferred family but failed DNSSEC validation
  while the other family validated fine. This is a security-relevant
  asymmetry: an admin needs to be able to tell "this name just doesn't
  publish AAAA" apart from "someone is tampering with AAAA responses for
  this name" from the log alone. Log at `warning` or above even though the
  resulting fallback address is identical to the `NODATA` case.

`fallback_used_out`/`skipped_status_out` are surfaced past the log line too
— a future NetworkManager-style front-end (the actual motivating use case
for this feature) can render "connected, but your IPv6 preference wasn't
honored" as a visible connection state rather than something that only ever
lived in a log file.

### Resolution timing

Parse-time resolution (today's model) cannot track a Dynamic DNS change, and
resolution must never block the event loop (see Goals), so hostname entries
are resolved lazily and asynchronously. Each hostname `remoteconf` carries
one of three states:

- **Unresolved (cold)**: no cached `resolvpaws_result`, or the cached one has
  expired past its TTL and no refresh has completed yet.
- **Pending**: a `resolve_start()` call is in flight; its fd is registered
  with racoon's dispatcher via `monitor_fd()`.
- **Resolved (cache hit)**: a non-expired `resolvpaws_result` is cached on
  the `remoteconf`.

State transitions:

- A Phase 1 initiation request against a **resolved** `remoteconf` calls
  `resolvpaws_select()` synchronously against the cached result and proceeds
  to `isakmp_ph1begin_i()` immediately — identical latency to today's
  behavior. This is the steady-state path for every negotiation after the
  first for a given hostname.
- A Phase 1 initiation request against an **unresolved** `remoteconf`
  transitions it to pending, calls `resolve_start()`, registers the returned
  fd with `monitor_fd()`, and queues the negotiation request rather than
  calling `isakmp_ph1begin_i()` inline. Racoon's event loop continues
  servicing all other peers and negotiations normally while this is pending.
- A second initiation request arriving for a `remoteconf` that is already
  **pending** (retransmit, peer-initiated retry) attaches to the existing
  pending query instead of calling `resolve_start()` again — dedup is keyed
  on `remoteconf`, not on the caller.
- When the dispatcher reports the query's fd readable, `resolve_readable()`
  runs. If it invokes `cb()` with a terminal result, the `remoteconf`
  transitions to resolved (on any family reaching `RESOLVPAWS_SECURE`) or
  back to unresolved (`resolvpaws_select()` finds no usable family — fails
  closed), and any queued negotiation requests are released to proceed or
  fail accordingly. `unmonitor_fd()` is called as part of this transition.
- A `sched_schedule()` timer bounds how long a pending resolution may run.
  On expiry, `resolve_cancel()` is called and the pending negotiation(s) fail
  closed exactly as a `RESOLVPAWS_ERROR` result would — the timeout is a
  resolution outcome, not a separate failure mode requiring its own handling.
- Independent of any negotiation, the same `sched_schedule()` subsystem
  refreshes a **resolved** `remoteconf` as its cached TTL approaches expiry —
  armed from `min(inet.ttl_expiry, inet6.ttl_expiry)` across whichever
  families are currently `SECURE`, so both stay fresh regardless of which one
  `dnssec_af_preference` currently selects. A refresh that comes back with no
  usable family transitions the `remoteconf` back to unresolved; it does
  **not** retry immediately on a fixed schedule beyond the normal TTL-driven
  timer — the next attempt is either the next scheduled refresh or a new
  negotiation request re-triggering `resolve_start()`, whichever comes first.
- On any resolution failure (pending timeout, or a terminal result with no
  `SECURE` family), Phase 1 initiation for that `remoteconf` fails closed —
  no address substitution, no retry against a cached stale address.

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
  (`configure.ac:551-596`) — probe for `ub_resolve_async`/`ub_ctx_create`
  (the async entry point, not the blocking `ub_resolve`, given the interface
  above), allow a directory override, define `HAVE_LIBUNBOUND`, and error out
  (not silently disable) if explicitly requested but not found.
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
- **Two separate `resolve()` calls, one per address family.** This was the
  original (v1) shape. Rejected on review: it forced two independent
  DNS/DNSSEC transactions per hostname with no shared place to record that an
  address-family fallback had occurred, which made the dual-stack preference
  problem impossible to answer cleanly at the API level. Superseded by the
  single combined `resolve_start()` call plus the backend-independent
  `resolvpaws_select()`.
- **Synchronous `resolve()`, or a non-blocking wrapper built on
  `getaddrinfo_a()`.** `getaddrinfo_a()`'s non-blocking behavior is
  implemented via a hidden pthread inside glibc, not an fd racoon's own
  event loop can observe. For a deliberately single-threaded daemon, a
  library-internal thread is arguably worse than the blocking call it
  replaces: it violates the single-threaded assumption invisibly, with no
  fd for racoon's dispatcher to reason about or bound with a timeout.
  Rejected in favor of the fd-driven `resolve_start()`/`resolve_readable()`
  pair, which keeps racoon's existing `monitor_fd()`-based event loop as the
  only scheduler in the process.

## Compatibility

- **racoon.conf**: purely additive. Existing numeric `remote` addresses are
  unaffected — `str2saddr()`'s `AI_NUMERICHOST` path is unchanged for them.
  New syntax (hostname + `dnssec_verify on;`, optional `dnssec_af_preference`,
  `dnssec_trust_anchor_file`) is opt-in, and the global `dnssec_verify`
  default (`off`) preserves today's behavior for anyone who doesn't touch the
  new directives.
- **On-wire/IKEv1 behavior**: unaffected. Resolvpaws only changes how Racoon
  picks the destination address before opening a negotiation; it does not
  touch IKE payload construction or peer authentication, which remain the
  actual cryptographic trust boundary between peers.
- **Platform/build**: `--with-libunbound` is optional; a build without it is
  functionally identical to today for hostname-less configs, and still gets
  the `glibc` backend for anyone who opts into `dnssec_verify` without
  building against libunbound. `--disable-resolvpaws` removes hostname
  support entirely for minimal builds.
- **Daemon behavior under load**: a cold hostname `remoteconf` no longer
  blocks the event loop, so concurrent negotiations against other peers are
  unaffected by a slow or unresponsive resolution elsewhere — see Acceptance
  criteria.

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
  strong as trust in the configured nameserver and the path to it. The
  non-blocking constraint sharpens this further: the glibc backend cannot
  lean on libc's `getaddrinfo()`/`res_query()` at all, so it talks to
  whatever's in `resolv.conf` via racoon's own stub resolver code, with no
  libc-mediated indirection. Mitigation: document this loudly in
  `racoon.conf.5` and recommend `--with-libunbound` for any deployment where
  "verified" needs to mean something under an untrusted network.
- **glibc backend's hand-rolled stub resolver is new attack surface**:
  satisfying "non-blocking" and "AD-bit visible" together (neither
  `getaddrinfo()` nor blocking `res_query()` qualify) means the glibc backend
  has to construct DNS query packets and parse responses itself over a raw
  UDP/TCP socket, rather than delegating that parsing to a hardened,
  widely-audited libc routine. This is new, racoon-owned packet-parsing code
  that didn't exist before this RFC. The surface is small and well
  understood (DNS message parsing is a solved problem with plenty of
  reference implementations to model against), but it should get dedicated
  fuzzing/Valgrind attention given the project's existing testing discipline,
  not be treated as a trivial addition.
- **Concurrent cold-resolution volume**: a burst of many simultaneous cold
  `remoteconf` entries (e.g. daemon restart with many configured FQDN peers)
  submits that many concurrent async queries to the resolver backend at
  once. `libunbound` handles concurrent async queries natively; the
  hand-rolled `glibc` backend's stub resolver needs to be written with this
  in mind from the start (bounded concurrent transaction state, not a
  design retrofit). Worth load-testing rather than assuming linear scaling.
- **libunbound root trust anchor maintenance**: an embedded validating
  resolver needs a root trust anchor that itself needs updating over time
  (RFC 5011 rollover). Addressed by consuming the system-maintained anchor
  file rather than Racoon tracking rollover itself — see "Trust anchor
  sourcing" above — but it does mean anchor availability becomes a hard
  startup dependency for any `libunbound`-backed `remote` with `dnssec_verify
  on`: a missing/unreadable anchor is a Racoon startup failure, not a
  degraded mode. This is intentional (fail closed) but worth flagging
  clearly in release notes and the admin guide, since it can turn a routine
  OS reinstall or minimal-image choice ("no `unbound-anchor` package
  installed") into an unexpected startup failure.

## Open questions

None outstanding as of this revision. Every question raised across prior
review rounds has been resolved and is recorded in the relevant section
above:

- Per-remote vs. global `dnssec_verify` → "Config grammar" (tri-state,
  global default `off`, with the apparent tension against "no implicit
  insecure fallback" addressed directly there).
- Trust anchor sourcing/refresh story → "Trust anchor sourcing" (system-
  maintained anchor only, per-distro probe order, no bundled fallback).
- IPv4/IPv6 dual-stack preference order → "Address-family selection" and
  the `resolvpaws_select()` interface (explicit `dnssec_af_preference`,
  deterministic sequential fallback, no racing).
- Whether racoon's dispatch loop can support fd-driven async resolution →
  "Current design" (confirmed: `monitor_fd()`, `session.c:134`).

The CERT-RR-onto-`resolvpaws_backend` migration remains a deliberately
deferred *candidate for a future RFC 0004* (see Non-goals) rather than an
open question of this RFC — it is out of scope here by design, not
unresolved.

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
- [ ] `--with-libunbound` configure flag builds the `unbound` backend against
      `ub_resolve_async`, following the `--with-libldap` structural precedent
      (DIR override, `HAVE_*` define, explicit error if requested-but-missing).
- [ ] `resolve_start()` fetches and validates both A and AAAA as one
      operation; `resolvpaws_select()` performs family selection with no
      additional DNS query.
- [ ] A resolution returning no `RESOLVPAWS_SECURE` family for the selected
      preference blocks Phase 1 initiation for that `remoteconf` with no
      address fallback to unvalidated data.
- [ ] `libunbound` backend fails startup (not silent unvalidated resolution)
      when `dnssec_verify on` applies to a `remote` and no readable trust
      anchor file is found via `dnssec_trust_anchor_file` or the per-distro
      probe list (Ubuntu/Debian: `/var/lib/unbound/root.key` and
      `/usr/share/dns/root.key`, newest-mtime-wins if both exist; Arch:
      `/etc/unbound/trusted-key.key` then `/etc/trusted-key.key`).
- [ ] TTL-driven refresh is scheduled via `schedule.c`, armed from
      `min(inet.ttl_expiry, inet6.ttl_expiry)`, and observably re-resolves
      near expiry in a test environment using a short-TTL zone.
- [ ] An address change picked up by refresh does not tear down an active
      Phase 1/Phase 2 SA; the next new negotiation uses the updated address.
- [ ] A preferred-family IKE negotiation failure falls back to the other
      already-validated family from the same cached `resolvpaws_result`
      without issuing a second DNS resolution.
- [ ] An unsatisfiable `dnssec_af_preference` falls back rather than hard-
      failing, with `resolvpaws_select()`'s `skipped_status_out`
      distinguishing `RESOLVPAWS_NODATA` (logged at `notice`) from a
      validation failure on the preferred family (logged at `warning` or
      above) even though both produce the same fallback address.
- [ ] Resolution for a cold `remoteconf` does not block the daemon's
      handling of concurrent, unrelated Phase 1 exchanges — verified by a
      test that starts a slow/unresponsive-resolver resolution and confirms
      an unrelated peer's negotiation completes normally in the meantime.
- [ ] A pending resolution that exceeds its bounded timeout is cancelled via
      `resolve_cancel()` and the queued negotiation fails closed, without
      leaking the backend's fd (`unmonitor_fd()` called) or query state
      (Valgrind-clean).
- [ ] A negotiation against an already-resolved (cache-hit) `remoteconf`
      shows no measurable added latency versus today's baseline.
- [ ] `racoon.conf.5` documents the new syntax (`dnssec_verify`,
      `dnssec_af_preference`, `dnssec_trust_anchor_file`) and explicitly
      states the `glibc` backend's trust-boundary caveat and the
      fail-closed trust-anchor behavior.
