# TODO / XXX Markup Analysis — Security & Quality Assessment

**Status:** Draft for review
**Scope:** All `TODO` and `XXX` source-code comments on `develop`
**Analyzed commit:** `69d1129` (`racoonctl: replace confusing "send: Bad file descriptor" with a real diagnostic`)
**Date:** 2026-07-22

---

## 1. Executive summary

`develop` carries **194 `TODO`/`XXX` occurrences across 47 files** (192 real markers; 2 are `mkstemp()`
template strings that only *look* like `XXX` — `test/test_x509_cert.c:93`, `test/test_rsa_comprehensive.c:2547`
— and are excluded from the rest of this report). These comments are the project's own developers flagging
things they were unsure about, hadn't finished, or knew were fragile — a fundamentally different signal
than what a pattern-matching security scanner looks for.

This review reads every one of the 192 markers in context and classifies it by **type**
(security / functional / RFC-compliance / missing-feature / code-style), and — where security-relevant —
by **severity** and **fix priority**. Chasing several of these markers past the comment itself, into the
surrounding logic and its callers, surfaced two findings that are not obvious from the comment text alone
and were not caught by any of the three prior security passes:

| # | Finding | Location | Severity |
|---|---|---|---|
| 1 | Certificate identity check compares `strlen()` of a SAN entry, not its true ASN.1 length — a NUL-embedded SAN string (à la CVE-2009-2408) would be accepted for `verify_identifier` FQDN/USER_FQDN checks | `oakley.c:1844`, `crypto_openssl.c:583` | **Medium-High** |
| 2 | Privilege-separation returns the raw RSA private key bytes to the unprivileged process instead of signing inside the privileged one, self-documented as a known weakening of the privsep boundary | `privsep.c:376` | **Medium-High** |
| 3 | No anti-clogging / half-open-connection defense on inbound ISAKMP packets — self-documented as "I don't know how to check" | `isakmp.c:371` | **Medium** (DoS) |
| 4 | `racoonctl` admin command pushing XAUTH id/key mutates the shared `remoteconf` globally, not per-session | `admin.c:540` | **Medium** |
| 5 | `g_nextreqid` wraps without checking for collision with a still-active SP `reqid` | `proposal.c:1247` | **Low-Medium** |

Everything else is either a genuine but low-impact gap (magic numbers, incomplete RFC edge cases, stale
comments contradicted by the code beneath them, dead `#if 0` blocks) or a legitimate design note that
doesn't need code changes. Full classification of all 192 markers is in §5 (appendix).

§6 covers the actual ask behind this review: **why did three independent security/vulnerability passes
not surface any of this**, and what should change in our process so a fourth pass doesn't repeat it.

---

## 2. Methodology

1. `git grep -nE '(TODO|XXX)' --include='*.[ch]'` across `src/`, `test/`, and `src/include-glibc/` on
   `develop` (a detached worktree, so this branch's own history was untouched during analysis).
2. Each hit was read with ±2–5 lines of surrounding context; anything ambiguous was traced to its
   full function, its callers, and (for the two flagship findings) the sibling function it depends on.
3. Classified by:
   - **Type** — `SEC` (security-relevant), `FUNC` (functional/reliability bug or gap), `RFC` (protocol/
     interoperability compliance gap), `MISSING` (acknowledged incomplete feature), `STYLE` (magic number,
     dead code, comment-only cleanup), `DOC` (comment is stale, unclear, or purely informational).
   - **Severity** (security-relevant items only) — Critical / High / Medium / Low, following a standard
     CVSS-style qualitative scale (exploitability × impact), not a numeric score, since these are design
     observations rather than a single exploitable code path in most cases.
   - **Priority** — High / Medium / Low, weighing severity against how reachable the code path is by an
     unauthenticated remote attacker vs. gated behind an optional feature, local trust boundary, or
     already-mitigated-elsewhere condition.
4. Where a marker's claim was checkable against the code (e.g. "magic number" bounds, "should abort"
   defaults, "not checked" claims), it was verified rather than taken at face value — several markers
   turned out to describe behavior the code no longer has (comment rot), or safety nets that were already
   in place a few lines down.

---

## 3. Inventory summary

| Type | Count | Notes |
|---|---:|---|
| STYLE (magic numbers, dead `#if 0`/`#ifdef _KERNEL` code, cosmetic markers, duplicated boilerplate) | ~95 | No behavior change needed; several are candidates for a documentation/cleanup pass |
| FUNC (functional/reliability gaps, self-acknowledged uncertainty in logic) | ~48 | Mix of genuine edge-case bugs and "we're not sure this is right" notes that are actually fine |
| RFC / interoperability compliance gaps | ~24 | Mostly lenient-parsing or unimplemented optional-payload edge cases |
| MISSING (acknowledged incomplete feature) | ~11 | DSA signing path, IPv6 in one admin command, SA-bundle multi-proposal handling, block-length variants of vendored Rijndael code (pre-AES-standardization, not applicable to current use) |
| SEC (security-relevant; detailed in §4) | 11 | 2 Medium-High, 3 Medium, 6 Low |
| DOC (stale/contradicted comment, no code implication) | 3 | e.g. `policy.c:196` — see §5 |
| Test/debug print artifacts (not real TODOs) | 2 excluded + 6 `eaytest.c` self-test markers | Not part of the shipped daemon |

Per-file distribution: `src/racoon` accounts for 175 of the 192 real markers (91%), consistent with it being
the actual IKE/ISAKMP protocol engine; `src/libipsec` 8, `src/setkey` 3, `src/include-glibc` 1,
`test/` 1 (the excluded `mkstemp` one aside), and 6 in vendored/optional code (`missing/crypto/rijndael`,
`gssapi.c`/`.h` `#if 0` blocks).

---

## 4. Detailed findings — security-relevant

### 4.1 [SEC-01] Certificate SAN identity check trusts `strlen()`, not the ASN.1 length — Medium-High

**Location:** `src/racoon/oakley.c:1842–1912` (`oakley_check_certid()`), root cause in
`src/racoon/crypto_openssl.c:583–630` (`eay_get_x509subjectaltname()`)
**Marker:** `oakley.c:1844` — `/* XXX fix it! access by ASN.1 directly without. */`
**Type:** Security (identity-spoofing class) · **Severity:** Medium-High · **Priority:** High

The `XXX` at `oakley.c:1844` only flags the IP-address branch as an inefficient string round-trip through
`getaddrinfo()`. Following that thread into `eay_get_x509subjectaltname()` and the sibling
`IPSECDOI_ID_FQDN`/`IPSECDOI_ID_USER_FQDN` branch a few lines below turns up a real problem:

```c
/* crypto_openssl.c:613 */
if (gen->d.ia5->data[gen->d.ia5->length] != '\0') {
    plog(LLV_ERROR, LOCATION, NULL, "data is not terminated by NUL.");
    goto end;
}
len = gen->d.ia5->length + 1;
*altname = racoon_malloc(len);
strlcpy(*altname, (char *) gen->d.ia5->data, len);   /* stops at first embedded NUL */
```

```c
/* oakley.c:1936 */
if (idlen != strlen(altname)) {          /* compares against strlen(), not the ASN.1 length */
    ...
    return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
}
...
error = memcmp(id_b + 1, altname, idlen);
```

The guard at `crypto_openssl.c:613` only confirms OpenSSL's `ASN1_STRING` buffer happens to have a
trailing NUL one byte past its declared length — an internal OpenSSL storage artifact, not a check for
an *embedded* NUL earlier in the string. If a certificate's subjectAltName IA5String contains an embedded
NUL (e.g. `"foo\0.attacker.example"`), `strlcpy()` copies only up to that NUL, `strlen(altname)` returns
the short prefix length, and `idlen != strlen(altname)` + the subsequent `memcmp()` both operate on that
truncated prefix. A peer presenting ID payload `"foo"` would pass the identity check against a certificate
actually issued for the longer, embedded-NUL name — the exact class of bypass documented in
CVE-2009-2408 / CVE-2009-2409 and Moxie Marlinspike's 2009 "Defeating SSL" research, just in IKEv1's
identity payload instead of TLS's `CN`/SAN.

**Exploitability caveat:** this requires a CA the peer's trust store accepts to sign (or be tricked into
signing) a certificate whose SAN entry contains an embedded NUL. Most IPsec deployments run a private/
enterprise CA, which somewhat narrows real-world exposure compared to the public Web PKI context these
CVEs originated in — but "our CA would never do that" is exactly the assumption that failed in 2009, and
`verify_identifier` exists specifically so operators can lean on this check as a hard boundary. The DER_ASN1_DN
branch of the same function (a few lines above) is **not** affected — it compares full binary length via
`vchar_t.l`, not a NUL-terminated string.

**Recommendation:** compare against the true `GENERAL_NAME`/`ASN1_STRING` length (`gen->d.ia5->length`),
not `strlen()`, for the FQDN/USER_FQDN branch; reject (rather than merely log) any SAN entry containing an
embedded NUL before it's used in any comparison. This is precisely the ASN.1-native rewrite the original
`XXX` was already asking for.

---

### 4.2 [SEC-02] Privilege separation returns the private key material to the unprivileged process — Medium-High

**Location:** `src/racoon/privsep.c:376–410`
**Marker:** `privsep.c:377` — `/* XXX Improvement: instead of returning the key, stuff eay_get_pkcs1privkey and eay_get_x509sign together and sign the hash in the privileged instance? pro: the key remains inaccessible to unpriv / con: a compromised unpriv racoon can still sign anything */`
**Type:** Security (privilege-separation weakening) · **Severity:** Medium-High · **Priority:** High

`racoon`'s privilege-separation model runs a privileged parent that alone can open root-only files (private
key PEM files, PF_KEY socket, etc.) and an unprivileged child that does the actual network-facing protocol
parsing — the code path an attacker reaches first. For `PRIVSEP_EAY_GET_PKCS1PRIVKEY`, the privileged side
reads the private key file (correctly gated by `unsafe_path()`), but then serializes the **raw private key
bytes** back over the privsep socket to the unprivileged process:

```c
if ((privkey = eay_get_pkcs1privkey(bufs[0])) == NULL) { ... }
reply->bufs.buflen[0] = privkey->l;
...
memcpy(reply + 1, privkey->v, privkey->l);   /* private key now lives in the unprivileged process */
```

The comment already states the consequence precisely: the *only* thing standing between "unprivileged
racoon compromised" and "attacker has the IKE private key" is that the attacker has to notice the key is
sitting in that process's memory. Given the unprivileged process is the one parsing untrusted ISAKMP
payloads (the same subsystem three prior audits found pre-auth OOB reads in — issues #37–#41), a memory-
disclosure or RCE bug there — even one considered "low severity because it's post-crash" — becomes a
full private-key compromise instead of a config/state compromise. This is a real degradation of the
privsep design's stated threat model, not a hypothetical one.

**Recommendation:** move signing (`eay_get_x509sign`/`eay_pkey_sign`) into the privileged side, passing
only the to-be-signed hash across the socket and returning only the signature — exactly what the comment
proposes. This is architecture work, not a one-line fix, hence High priority but not Critical/urgent-patch.

---

### 4.3 [SEC-03] No anti-clogging defense against half-open ISAKMP negotiations — Medium (DoS)

**Location:** `src/racoon/isakmp.c:371–373`
**Marker:** `/* XXX: check sender whether to be allowed or not to accept */` and
`/* XXX: I don't know how to check isakmp half connection attack. */`
**Type:** Security (resource-exhaustion) · **Severity:** Medium · **Priority:** Medium

Immediately after the cookie/version/flags sanity checks on every inbound ISAKMP packet, and before any
per-phase1 state is allocated, the code admits it performs no rate-limiting or stateless-cookie check
against an attacker flooding phase 1 SA_INIT-equivalent packets from spoofed or throwaway source
addresses. Compounding this, `isakmp.c:809–825` (the phase-1 error path) explicitly **keeps** the phase1
handler alive on any processing error except when in `PHASE1ST_START` as responder, to avoid dropping
legitimate retries — meaning a stream of near-valid garbage sent after the initial packet can also pin
resources for the negotiation timeout window rather than being torn down immediately.

**Recommendation:** this is a 25+ year old, self-acknowledged, unresolved gap in a core protocol path.
It doesn't need to reach full RFC 2409 §5 anti-clogging-token parity, but even a lightweight per-source
half-open-count cap or exponential backoff would materially raise the cost of this class of DoS.
Medium priority: real, but IKE daemons are conventionally deployed behind rate-limiting infrastructure
(fail2ban-style tools, firewall SYN-proxy equivalents for UDP flood shaping) in most production setups,
so this is defense-in-depth rather than the only barrier.

---

### 4.4 [SEC-04] Admin-socket XAUTH id/key push mutates the shared `remoteconf`, not the session — Medium

**Location:** `src/racoon/admin.c:538–553`
**Marker:** `/* XXX This overwrites rmconf information globally. */`
**Type:** Security (session isolation) · **Severity:** Medium · **Priority:** Medium

When an external XAUTH front-end pushes an id/key pair over the admin control socket
(`ENABLE_HYBRID` build), the code writes it directly into `rmconf->xauth->login`/`pass` — the shared
`remoteconf` structure matched by address or name, not a per-`ph1handle` copy:

```c
if (id && key) {
    ...
    rmconf->xauth->login = id;
    rmconf->xauth->pass = key;
}
```

If more than one concurrent phase-1 negotiation matches the same `remoteconf` (the common case for a
road-warrior/"anonymous" section serving many road-warrior clients against one config block), setting
one client's XAUTH credentials via this admin path clobbers what every other concurrent negotiation
against that same section sees. Depending on timing, this can misattribute one user's credentials to
another user's session.

**Recommendation:** store pushed id/key on the `ph1handle`/xauth-state rather than the shared `remoteconf`,
or document (and enforce) that this admin command is only safe against 1:1 (non-anonymous) remote
sections. Medium priority — reachable only via the privileged local admin socket and only in
`ENABLE_HYBRID` XAUTH-proxy deployments, but the impact (cross-session credential confusion) is
significant when it applies.

---

### 4.5 [SEC-05] `reqid` counter wraparound can collide with a still-active SP entry — Low-Medium

**Location:** `src/racoon/proposal.c:1244–1253`
**Marker:** `/* XXX there is a (very limited) risk of reusing the same reqid as another SP entry for the same peer */`
**Type:** Security/functional (policy misassociation) · **Severity:** Low-Medium · **Priority:** Low-Medium

`g_nextreqid` is a monotonically increasing global counter (under `GENERATE_POLICY_UNIQUE`) that wraps
back to `1` at `IPSEC_MANUAL_REQID_MAX` with no check that the recycled value isn't still bound to a live
SA/SP. Under sustained high SA churn (frequent rekeys, many road-warriors) this could, in principle,
associate a newly negotiated SA with the wrong SPD `reqid`, causing traffic to be matched against the
wrong policy. The original authors already assessed this as "very limited risk," which matches this
review's read of it — flagging it here mainly so it's tracked rather than re-discovered, and because the
fix (a simple in-use bitmap/free-list) is cheap relative to the class of bug it forecloses.

---

### 4.6 [SEC-06] Blowfish weak-key check is a permanent stub — Low

**Location:** `src/racoon/crypto_openssl.c:1706–1709`
**Marker:** `/* XXX to be done. refer to RFC 2451 */`
**Type:** Security (incomplete crypto hygiene, RFC-compliance) · **Severity:** Low · **Priority:** Low-Medium

```c
int
eay_bf_weakkey(key)
	vchar_t *key;
{
	return 0;	/* XXX to be done. refer to RFC 2451 */
}
```

Confirmed live (not dead) code: `oakley.c:2775` calls this through the generic `oakley_encdef[]` weak-key
dispatch table after DH key derivation, so a derived Blowfish key is genuinely never checked for
Blowfish's known weak/semi-weak key classes. By contrast, `eay_des_weakkey`/`eay_3des_weakkey` in the same
file have real implementations (with an explicit rationale comment — evidently the product of the prior
OpenSSL 3.x migration audit), and `eay_cast_weakkey`/`eay_aes_weakkey`/`eay_camellia_weakkey` correctly
return "not weak" because those ciphers have no known weak-key class — so this genuinely looks like an
oversight rather than a considered decision, and the same gap (no explicit `XXX`, but identical in kind)
also exists in `eay_idea_weakkey`, which returns unconditional `0` for a cipher that likewise has
documented weak keys.

**Practical risk is low**: IKE keys are derived from a Diffie-Hellman shared secret through a PRF, so
landing on one of Blowfish's specific weak-key values by chance is astronomically unlikely, and Blowfish
is a legacy/rarely-configured cipher in current deployments. Low priority given the trivial fix (mirror
the `eay_des_weakkey` pattern) and negligible real-world exposure.

---

### 4.7 Other security-adjacent items worth tracking (brief)

| # | Location | Issue | Severity | Priority |
|---|---|---|---|---|
| SEC-07 | `isakmp_inf.c:1181–1184` | On SA delete notify, only same-direction SAs are torn down; opposite-direction SA can persist as a stale resource ("should we remove SAs with opposite direction as well?") | Low-Medium | Low |
| SEC-08 | `session.c:398–402` | `reload_conf()` (SIGHUP handler) is self-documented as having "possible mem leaks and no way to go back" — repeated SIGHUP could grow memory usage over time | Low-Medium | Low |
| SEC-09 | `session.c:480–484` | Malloc-recording debug instrumentation runs signal-handler-unsafe code, "may lead to crashes and security breaches" per the comment's own citation of a 2005 EuroBSDCon talk — but gated behind `DEBUG_RECORD_MALLOCATION`, not built in production | Low (debug-only) | Low |
| SEC-10 | `crypto_openssl.c:1051–1054` | `eay_get_x509sign()` hardcodes `EVP_PKEY_RSA` when parsing the private key for signing, `/* XXX to be handled EVP_PKEY_DSA */` — DSS (DSA) local-id auth method (RFC 2409 §5) is effectively unsupported for signing despite being advertised as an auth method elsewhere | Low-Medium (functional) | Medium |
| SEC-11 | `ipsec_doi.c:694`, `ipsec_doi.c:2909–2911` | GSS-API ID decode notes `dstleft`/`srcleft` from an `iconv()` conversion aren't validated ("should always be 0; assert it?" / "Check srcleft and dstleft?") — worth an explicit check given this decodes attacker-influenced GSS ID payload data under `ENABLE_HYBRID` | Low-Medium | Low |

---

## 5. Full inventory (appendix)

Every one of the 192 real markers, grouped by file. `Type` legend: **SEC**=security (cross-referenced to
§4 where applicable), **FUNC**=functional/reliability, **RFC**=protocol/interop compliance, **MISSING**=
acknowledged incomplete feature, **STYLE**=cosmetic/magic-number/dead-code, **DOC**=stale or purely
informational comment. `Sev`/`Prio` are only populated for SEC rows; everything else defaults to
Low priority unless noted.

### src/include-glibc/sys/queue.h
| Line | Marker | Type | Notes |
|---|---|---|---|
| 412 | `insque()`/`remque()` "bogusly assume all queue heads look alike" | DOC | Vendored BSD header comment, informational only |

### src/libipsec
| File:Line | Marker | Type | Notes |
|---|---|---|---|
| key_debug.c:291 | `ipsec_hexdump` cast | STYLE | `_KERNEL`-only, not compiled in racoon userland |
| key_debug.c:728 | "misc[123]?" | STYLE | Inside `#if notyet` dead code |
| libpfkey.h:170 | "should be somewhere else" | STYLE | Header organization nit |
| pfkey.c:1871 | "rewritten to pass length explicitly" | STYLE | API design nit, `pfkey_align` helper family |
| pfkey.c:1954 | "obtain length explicitly" | STYLE | Same theme as above |
| pfkey.c:1962 | `ep` "should be passed from upper layer" | FUNC | Implicit reliance on caller state; works today, fragile |
| pfkey.c:1992 | duplicate KEY_AUTH/KEY_ENCRYPT check | FUNC | PF_KEY message validation gap; PF_KEY socket is root-only/local trust boundary |
| pfkey.c:2008, 2010 | "should check weak keys" | DOC | Superseded — real weak-key checks exist in `oakley.c`/`crypto_openssl.c` (see §4.6); likely stale duplicate note |
| pfkey.c:2140 | "What does it do?" (promiscuous mode) | DOC | Undocumented but long-stable KAME code path |
| pfkey_dump.c:470 | `/* XXX DEBUG */` | STYLE | `setkey -x` dump tool, debug print marker |
| pfkey_dump.c:591, 612 | `sport/dport = 0` fallback | FUNC | Defensive default on `getnameinfo()` failure, fine |
| pfkey_dump.c:697 | `/* XXX TEST */` | STYLE | Debug print marker |

### src/racoon/admin.c
| Line | Marker | Type | Sev/Prio |
|---|---|---|---|
| 376 | commented-out `flushph2()`, falls to `ENOTSUP` | FUNC | Disabled admin command, Low |
| 540 | rmconf overwritten globally by XAUTH push | **SEC-04** | Medium / Medium |

### src/racoon/crypto_openssl.c
| Line | Marker | Type | Sev/Prio |
|---|---|---|---|
| 682 | "other possible types?" | STYLE | Defensive fallback already correct |
| 1054 | DSA private key not handled in `eay_get_x509sign` | **SEC-10** | Low-Medium / Medium |
| 1709 | Blowfish weak-key stub | **SEC-06** | Low / Low-Medium |

### src/racoon/dnssec.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 93 | "should be processed to query PTR?" | RFC | DNSSEC cert-lookup dispatch gap, optional feature |
| 109 | "is it enough condition to set this type?" | DOC | Heuristic uncertainty, no known issue found |

### src/racoon/eaytest.c (standalone crypto self-test binary, not part of the daemon)
| Line | Marker | Type | Notes |
|---|---|---|---|
| 327 | `0x0c, /* <== XXX */` | STYLE | Annotates a byte in a hardcoded ASN.1 test vector |
| 716, 872, 887, 899, 914, 927 | `"XXX NG XXX"` / `"XXXX NG (%s) XXXX"` | N/A | Literal test-failure print strings, not TODO markers |

### src/racoon/getcertsbyname.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 63 | "use `ci_errno` instead of `h_errno`?" | STYLE | API design nit |
| 213 | `hostbuf[1024]` | STYLE | `dn_expand()` correctly passed `sizeof(hostbuf)`; bound is safe, size itself is arbitrary-but-fine |

### src/racoon/gssapi.c / gssapi.h
| Line | Marker | Type | Notes |
|---|---|---|---|
| 250, 732 | "Did this debug message ever work?" | DOC | Inside `#if 0` dead code |
| gssapi.h:53 | hardcoded max of 3 GSS tokens | MISSING | Large Kerberos/PAC tokens could in principle need more fragments; Medium functional priority for enterprise Kerberos/GSS deployments, no evidence of active problem reports |

### src/racoon/handler.c / handler.h
| Line | Marker | Type | Notes |
|---|---|---|---|
| 621–625 | zombie-handler sanity check "should be done somewhere more interesting" | FUNC | Self-acknowledged suboptimal placement, check itself is present |
| 1064 | retransmit-in-short-time "should it be error?" | FUNC | Log-level/classification nit |
| 1269–1273 | NULL `approval` "why...sometimes???" | FUNC | Already defensively handled (early return), root cause undiagnosed |
| 1289–1292 | check_level / lifebyte on config reload | FUNC | Config-reload consistency gap, Medium functional priority |
| 1423 | `/* XXX comp */` | DOC | Unclear label on a debug log call |
| handler.h:128 | "copy from rmconf due to anonymous configuration" | DOC | Architecture note on anonymous-section design debt |

### src/racoon/ipsec_doi.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 694 | GSS ID `dstleft` should be 0, not asserted | **SEC-11** | Low-Medium / Low |
| 830 | "should check the number of transform" | FUNC | Proposal payload parser hardening candidate, Medium priority (network-facing input) |
| 916 | "cannot understand the comment!" | DOC | Meta-comment, needs rewrite only |
| 1098, 1104 | bare `goto err; /* XXX */` | STYLE | Defensive early exits on malformed proposal pairs, correct behavior |
| 1301–1303 | multi-proposal-group support | MISSING | Inside `#if 0`, not compiled |
| 1568–1572, 2911, 2960–2964 | 16-bit vs 32-bit SPI/CPI field for IPComp | RFC/MISSING | Design note; interoperability config option not implemented, Low-Medium |
| 2270, 2491 | `attrseen[16]` "magic number" | STYLE | **Verified bounds-checked** (`if (type < sizeof(attrseen)/sizeof(attrseen[0]))`) before indexing — no overflow |
| 2909–2911 | GSS ID `srcleft`/`dstleft` (duplicate of 694) | **SEC-11** | Low-Medium / Low |
| 3170 | hardcoded `SIT_IDENTITY_ONLY` | STYLE | Actually RFC 2407-compliant as-is; "configurable?" is moot |
| 3306, 3321 | `return -1; /* XXX */` protocol-id mapping fallback | STYLE | Defensive default, correct |
| 3707 | ID "must be encoded to asn1dn" | FUNC/RFC | Interop risk if `idv` isn't valid DER; Medium priority to verify |
| 4767 | KPDK mapped to `IPSECDOI_AH_MD5` | RFC | Obsolete/rare auth mechanism approximation |
| 4821 | `IDTYPE_ADDRESS` default fallback | STYLE | Defensive default for logging helper |

### src/racoon/isakmp.c / isakmp.h
| Line | Marker | Type | Sev/Prio |
|---|---|---|---|
| 371, 373 | half-open connection / sender allowlist | **SEC-03** | Medium / Medium |
| 425–427 | version check placement uncertainty | RFC | Low |
| 447 | E/A flag exclusivity not cross-checked | RFC | Low, malformed-but-harmless combinations rejected downstream |
| 712–716 | commit-bit handling "should be fixed in the future" | RFC | Low, long-stable legacy behavior |
| 811–825 | invalid-packet handling keeps ph1 alive outside `START` | FUNC | Related to SEC-03, contributes to resource-pinning window |
| 899 | skip `INITIAL_CONTACT` during XAUTH | FUNC | Flagged for review; no confirmed bug |
| 1086 | "copy remote address" marker | STYLE | — |
| 1355, 1360 | `dupsaddr` "should be considered" | STYLE | — |
| 1849 | "is the peer really dead here???" | FUNC | DPD heuristic uncertainty, Low |
| 2171–2173 | `sa_dst` for mobility/MOBIKE | MISSING | Mobility corner case, Low-Medium |
| 2199–2201 | phase2↔phase1 matched by address not identity | FUNC | Correctness note under NAT/multihoming, Medium |
| 2294 | sainfo failure "use algorithm list from register message" | FUNC | Low-Medium |
| 2384–2386 | ph1-as-responder phase2 start question | FUNC | Design question, no confirmed bug |
| 2619 | payload-existence check marker | STYLE | — |
| isakmp.h:94 | NAT-T draft payload numbers conflict with RFC 3547 | RFC | Only matters if GDOI/GROUPKEY coexists with legacy-draft NAT-T, Low |
| isakmp.h:366 | `-1` internal-error sentinel note | STYLE | — |

### src/racoon/isakmp_agg.c, isakmp_base.c, isakmp_ident.c (auth-method exchange handlers)
| Pattern | Occurrences | Type | Notes |
|---|---|---|---|
| "send information" (no notify on invalid proposal) | agg.c:478,873; base.c:380,871; ident.c:325,928 | RFC | Ambiguous: could be a deliberate anti-oracle choice (don't help an unauthenticated peer fingerprint failure reasons) rather than an oversight; recommend documenting the decision either way, Low priority |
| "if there is CR or not?" (Certificate Request handling) | agg.c:645,1073; base.c:484,1292 | RFC | Low |
| isakmp_ident.c:773, 1498 | "compare ph1handle's and ID payload's addresses?" | SEC-adjacent | Likely an intentional NAT-T relaxation; recommend confirming and documenting rather than "fixing" blind, Low-Medium |
| isakmp_ident.c:869 | multiple VID silently ignored | FUNC | Feature-negotiation gap, Low |
| isakmp_ident.c:1416 | "same as ident_i4recv(), should be merged" | STYLE | Duplicated logic — two copies must be kept in sync for any future security fix; Low-Medium priority refactor |

### src/racoon/isakmp_cfg.c / isakmp_cfg.h
| Line | Marker | Type | Notes |
|---|---|---|---|
| 1339 | "might need to resend the message" | FUNC | Reliability nit, Low |
| cfg.h:39 | "don't forget to update `handler.c:exclude_cfg_addr()` if you add IPv6" | DOC | Maintenance trap; better as an automated cross-check than a comment |
| cfg.h:64 | `MAXWINS` magic number | STYLE | — |
| cfg.h:94 | move `default_domain`/`motd` to a unity substructure | STYLE | Refactor candidate |
| cfg.h:164 | duplicate IV-manager struct vs ph1's | STYLE | Refactor candidate |

### src/racoon/isakmp_inf.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 306–307 | ike-01 draft "Acknowledged Informational" | DOC | Dead/legacy draft feature, largely unused |
| 593, 652–655 | "should send outbound SAs too?" on delete notify | DOC | Likely a non-issue on inspection — RFC 2408 DELETE payload correctly carries the sender's own inbound SPI |
| 718, 751, 809, 844, 1070, 1440, 1555 | assorted `/* XXX */` bookkeeping markers | STYLE | — |
| 866, 1446 | "Should we do FLAG_A?" | RFC | Low, ambiguity only |
| 1010, 1013 | dead "Acknowledged Informational" cleanup path | DOC | — |
| 1030 | "Which SPI, inbound or outbound?" | DOC | Duplicate of 593 theme |
| 1181 | n² SA-deletion algorithm | FUNC | Bounded by SA count in practice; Low algorithmic-complexity note |
| 1184 | opposite-direction SA not removed | **SEC-07** | Low-Medium / Low |
| 1425–1427 | DPD cookie comparison redundancy | FUNC | Likely already covered by ISAKMP header dispatch, Low |
| 1541 | "check recent activity to avoid useless sends" (DPD) | FUNC | Minor efficiency, Low |

### src/racoon/isakmp_newg.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 212 | `/*XXX*/` before default reject of unsupported new-group attrs | STYLE | Correct/safe fallback (`ATTRIBUTES_NOT_SUPPORTED`) |

### src/racoon/isakmp_quick.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 459, 1130 | "command line/config option to enable/disable" HASH-position check | RFC | Already lenient (warns, doesn't reject) for backward compat; Low |
| 1223 | "we allowed in this case" | RFC | Documents an already-implemented leniency decision |
| 1582, 1592, 1604 | `np_p` bookkeeping markers | STYLE | — |
| 1646–1648 | single vs. multiple RESPONDER-LIFETIME in SA bundle | RFC | SA-bundle edge case, Medium priority to verify given niche/legacy usage |
| 1655 | generic early-exit marker | STYLE | — |
| 1864, 1867 | HASH(4)/notify generation for multiple-SA bundles | RFC | Same SA-bundle ambiguity theme, Medium |
| 2107 | "is next type always SA?" | STYLE | Fixed by protocol structure of Quick Mode msg 3 |

### src/racoon/isakmp_unity.h / isakmp_var.h / vendorid.h
| Line | Marker | Type | Notes |
|---|---|---|---|
| unity.h:55 | Cisco Unity padding purpose unknown | DOC | Reverse-engineered vendor extension, inherent uncertainty acceptable |
| var.h:60–62 | forward declarations marked `XXX` | STYLE | — |
| vendorid.h:88 | "cleanup to separate vendor lists" | STYLE | Refactor candidate |

### src/racoon/localconf.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 119 | `complex_bundle = TRUE; /*XXX FALSE;*/` | STYLE | Dead alternative value left beside the active default; confirm `TRUE` is intentional and remove the commented-out one |
| 176 | `getpsk()` fixed 1024-byte line buffer | FUNC | **Verified**: `fgets(buf, sizeof(buf), fp)` — bounded correctly; a PSK file line >1023 chars is mis-parsed (truncated), not overflowed. Local admin-controlled config file, Low impact |

### src/racoon/logger.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 129, 147, 166 | no fallback to syslog when `fname` unset | FUNC | Operational-observability gap (log messages silently dropped rather than falling back); Low-Medium priority given logging is part of incident-detection posture |

### src/racoon/missing/crypto/rijndael/*
| File:Line | Marker | Type | Notes |
|---|---|---|---|
| rijndael-alg-fst.c:227, 392 | `memcpy(out, b, sizeof b /* XXX out */)` | STYLE | Vendored reference implementation; do not modify casually |
| rijndael-api-fst.h:77 | TODO: 192/256-bit block-length variants | MISSING | Pre-AES-standardization Rijndael variant support; not applicable since AES fixes block length at 128 bits |

### src/racoon/nattraversal.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 215 | "should abort" on `natd_computed` alloc failure | FUNC | **Verified fail-safe**: `verified` defaults to `0`, so allocation failure results in "NAT assumed present," not a bypass. Robustness nit only, Low |

### src/racoon/oakley.c
| Line | Marker | Type | Sev/Prio |
|---|---|---|---|
| 42–43 | header-include comments | STYLE | — |
| 543 | SPI-size comment | STYLE | — |
| 1844 | ASN.1 string round-trip | **SEC-01** | Medium-High / High |
| 2047–2048 | "choice the 1th cert, ignore after" | FUNC | Multi-cert chains not built; single-cert assumption, Low-Medium |
| 2116–2118, 2151–2153 | "If verify cert is disabled, we still just take the first cert" | DOC | Documents an already-implemented, already-understood limitation of the disabled-verification path |
| 2179 | `ISAKMP_CERT_ARL` default fallback | STYLE | — |

### src/racoon/pfkey.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 1967 | "should be looped if multiple phase 2 handler" | FUNC | Possible missed-rekey/acquire handling for multiple SPD entries; Medium functional priority |
| 2858–2860 | SA-address update only for tunnel mode, not transport | MISSING | Mobility/MOBIKE limitation, documented, Medium priority for mobility support |
| 3462–3463 | SP lookup via `spidx` vs. `spid` from `xpl` | DOC | Design question, no confirmed bug |
| 3491–3500 | phase1-during-MIGRATE race | FUNC | Mobility corner case, Low-Medium |
| 3580 | `sadb_msg_errno = ENOENT; /* XXX */` | STYLE | — |

### src/racoon/plog.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 100 | static 800-byte buffer, "allocated every time?" | STYLE | Perf/reentrancy nit — not thread-relevant (racoon is single-threaded/event-loop), Low |
| 267 | printable-char range "too large?" | DOC | — |

### src/racoon/policy.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 196 | "don't check direction now" | **DOC (stale)** | **Verified comment is wrong**: the very next line (`a->dir != b->dir`) *does* check direction. Textbook comment rot — flagged in §6 as a process-relevant example |

### src/racoon/privsep.c
| Line | Marker | Type | Sev/Prio |
|---|---|---|---|
| 377 | privileged key material returned to unprivileged process | **SEC-02** | Medium-High / High |

### src/racoon/proposal.c / proposal.h
| Line | Marker | Type | Notes |
|---|---|---|---|
| 191 | "cannot understand the comment!" | DOC | Meta-comment, needs rewrite |
| 380 | ordering assumption with multiple same-`proto_id` proposals | FUNC | Low-Medium |
| 521 | "should check if we have visited all items" | FUNC | Low |
| 604 | notify-on-rejected-keylength question | RFC | Low |
| 776 | "should be handled isakmp cookie" (SPI size check) | FUNC | Low-Medium |
| 785–787 | SPI/CPI left-fill design note (duplicate of ipsec_doi.c theme) | RFC | Low |
| 1187 | "assumed there is only one proposal even if it's the SA bundle" | RFC | Same SA-bundle theme as isakmp_quick.c, Medium |
| 1249 | `g_nextreqid` wraparound | **SEC-05** | Low-Medium / Low-Medium |
| proposal.h:64 | "assumed DOI values are 1 or 2" | RFC | Low, matches current IPsec DOI reality |
| proposal.h:80 | `spi` "should be `vchar_t *`" | STYLE | Type-design nit |
| proposal.h:177 | "should define behavior of key length" | RFC | Low |

### src/racoon/racoonctl.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 933, 937 | unchecked `atoi()` on `p_prefs`/`p_prefd` | FUNC | Local CLI tool input, low trust-boundary concern, Low |
| 1002 | empty-`else` marker | STYLE | — |

### src/racoon/session.c
| Line | Marker | Type | Sev/Prio |
|---|---|---|---|
| 103 | `algorithm.h` include comment | STYLE | — |
| 400–401 | `reload_conf()` possible mem leaks | **SEC-08** | Low-Medium / Low |
| 416 | "save/restore/flush old lcconf" on reload | FUNC | Related to SEC-08 |
| 482 | signal-handler-unsafe debug instrumentation | **SEC-09** | Low (debug-only) / Low |

### src/racoon/sockmisc.c / sockmisc.h
| Line | Marker | Type | Notes |
|---|---|---|---|
| 276 | site-local IPv6 handling | RFC | Deprecated address scope (RFC 4291 obsoletes site-local), Low |
| 384 | "wasn't compiled on Linux — does it work?" | FUNC | Untested code path on an `#if defined(INET6) && defined(INET6_ADVAPI)` guard uncommon on Linux; worth a build-matrix check, Low-Medium |
| 398, 405 | site-local / scope-id sanity checks | RFC | Low |
| sockmisc.h:38, 42 | `IP_IPSEC_POLICY`/`IPV6_IPSEC_POLICY` hardcoded from `linux/in.h` | STYLE | Portability note, values are stable/correct |

### src/setkey/setkey.c
| Line | Marker | Type | Notes |
|---|---|---|---|
| 417, 640, 869 | `rbuf[1024*32]` "Enough? Should I do MSG_PEEK?" | FUNC | Fixed 32KB receive buffer for PF_KEY messages; local root-only socket, Low-Medium if a legitimately larger SA/policy dump ever exceeds it (truncation, not overflow — recv() bounds the copy) |
| 770 | `f_withports` TODO | MISSING | Display feature gap in `setkey -D`, Low |

### test/
| Line | Marker | Type | Notes |
|---|---|---|---|
| test_rsa_comprehensive.c:2547 | `mkstemp()` template `XXXXXX` | N/A | Not a TODO marker, excluded from counts |
| test_x509_cert.c:93 | `mkstemp()` template `XXXXXX` | N/A | Not a TODO marker, excluded from counts |

---

## 6. Why three prior security/vulnerability passes didn't surface these

Looking at what actually shipped from the prior review cycles (`docs/security-review-pr65-portability.md`,
issues #26/#32/#34/#35/#37–#41/#50/#52/#57, and the IKEv1 pre-auth OOB-read pass that became PR #42), a
clear pattern emerges: **every prior pass was scoped to a vulnerability *class* or a *subsystem*, and
none of them enumerated developer-authored uncertainty as its own input.**

1. **Pattern-driven, not comment-driven, review.** The prior audits searched for known *code shapes* —
   unchecked buffer lengths in payload parsers (#37–#41), `memcmp` vs. `CRYPTO_memcmp` timing
   side-channels (#34), OpenSSL 3.x API migration hazards (#32/#35), missing NULL checks after `malloc()`.
   These are exactly the patterns a static analyzer or an LLM primed with "find CWE-class bugs" will
   surface. A comment like `/* XXX there is a (very limited) risk of reusing the same reqid */` or
   `/* XXX This overwrites rmconf information globally. */` has no distinctive "bad code shape" — the code
   around it is syntactically unremarkable. It only reads as a finding once you already know to ask
   "what does the *developer* think is unresolved here," which none of the three passes asked as a
   starting question.

2. **Subsystem scoping excluded the exact places where these live.** The three passes concentrated on
   `eay_rsa.c`/`crypto_openssl.c`'s key-lifecycle code, the ISAKMP payload-length validators, and (for
   PR #65) NetBSD portability/compile correctness. Several of this review's findings sit one layer over
   from those exact files — `oakley.c`'s certificate-identity comparison calls into
   `crypto_openssl.c`, but the vulnerable comparison itself is in `oakley.c`, which wasn't in scope for the
   crypto-lifecycle-focused audits. `privsep.c`, `admin.c`, and `session.c` don't appear in any of the
   three prior audits' file lists at all.

3. **"Self-flagged debt" is a different signal from "exploitable pattern," and needs a different query.**
   A `grep -n 'XXX\|TODO'` sweep is trivial to run but wasn't part of any prior pass's documented
   methodology (§2 of `docs/security-review-pr65-portability.md` describes issue-tracker mining and
   commit-range diffing, not a comment sweep). These markers are effectively a hand-written list of
   "things the author didn't fully trust," left by people with full context on the code — which is a
   *higher-signal* input than an automated scanner's guesses, but only if someone actually reads it.

4. **Comment rot went unverified.** `policy.c:196` claims direction isn't checked; the code three lines
   below checks it. A pass that reads comments without checking them against the code they annotate will
   either flag a non-issue or, worse, trust a stale comment's claim about what the code *doesn't* do and
   miss that it actually does something different now. This review's practice of verifying every marker's
   claim against the current code (rather than trusting the comment) is what caught this, and what
   distinguishes marker-analysis from a naive text search.

5. **Cross-file reasoning wasn't incentivized.** SEC-01 (§4.1) required tracing from the `XXX` in
   `oakley.c` into a helper function in a different file, then reading a third function 90 lines further
   down in `oakley.c` that the comment doesn't even mention. A review budgeted around per-file or
   per-CWE-pattern checklists naturally stops at the file/pattern boundary; a finding that only exists in
   the interaction between two files falls in the gap.

### Process changes recommended

- **Add a standing "developer-uncertainty sweep" as its own audit type**, run at least once per major
  release cycle (not just once, retroactively, as this report): `grep -rnE '(TODO|XXX)' --include='*.[ch]'`
  against the full tree, triaged the same way §4/§5 of this report were — read in context, verify the
  comment's factual claim against the current code, and only then classify.
- **Track it as a living artifact, not a one-off report.** Add a lightweight marker convention going
  forward (e.g. `XXX(security):` vs. plain `XXX`) so future contributors' security-relevant uncertainty is
  distinguishable from cosmetic notes at grep time, and wire a CI check that fails if a `TODO`/`XXX` is
  added inside `src/racoon/*.c` without a linked issue number.
- **Broaden audit scope statements to name "cross-file identity/trust-boundary reasoning" explicitly**,
  not just "per-file pattern scan," so findings like SEC-01 and SEC-02 — which live in the *interaction*
  between a data-extraction function and its caller's comparison logic — aren't structurally excluded by
  how the audit's scope is worded.
- **When a review reads a comment describing current behavior, verify it against the code before citing
  it** (either in a fix commit or in an audit report) — this review found at least one comment (`policy.c:196`)
  that actively describes the *opposite* of what the code does.
- **Prioritize SEC-01 and SEC-02 for follow-up issues** (recommended: `security` + `pre-auth` labels for
  SEC-01 given it's reachable pre-full-authentication during Phase 1 identity verification, matching this
  repository's existing issue-label conventions from the #37–#41 pre-auth OOB series).

---

## 7. Prioritized action list

| Priority | Item | Reference |
|---|---|---|
| High | Fix FQDN/USER_FQDN certificate identity comparison to use true ASN.1 length, reject embedded-NUL SAN entries | §4.1 |
| High | Move private-key signing into the privileged privsep process; stop returning raw key bytes to the unprivileged side | §4.2 |
| Medium | Add lightweight half-open-connection rate limiting to inbound ISAKMP packet intake | §4.3 |
| Medium | Scope XAUTH admin-socket id/key push to the session, not the shared `remoteconf` | §4.4 |
| Medium | File a tracking issue for `g_nextreqid` wraparound-collision hardening | §4.5 |
| Medium | Implement `eay_get_x509sign()` DSA path (or explicitly reject/document DSS auth as unsupported) | §4.7 (SEC-10) |
| Low-Medium | Implement `eay_bf_weakkey`/`eay_idea_weakkey` following the existing `eay_des_weakkey` pattern | §4.6 |
| Low-Medium | Validate GSS-ID `iconv()` `srcleft`/`dstleft` remainders instead of ignoring them | §4.7 (SEC-11) |
| Low | Remove/tear down opposite-direction SA on delete notify | §4.7 (SEC-07) |
| Low | Fix or remove the stale "don't check direction" comment in `policy.c` | §5 / §6 |
| Low | Sweep remaining STYLE-classified magic numbers and dead `#if 0` blocks in a dedicated cleanup pass | §5 |

---

*This report supersedes no prior security review; it is additive, covering a category of finding
(developer-self-flagged uncertainty markers) that fell outside the scope of all three prior passes.*
