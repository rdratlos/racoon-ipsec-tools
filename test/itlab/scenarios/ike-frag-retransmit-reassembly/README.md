# Scenario: IKE fragment reassembly under last-fragment retransmission

Regression scenario for the CVE-2016-10396 **follow-up** defect in
`src/racoon/isakmp_frag.c` (see the fix commit and `test/test_isakmp_frag.c`).

## What it proves

With `ike_frag on` and a payload large enough to fragment, a legitimate
retransmission of the **last** IKE fragment — or any fragment arriving after
the tail — must not abort reassembly. The pre-fix code logged
`ERROR: Repeated last fragment index mismatch` and let phase 1 time out; the
fixed code completes reassembly and establishes the SA.

## Status and how it runs today

This directory is a **declarative scenario descriptor**, not an executable
test yet. RFC 0001 (`docs/rfcs/0001-incus-integration-testing-framework.md`)
defines the itlab architecture but is a *Draft*; the scenario/topology schema
and the single-fault packet-drop capability (RFC 0001 §5/§9) are not
implemented. `scenario.yaml` is written against RFC 0001's layered model so it
is ready to wire up at itlab Milestone 1–2 (Appendix A.4).

Until itlab exists, the same reassembly logic is verified **deterministically
and today** by the unit-level regression test:

```
./configure --enable-frag --enable-tests
make
make -C test check TESTS=test_isakmp_frag
```

That test drives the real `isakmp_frag_extract()` /
`isakmp_frag_reassembly()` with the out-of-order and retransmitted-tail
fragment sequences; it fails against the pre-fix object and passes against the
fixed one.

## DH group / fragmentation threshold (block 2 of the task)

`ISAKMP_FRAG_MAXLEN = 552` bytes. Whether an exchange fragments at all depends
on payload size, which is why the bug stayed invisible for years:

| DH group | KE payload | Fragments on KE alone? | Notes |
| --- | --- | --- | --- |
| 14 (MODP-2048) | 256 B | No (PSK) | Needs a large payload (certificate chain) to cross 552 B; PSK + group 14 never fragmented, so never hit the bug. |
| 16 (MODP-4096) | 512 B | Yes | The KE-bearing message alone exceeds 552 B; raising the DH group for stronger PFS is what started exposing the defect. |

The matrix therefore runs both groups. For group 14 the runner augments the
profile with a certificate chain (`augment: certificate-chain`) to force
fragmentation; group 16 fragments unconditionally.

## Files

- `scenario.yaml` — the declarative scenario (topology, config, fault
  injection, verification, DH-group matrix).
