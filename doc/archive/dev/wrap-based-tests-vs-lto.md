> **Archived.** Superseded by [doc/dev/v0.9.1-hardening-spec.md](../../dev/v0.9.1-hardening-spec.md)#32-the-wrap-vs-lto-decision-tree as of 2026-08-04; retained for provenance. See also git tag `archive/pre-doc-consolidation`.

# `-Wl,--wrap=` test doubles vs. whole-program LTO

Filed after two failures reported from a live Ubuntu 26.04 "Resolute"
build (GCC 15.2.0, GNU ld 2.46) that neither Arch Linux nor Ubuntu Bionic
(32-bit) reproduced:

```
[TEST] PSK id/key falling through into a non-ISAKMP proto are freed, not leaked ...
  ✗ FAIL: id and key were not both freed for a non-ISAKMP proto
[TEST] freecertinfo() frees ci_cert and the node for every entry in the chain ...
  free_calls = 0, expected 6
  ✗ FAIL: freecertinfo() did not free exactly 2 allocations per node
```

## Root cause

Resolute's `test/Makefile` carries `CFLAGS`/`LDFLAGS` including
`-flto=auto -ffat-lto-objects` -- Ubuntu's `dpkg-buildflags` hardening
defaults as of this release. Confirmed via `nm` on the built test
binaries:

```
$ nm test_admin_establish_sa_psk | grep -i vfree
0000000000001a30 T vfree
$ nm test_getcertsbyname_helpers | grep -iE 'wrap_free|real_free'
0000000000001640 T __wrap_free
```

`__wrap_vfree` is **entirely absent** from the first binary; `__wrap_free`
is present in the second but is never actually called (`free_calls`
stays 0). Two distinct mechanisms, same underlying cause:

- **`vfree()`** is this project's own function, defined in `vmbuf.c`.
  With `-ffat-lto-objects`, `vmbuf.o` carries embedded LTO IR alongside
  its normal ELF code, so it participates in the same whole-program LTO
  analysis as every caller. GCC inlines `vfree()`'s real body directly at
  each call site once its definition is visible that way, leaving no
  relocation against the symbol `vfree` for `-Wl,--wrap=vfree` to
  redirect -- the wrapper function is never referenced by the final
  linked program and is dropped as dead code.
- **`free()`** is glibc's, never LTO-visible to this project's build at
  all -- but GCC has *built-in* semantic knowledge of `malloc()`/`free()`
  regardless of LTO or visibility: if it can prove an allocation never
  escapes and is unconditionally freed, it can eliminate the entire
  allocate/free sequence as having no externally observable effect. GCC
  has no knowledge that the linker will later redirect that `free()` call
  to a function (`__wrap_free`) with a real, observable side effect
  (incrementing a counter) -- from the optimizer's point of view at
  compile time, eliding the pair is correct. Under whole-program LTO the
  interprocedural visibility needed to prove "never escapes" reaches
  further (across every `.o` in the link), so more allocate/free
  sequences become eligible for this than a per-translation-unit build
  would ever attempt.

Both are legal, conforming compiler behavior; `-Wl,--wrap=` is a purely
linker-level renaming trick the compiler's optimizer has no knowledge of,
so nothing here is a compiler or linker bug. The generalized lesson from
an earlier finding in this same effort (`-Wl,--wrap=res_query`/
`--wrap=res_init` silently not interposing on Ubuntu Bionic 32-bit,
`getcertsbyname.c`'s `parse_cert_answer()` extraction) extends further:
**`-Wl,--wrap=` of any allocator-family or otherwise-inlinable symbol is
not portable across toolchains, and whole-program LTO -- increasingly a
distro hardening default -- is now a concrete, observed way to defeat it,
in addition to older/exotic toolchains failing to interpose it at all.**

## Why `test_script_hook_leak.c` (also `-Wl,--wrap=free`) is unaffected

That test's leaked pointer originates from `ipsecdoi_id2str()`, reached
through several stub indirections and a `fork()`/`execve()` boundary
(`test_leak_normal_id()`), which defeats the same interprocedural
"never escapes" proof GCC needs to elide the pair -- confirmed still
passing under a local reproduction of Resolute's exact flags (GCC 13.3,
this project's own sandbox). This is incidental to that test's structure,
not a guarantee: any future `-Wl,--wrap=` test built around a simple,
fully-local allocate/free pair is at the same risk this document
describes.

## Fix: a startup canary, not a build-time exclusion

The two affected tests (`test/test_admin_establish_sa_psk.c`,
`test/test_getcertsbyname_helpers.c`) now each run a canary allocate/free
round trip through the exact same wrapped symbol before trusting any
assertion that counts it, and `return 77` (automake's `SKIP` convention,
already used elsewhere in this suite for tests that need real root -- see
`CONTRIBUTING.md`) if the canary isn't observed:

- `test_admin_establish_sa_psk.c`: `vmalloc(1)` + `vfree()`.
- `test_getcertsbyname_helpers.c`: a single-node `getnewci_unittest()` +
  `freecertinfo()` round trip -- deliberately *not* a bare `malloc()`/
  `free()`, which turned out to be eliminated by GCC even **without**
  LTO (a self-contained allocate/free pair in one function, with no
  opaque cross-translation-unit call in between, is trivial enough for
  GCC's elision at plain `-O2` alone). Routing the canary through the
  same externally-defined, cross-TU allocator/deallocator pair the real
  tests use mirrors their actual exposure and avoids a false SKIP on
  every ordinary, non-LTO toolchain.

This was chosen over excluding the two binaries at configure time (the
existing `SANITIZER_BUILD` precedent) because it preserves every
assertion that doesn't depend on the wrap (e.g.
`test_getnewci_populates_all_fields()`) and turns a silent, indistinguishable
false pass (`vfree_calls == 0` reads identically whether ownership
correctly transferred or the wrap is simply dead) into an honest,
diagnosable `SKIP` — while a genuine regression (a *nonzero but wrong*
count) still fails exactly as before, since the canary only ever changes
behavior when the count would otherwise have been unconditionally zero.

Verified: full `make check` is unaffected (68/68 pass) on a plain
non-LTO toolchain (this project's own sandbox, GCC 13.3), and reports a
clean `66 PASS / 2 SKIP / 0 FAIL` under a local reproduction of
Resolute's exact `-flto=auto -ffat-lto-objects` flags (same GCC 13.3;
Resolute's own GCC 15.2/ld 2.46 could not be reproduced directly, but the
`nm` evidence gathered on Resolute itself and the local LTO reproduction
agree on the mechanism).
