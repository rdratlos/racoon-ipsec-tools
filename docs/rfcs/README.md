# Racoon RFC Process

This directory holds the **Requests for Comments (RFCs)** for the
`racoon-ipsec-tools` project. An RFC is a short design document that
describes a significant change *before* it is implemented.

The goal of this process is deliberately modest: give the project a
permanent, reviewable record of *why* the architecture looks the way it
does, without adding bureaucracy that a small team cannot sustain. It is
designed to work for a **single maintainer** while remaining open to
occasional contributors and external reviewers, and to keep running for
many years using nothing but standard GitHub features.

---

## What an RFC is

An RFC is a Markdown file in `docs/rfcs/` that captures an architectural
decision: the motivation, the proposed design, the alternatives that were
weighed, and the trade-offs that were accepted.

An RFC is **design review, separated from implementation**. It answers
*"what should we build and why"*. The code that follows answers
*"here is the build"*. Keeping the two apart means design discussion is not
buried inside a large code diff, and the decision survives in Git history
long after the pull request that implemented it has scrolled out of view.

An RFC is **not**:

- a place for the full implementation (that lives in normal code PRs),
- a substitute for a bug report or a small change (use an Issue or a PR),
- a binding contract — an accepted RFC can later be amended or superseded.

## When an RFC is required

Use judgement, not a rulebook. An RFC is expected when a change is hard to
reverse or affects the project broadly. In practice, open an RFC when the
change involves any of:

- **On-wire or protocol behaviour** — IKEv1 exchange handling, payload
  processing, or anything affecting interoperability with existing peers
  (Apple/Cisco-compatible clients, legacy devices).
- **Configuration surface** — new `racoon.conf` directives, or changes to
  the meaning of existing ones.
- **Cryptographic behaviour** — algorithm support, defaults, or the
  OpenSSL abstraction layer.
- **Public interfaces** — PF_KEY handling, `libipsec` API, command-line
  behaviour of `racoon` / `setkey`.
- **Cross-cutting structure** — build system, portability strategy,
  packaging model, or module boundaries.
- **Anything that would be costly to undo** or that a future maintainer
  would reasonably ask *"why was it done this way?"* about.

An RFC is **not** required for:

- bug fixes that restore intended behaviour,
- portability or compiler/OpenSSL compatibility fixes,
- documentation, comments, tests, or refactors with no behavioural change,
- small, obviously-correct improvements.

If you are unsure, open an Issue and ask, or open the RFC as a **Draft** —
it is cheap, and the discussion itself often reveals which side of the line
the change falls on.

## Lifecycle

An RFC moves through a small number of states. The `Status` field at the
top of the RFC file always reflects the current state.

```
Draft ──▶ Review ──▶ Accepted ──▶ Implemented
                │
                └──▶ Rejected / Withdrawn

Accepted / Implemented ──▶ Superseded
```

| Status | Meaning |
| --- | --- |
| **Draft** | Being written. Open as a pull request early to invite comment; not yet ready for a decision. |
| **Review** | The author considers the design complete and is requesting a decision. Reviewers comment on the PR. |
| **Accepted** | The maintainer has approved the design. The RFC PR is merged into the default development branch. Implementation may begin. |
| **Rejected** | The design will not be pursued. The RFC may still be merged (with `Status: Rejected`) so the reasoning is preserved, or the PR closed. |
| **Withdrawn** | The author has abandoned the RFC before a decision. |
| **Implemented** | The accepted design has landed in the codebase. Update the `Status` in a later PR once the work is complete. |
| **Superseded** | A newer RFC replaces this one. Record the successor's number (see below). Superseded RFCs are kept, never deleted. |

Notes:

- **Acceptance is recorded by merging the RFC pull request.** The merge
  commit is the permanent record of the decision.
- **Nothing is deleted.** Rejected, Withdrawn, and Superseded RFCs remain
  in the tree as historical record.
- A **single maintainer may accept their own RFC**, but should still open
  it as a pull request and leave it open long enough for external reviewers
  to comment. The value is in the public, written trail.

## Numbering rules

- Each RFC has a **unique, zero-padded four-digit number**: `0001`, `0002`,
  `0042`, …
- `0000` is reserved for the template and is never used for a real RFC.
- **The number is assigned when the RFC pull request is opened**, using the
  next unused integer. Check both merged files in `docs/rfcs/` and any open
  RFC pull requests to find the highest number in flight, then add one.
- If two RFCs collide on the same number (two PRs opened at once), the
  second one to merge renames its file to the next free number. Numbers are
  **never reused**, even for rejected or withdrawn RFCs.

## Naming conventions

- File name: `NNNN-short-kebab-case-title.md`
  - Example: `0007-openssl-provider-migration.md`
- Keep the slug short, lowercase, hyphen-separated, and descriptive.
- The number in the file name must match the `Status`/number in the header.
- Start every new RFC by copying [`0000-template.md`](0000-template.md).

## Review expectations

- **Open early.** A Draft PR is welcome before the design is finished;
  early comments are cheaper than late ones.
- **Review the design, not the prose.** Focus on correctness,
  interoperability, compatibility, and long-term maintainability.
- **All discussion happens in the pull request** — inline comments and the
  conversation thread — so it is captured alongside the change. Avoid
  private channels for anything that affects the decision.
- **External reviewers are explicitly encouraged.** Anyone may comment on
  an RFC pull request. Domain experts (IKE/IPsec, OpenSSL, packaging) are
  especially welcome, and the maintainer should give their comments real
  weight even when they are not formal approvers.
- **The maintainer is the decision-maker.** Consensus is the goal, but with
  a single primary maintainer the final call — and the responsibility —
  rests with them. The RFC records the reasoning either way.
- There is **no minimum review period** and no quorum. Non-trivial or
  breaking designs should stay open long enough for interested parties to
  weigh in; small ones need not.

## Relationship between RFCs and GitHub Issues

- **Issues are for problems and ideas; RFCs are for decisions.**
- An idea usually starts as an **Issue** (or a discussion). If it grows into
  something that needs an architectural decision, an RFC is written and the
  Issue links to the RFC PR.
- Once an RFC is **Accepted**, implementation work is tracked with one or
  more **implementation Issues** (see
  [`.github/ISSUE_TEMPLATE/implementation.md`](../../.github/ISSUE_TEMPLATE/implementation.md)),
  each referencing the RFC number.
- Rule of thumb: *Issue = "here is a problem"*, *RFC = "here is the design
  we agreed on"*, *implementation Issue = "here is a unit of work to build
  it"*.

## Relationship between RFCs and Pull Requests

There are two distinct kinds of pull request in this process:

1. **RFC pull requests** add or update a file under `docs/rfcs/`. Merging
   one records a design decision. It should contain little or no code.
2. **Implementation pull requests** change source code. Each should
   reference the RFC it implements in its description (the pull request
   template has a checkbox for this: *"Implements RFC ####"*).

Keeping these separate is the whole point: design is reviewed and recorded
on its own, and the code that follows can be reviewed on its own merits
against an already-agreed design.

---

## Recommended GitHub configuration

The process relies only on standard GitHub features. The following labels
and project board make it easier to track, but are optional conveniences,
not requirements.

### Labels

| Label | Colour (suggested) | Use |
| --- | --- | --- |
| `rfc` | `#5319e7` | Any RFC pull request or related Issue. |
| `design` | `#0e8a16` | Design discussion, usually alongside `rfc`. |
| `architecture` | `#1d76db` | Changes affecting cross-cutting structure. |
| `discussion` | `#c5def5` | Open-ended idea or question, not yet an RFC. |
| `accepted` | `#0e8a16` | An RFC whose design has been accepted. |
| `implementation` | `#fbca04` | Issues/PRs building an accepted RFC. |
| `breaking-change` | `#b60205` | Affects on-wire, config, or API compatibility. |

### Project board

A single GitHub **Project** (board view) with these columns tracks an idea
from inception to release:

| Column | Contains |
| --- | --- |
| **Ideas** | Raw ideas and `discussion` Issues. |
| **Draft RFC** | RFC being written (Draft PR open). |
| **Under Review** | RFC PR requesting a decision (`Review`). |
| **Accepted** | RFC merged; ready to be broken into work. |
| **Implementation** | Implementation Issues/PRs in progress. |
| **Testing** | Implemented, under verification. |
| **Ready for Release** | Merged and verified, awaiting a release. |
| **Done** | Shipped in a release. |

See [`CONTRIBUTING.md`](../../CONTRIBUTING.md) for how these pieces fit
together into the end-to-end workflow.
