# AI Provenance: Guiding Principles

Status: Approved.
Applies to RFC 0005 and to every tool,
schema, report and review that implements it, whether written by a human
or by an agent. When a proposed feature conflicts with these principles,
the principles win, and the conflict is raised rather than resolved by
the agent.

## Strategic Rationale

1. **Part of a transformation, not a brake on it.** AI-assisted
   development makes software work simpler, faster and more capable.
   Provenance exists to let that continue with confidence. It must never
   become the reason AI is used less or used secretly.

2. **Optional unless someone needs it.** For many projects a commit that
   describes the change and names the accountable human author is
   enough, exactly as before. Provenance is added where it pays off: a
   customer or regulator requires it (for example DoWI 8430.01 §3.6.f,
   records of models and versions), security-critical code, or a need to
   answer "which model touched this" later. Where none of these applies,
   "as before" is a valid outcome.

3. **Visible value.** Every element must give someone a benefit they can
   feel: less to type, faster review triage, a recall answered in
   minutes, an audit question answered from the record, numbers that
   settle a discussion with operators. An element whose value nobody can
   name is removed.

## Scope of Impact

4. **People first: developers, QA, LLM operators.** Provenance succeeds
   only if the people who produce, check and operate it accept it. Their
   time is the scarcest resource in the system.

5. **No surveillance.** Provenance records what tools contributed, not
   how productive a person is. No prompts, no transcripts, no
   per-person performance data. The human is identified as the
   accountable author through Git, as always.

6. **Operators act on QA demand.** Teams that run the model
   infrastructure change it when QA asks for it, with a concrete,
   minimal request (for example: return the deployment per request, keep
   the request log for the retention period). Provenance work prepares
   that request with evidence; it does not assume the change.

## Non-goals of AI Provenance

7. **Not verification, and no substitute for it.** Review, tests and
   analysis decide whether code is correct. Provenance only records how
   the code came about. AI-generated tests are themselves subject to
   review.

8. **Not proof of which model ran.** A profile names a declared setup.
   A route label such as `KITCH-Coder` is not a model. A value is only as
   strong as its weakest source, and the record says which source that
   was.

## How Provenance is Built

9. **Simple and intuitive.** The normal case is one step for the agent
   and one deliberate step for the human. If using the tool correctly
   takes three attempts, the tool is wrong, not the user.

10. **Survives ordinary Git.** Records survive rebase, cherry-pick,
    amend and merge without manual repair. No link may depend on a
    mutable commit SHA alone.

11. **Evidence comes from tools, not from models.** A model does not
    reliably know which model it is. Model identity is read by a tool
    from a harness record, a capture log or an operator log, never typed
    by the agent about itself.

12. **Honest over complete.** Unknown stays unknown. A record that
    claims less but is true is better than one that claims more. A false
    record, such as a model credited that did not run, is worse than no
    record.

13. **Proportionate.** Strictness follows risk: light for docs and
    guests, full rigour for security-critical paths. One way to do each
    thing; options nobody uses are removed.

14. **Human accountability is real.** Only a human approves. The
    approval means something only if its key is out of the agent's
    reach.

15. **The tooling meets its own standard.** The checker's rules and
    dependencies are identified and come from reviewed state, not from
    the change being checked. Tests derive from requirements, not from
    the implementation's output.

16. **Replaceable adapters.** Harnesses and routers change. The record
    format and the checker stay; adapters are expected to be rewritten.

## How we Decide

17. **Value versus effort, measured.** Like every part of the process,
    provenance faces that assessment at the end of each phase. What
    counts as value and what counts as failure is written down **before**
    the observation period starts, so the result can go either way.

18. **Small, reversible steps.** Prototype before norm. RFC text never
    runs ahead of what the checker demonstrably does.

19. **Exit is a legitimate result.** If the evidence shows the effort is
    not justified for a class of projects, the scope is reduced for that
    class, down to "as before".

## Rules for Agents Working on Provenance

Do:
- Name, for each change you propose, the principle it serves and who
  benefits.
- Cite every factual claim with file and line, commit, or command output.
  Mark anything unchecked as unchecked.
- Label your own reports as self-assessments. They are input to QA, not
  QA.
- Declare every AI-assisted commit you make, including fixes to your own
  work.
- Prefer removing an option over adding one. Ask before adding schema
  fields, trust levels or workflow steps.
- In reviews, separate "must fix before the next observation period"
  from "later" and from "not worth it". Say what should **not** be done.

Do not:
- Write a model identity into a commit or manifest from your own
  knowledge of yourself.
- Report a requirement as implemented without a test derived from that
  requirement.
- Describe weaknesses, commits or behaviour you have not observed.
- Add rigour beyond what the risk of the change justifies, even when a
  standard would allow it.
- Sign, attest, or write `reviewed` statements on behalf of a human.

## Value and Effort at a Glance

| Who | What they should gain | What it may cost them |
| --- | --- | --- |
| Developer | AI use without guilt or extra typing; faster reviews | one command per session, near zero for human-only work |
| QA | recall and audit questions answered from the record; trust grading per claim | reading a short record; defining the questions up front |
| LLM operators | data on what their routing actually does; one precise request instead of vague complaints | the changes QA requests, nothing else |
| Management | a decision based on measured value, effort and regulatory need | the observation period |
