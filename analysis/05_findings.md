# 05 — Consolidated Findings

What this analysis surfaced about agent-security evaluation design — the part
that's portable beyond this one competition.

## On the evaluation system

1. **Replay-validation is the right primitive.** Because the evaluator recomputes
   traces from scratch and never trusts attacker-reported metadata, the scoring
   can't be gamed. Any agent-safety benchmark that scores self-reported results
   is exploitable; this one isn't. Worth copying.

2. **Predicate definitions encode the threat model precisely.** The negative
   conditions (an action only counts as a vulnerability if the user didn't ask
   for it) are what separate "an agent doing its job" from "an agent being
   manipulated." Getting this boundary right is subtle and the SDK does it well.

3. **Defense-scoring alignment is deliberate.** The guardrail defends exactly the
   conditions the predicates score. This makes the benchmark honest: you can't
   score without genuinely defeating the defense.

## On building agents (the defensive lesson)

The guardrail is a compact template for a real mitigation:

- **Taint-track untrusted sources** (web, email) across the recent action window.
- **Deny dangerous operations** (`fs.delete`, `fs.write`, `shell.run`,
  `http.post`, `email.send`) when they follow untrusted input.
- **Deny on sensitive targets** by literal marker match as a backstop.

This is close to what a production tool-using agent should enforce at the tool
boundary. The competition is, in effect, stress-testing a reference mitigation.

## On the practical workflow

4. **Build a local harness early.** The official `evaluate_redteam` entry point
   isolates stdout and swallows exceptions, which made the first several attempts
   look like silent failures. Constructing the sandbox env directly — with a
   no-op guardrail for logic checks and the real guardrail for scoring checks —
   gave the visibility that the opaque harness hid. (See `local_harness/`.)

5. **Respect the budget semantics.** The real budget is a ceiling (9000s/target),
   not a target to consume. Returning as soon as the search is complete keeps the
   run fast and keeps the replay phase short. An early version that effectively
   tried to use the whole budget produced a 40-minute pending submission.

6. **Empty results read as format errors.** Because replay drops candidates that
   don't reproduce a predicate, an attack that fires nothing returns an empty
   list, which surfaces as a "Submission Format Error." The error is really
   "nothing reproduced," not "malformed output."

## Honest status

Against the public guarded targets, submissions score 0 — matching the official
baseline. The deterministic stub can be driven to fire predicates with a no-op
guardrail, confirming the mechanism is understood, but neither the real models
nor the guarded targets fall to the straightforward chains. Closing that gap is
the actual research contribution the competition is asking for, and it remains
open here.

## What I'd explore next (research directions, not recipes)

- Whether the predicate negative-conditions leave room for genuinely
  user-innocent phrasings that still causally chain from untrusted content.
- Whether the taint window has exploitable decay under agents that can be made to
  interleave clean actions — likely model-dependent.
- Characterizing where `gpt_oss` vs `gemma` differ in injection-following, since
  the per-target scores are reported separately.

Each of these is a measurement question best answered with the local harness, and
each is a legitimate defensive-research question: knowing where a reference
guardrail can be bypassed is exactly what tells you how to strengthen it.
