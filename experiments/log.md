# Experiment Log

Chronological record of submissions and what each one taught.

| # | Version | Local (no-op guardrail) | Local (optimal) | Leaderboard | Notes |
|---|---------|------------------------|-----------------|-------------|-------|
| 1 | Naive direct prompts (minute-scale margins) | n/a | n/a | format error | Margins set in minutes vs. a 30s observed budget → every attempt skipped → empty result |
| 2 | Same, with placeholder finding | n/a | empty after replay | format error | Confirmed: replay drops candidates that don't reproduce a predicate |
| 3 | Indirect injection via real corpus pages | fires predicates | 0 (guardrail blocks) | 0 | Mechanism confirmed on stub; optimal guardrail denies the dangerous ops |
| 4 | Broad page sweep, consumed full budget | fires (subset) | 0 | 0, ~40min pending | Budget is a ceiling not a target; long pending partly an evaluator-side issue per hosts |
| 5 | Lean, early-return (3 verified + 5 secondary pages) | fires (subset) | 0 | 0 | Returns in ~2s even with a 9000s budget; clean baseline submission |

## Key lessons captured

- **Format error == nothing reproduced.** The evaluator's replay validation makes
  an empty/all-blocked result surface as a format error, not a code error.
- **Stub != real model.** Chains that drive the deterministic agent do not
  transfer to `gpt_oss` / `gemma`, which decline naive instruction-following.
- **Budget semantics.** Return as soon as the search is done. The 9000s/target
  figure is a ceiling; consuming it produces long pending times and slow replay.
- **Baseline parity.** Zero against the public guarded targets matches the
  official Go-Explore baseline — the scoring gap is the real problem, not a bug
  in the submission.

## Open questions to pursue next

- Where do `gpt_oss` and `gemma` differ in susceptibility? (Per-target scores are
  reported separately, so this is measurable.)
- Is there a user-innocent phrasing that satisfies the predicate negative
  conditions while still chaining causally from untrusted content?
- Does the taint window have exploitable decay on a model that can be induced to
  interleave clean actions?
