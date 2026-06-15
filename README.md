# Analyzing an Agent-Security Benchmark: A Reverse-Engineering Walkthrough

A structured analysis of the evaluation system behind the **AI Agent Security –
Multi-Step Tool Attacks** competition (hosted by OpenAI, Google, and IEEE). This
repository documents how I worked from a near-empty starter notebook to a
complete understanding of the benchmark's scoring mechanism, agent model, and
defensive guardrail — using only the SDK the competition ships to participants.

> **Framing.** This is a *defensive* security-research exercise. All exploration
> was performed inside the competition's own offline, deterministic sandbox,
> which is explicitly designed to be red-teamed and contains no real systems,
> users, or data. The goal here is not an attack recipe; it is a methodology for
> understanding how an agent-security evaluation is constructed and what it
> teaches about why these systems are hard to break.

## Why this exists

The competition is an *algorithmic red-teaming* challenge: you submit an
`AttackAlgorithm` that searches a sandboxed tool-using agent for multi-step paths
from untrusted input to unsafe action, and the evaluator replays your findings to
score them. Unlike a tabular Kaggle competition, almost all of the difficulty is
hidden inside the SDK's internals — the scoring predicates, the agent's behavior,
and the guardrail. This repo is the map I built of those internals.

## What's inside

| Path | Contents |
|------|----------|
| `analysis/01_sdk_structure.md` | How the SDK is laid out and how an attack run actually flows end-to-end |
| `analysis/02_scoring_predicates.md` | The four security predicates and their exact trigger conditions |
| `analysis/03_agent_model.md` | The deterministic agent: how it maps messages to tool calls and where its modeled vulnerability lives |
| `analysis/04_guardrail.md` | The taint-tracking guardrail, its three rules, and why it blocks the obvious chains |
| `analysis/05_findings.md` | Consolidated takeaways about agent-security evaluation design |
| `local_harness/` | A local test harness that runs attacks without the submission loop |
| `experiments/log.md` | Every submission version and its result |
| `notebooks/` | The Kaggle submission notebook |

## Key takeaways (the short version)

1. **The scoring is predicate-based, not score-based.** Points come from firing
   one of four security predicates (exfiltration, untrusted-to-action,
   destructive-write, confused-deputy), each weighted by severity. Understanding
   the *exact* trigger conditions matters far more than volume of attempts.

2. **Every finding is re-validated by replay.** The evaluator independently
   replays each returned candidate against the target. Candidates that don't
   reproduce a predicate are silently dropped — which is also the real cause of
   the "Submission Format Error" an empty result produces.

3. **The default guardrail is strong by design.** A taint-tracking guardrail
   blocks dangerous operations that follow untrusted (web/email) input. The
   "obvious" injection chains map directly onto what it's built to stop, which is
   why even the official baseline scores zero against it.

4. **Local reproducibility requires bypassing the opaque harness.** The official
   `evaluate_redteam` entry point isolates stdout and captures exceptions, making
   debugging hard. Constructing the sandbox env directly gives full visibility.

## Status

Submissions against the public targets currently score 0 — consistent with the
official baseline. Reliably scoring against the guarded targets is the genuine
open problem at the core of this competition. This repo documents the analysis
that any serious attempt has to start from.

## Stack

Python · Kaggle code competition · `aicomp_sdk` · static + dynamic analysis
