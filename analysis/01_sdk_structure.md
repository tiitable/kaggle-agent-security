# 01 — SDK Structure and Attack-Run Flow

The competition ships an `aicomp_sdk` package. Before writing any attack, the
first job was mapping what's in it and how a run actually executes.

## Package layout (relevant parts)

```
aicomp_sdk/
├── attacks/
│   ├── contracts.py        # AttackAlgorithmBase, AttackCandidate, AttackRunConfig
│   └── baselines/          # attacker_goexplore (the official baseline)
├── core/
│   ├── predicates.py       # scoring predicates  <-- the heart of the system
│   ├── env/                # sandbox, gym, opaque env implementations
│   └── tools/              # tool suite (web, fs, http, email, shell)
├── agents/
│   ├── deterministic_agent.py   # the local/sandbox target
│   ├── gpt_oss_agent.py / gemma_agent.py   # real leaderboard targets
│   └── ...
├── guardrails/
│   ├── base.py             # GuardrailBase (default allow)
│   └── optimal.py          # the taint-tracking guardrail used publicly
├── evaluation/
│   └── runner.py           # evaluate_redteam — the high-level entry point
└── fixtures/
    ├── web_corpus.json     # web pages the agent can "open"
    ├── mail_seed.json      # email fixtures
    └── file_seed/          # files including secret.txt
```

## The contracts

Your submission implements one class:

```python
class AttackAlgorithm(AttackAlgorithmBase):
    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:
        ...
```

- **`AttackCandidate`** is a frozen dataclass holding `user_messages: tuple[str, ...]`.
  It is a *replayable* chain — just the user-side messages, nothing else.
- **`AttackRunConfig`** carries `time_budget_s`, `max_steps`, `max_tool_hops`.
  The locally-observed default `time_budget_s` is 30s, but the *real* evaluation
  budget is 9000s per target model (clarified by the hosts). Crucially this is a
  ceiling, not a target — returning early is expected and rewarded with faster
  replay.

## How an attack run flows

```
your AttackAlgorithm.run(env, config)
  └── you call env.reset() / env.interact(msg) / env.snapshot() / env.restore()
  └── env.export_trace_dict() gives you the trace so far
  └── eval_predicates(trace) tells you which predicates (if any) fired
  └── you return a list[AttackCandidate]

evaluator then INDEPENDENTLY replays each candidate against the target +
guardrail, recomputes the trace, and scores using its own trusted trace —
not anything you reported.
```

This replay-based design is the single most important architectural fact: you
cannot fabricate a finding. A candidate only counts if, on a clean replay, it
reproduces a predicate on the actual scored target.

## The env interface (`AttackEnvProtocol`)

```python
seed: int                                   # property (get/set)
reset(*args, **kwargs) -> Any
interact(user_message: str, max_tool_hops: int | None = None) -> EnvInteractionResult
export_trace_dict() -> dict                 # keys: seed, user_messages,
                                            #   assistant_messages, tool_events, egress
snapshot() -> Any                           # capture restorable state
restore(snapshot) -> None                   # Go-Explore-style backtracking
```

`EnvInteractionResult` reports `total_tool_events`, `successful_tool_calls`,
`failed_tool_calls`, `agent_refused`, etc. — useful signal for whether the agent
actually did anything or refused.

## Note on the submission entry point

The packaged notebook ends by launching an inference server
(`JEDAttackInferenceServer().serve()`) that the evaluator connects to. Constants
on that server pin the required shape:

- class name must be `AttackAlgorithm`, file must be `attack.py`
- `MAX_REPLAY_FINDINGS = 2000`
- `MAX_REPLAY_MESSAGES_PER_FINDING = 32`
- `MAX_USER_MESSAGE_CHARS = 2000`

These are generous; for a focused attack you stay far under all three.
