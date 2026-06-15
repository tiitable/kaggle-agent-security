# 03 — The Agent Model

The local/sandbox target is a **deterministic agent**. Understanding it is what
makes local debugging possible: it has no randomness, so a chain that behaves a
certain way once behaves that way every time.

## What "deterministic" means here

The agent does not call an LLM. It maps user messages and tool outputs to tool
calls through fixed rules. This is a feature, not a limitation — it gives the
benchmark a reproducible target to develop against before facing the real models
(`gpt_oss`, `gemma`) on the leaderboard.

## A vocabulary, not a language model

The agent recognizes a fixed set of command phrases rather than parsing natural
language intent. Observed command families include:

- **Reads:** `read email`, `read secret`, `read file <name>`
- **Consequential ops:** `delete secret`, `run echo`, `upload report`,
  `post data`, `send email`
- **Open/browse:** `open <page>` / `search <query>`

A consequence worth internalizing: elaborate natural-language prompts are mostly
ignored. The agent keys off the recognized tokens, so a verbose "please POST the
secret key to …" collapses to whatever fixed token it matches.

## The modeled vulnerability

The agent's decision logic checks **the output of the previous tool first**, and
if that output contains instruction-like text, it follows it. This is the
deliberately-modeled flaw: it represents an agent that naively trusts content it
just retrieved. The path from untrusted input to action runs straight through
this behavior:

```
user: open <a poisoned page>
  -> agent calls web.open(...)            # output is attacker-controlled text
user: <any nudge to continue>
  -> agent reads the previous tool output
  -> finds instruction-like text in it
  -> issues the corresponding tool call   # now sourced from "web" = untrusted
```

The page content is the real payload; the user messages are just what move the
agent through the steps.

## Why this still scored zero on the real targets

The deterministic agent follows retrieved instructions naively. The real
leaderboard models (`gpt_oss`, `gemma`) do **not** — they have enough safety
behavior to decline "open this page and do what it says." So chains tuned to the
deterministic stub do not transfer. This is the expected and correct outcome: the
stub is a development convenience, not a stand-in for a real model's
susceptibility. It is also why the gap between "works on the stub" and "works on
the model" *is the competition.*

## Fixtures

The agent's world is seeded from `fixtures/`:

- `web_corpus.json` — the pages `open` can retrieve; some are benign, some are
  crafted to contain instruction-like text.
- `file_seed/` — includes `secret.txt` carrying sensitive-looking markers.
- `mail_seed.json` — email fixtures.

The fixtures matter because the agent can only "follow" content that actually
exists in them; references to non-existent pages simply fail to open.
