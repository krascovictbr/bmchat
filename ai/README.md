> **Language:** [English](README.md) | [Português (BR)](README.pt-BR.md)

# 🤖 AI / LLM Configuration — bmchat

> Central hub for AI/LLM configurations to optimize, audit and evolve **bmchat** — a Telegram-style P2P messenger over the Bitmessage protocol (Python + Tkinter, no servers).

## Purpose

This folder (`ai/`) is the **single source of truth** for any AI agent or LLM working on bmchat. It provides:

- **Ready-to-use configs** for the 7 major LLM families (OpenAI, Anthropic, Google, Meta, Mistral, DeepSeek, Cohere) with bmchat-tuned system prompts and task-specific prompts.
- **Optimized prompts** for common tasks (performance, security audit, refactor, testing, docs).
- **Skill definition** (`skills/bmchat-optimizer.md`) that teaches any agent what bmchat is, its architecture, bottlenecks and guardrails.

Use it to get **consistent, verified outputs** regardless of which LLM you use — all configs embed the same bmchat context and constraints.

## Structure

```
ai/
├── README.md                    # this file (EN)
├── README.pt-BR.md              # PT-BR version
├── .gitkeep
├── config/  (alias: llms/)      # per-LLM JSON configs (JSON valid, YAML compatible)
│   ├── openai-gpt4o.json
│   ├── openai-gpt4o-mini.json
│   ├── anthropic-claude-3.5-sonnet.json
│   ├── google-gemini-1.5-pro.json
│   ├── google-gemini-1.5-flash.json
│   ├── meta-llama-3.1.json
│   ├── mistral-large.json
│   ├── deepseek-v3.json
│   └── cohere-command-r-plus.json
├── prompts/                     # task prompts (markdown, copy-paste ready)
│   ├── performance.md
│   ├── security-audit.md
│   ├── refactor.md
│   ├── testing.md
│   ├── documentation.md
│   └── code-review.md
└── skills/
    └── bmchat-optimizer.md      # OpenCode skill with frontmatter
```

- `ai/config/` is canonical; `ai/llms/` is a symlink (`llms -> config`) for discoverability — both paths work.
- All configs are **valid JSON** (YAML is also accepted if you convert — structure is identical).

## Supported LLMs

| Provider | Model(s) | Config file | Context | Temp* | Best for |
|---|---|---|---|---|---|
| **OpenAI** | GPT-4o | `openai-gpt4o.json` | 128k | 0.20 | deep reasoning, refactor, architecture |
| **OpenAI** | GPT-4o-mini | `openai-gpt4o-mini.json` | 128k | 0.20 | fast iteration, docs, tests |
| **Anthropic** | Claude 3.5 Sonnet | `anthropic-claude-3.5-sonnet.json` | 200k | 0.20 | security audit, long-context review |
| **Google** | Gemini 1.5 Pro | `google-gemini-1.5-pro.json` | 2M | 0.25 | huge codebase, cross-file analysis |
| **Google** | Gemini 1.5 Flash | `google-gemini-1.5-flash.json` | 1M | 0.25 | quick scans, CI assistance |
| **Meta** | Llama 3.1 405B/70B/8B | `meta-llama-3.1.json` | 128k | 0.30 | open-source, self-hosted |
| **Mistral** | Mistral Large 2 | `mistral-large.json` | 128k | 0.25 | code generation, multilingual |
| **DeepSeek** | DeepSeek-V3 / R1 | `deepseek-v3.json` | 128k | 0.20 | cost-efficient, code-heavy tasks |
| **Cohere** | Command R+ | `cohere-command-r-plus.json` | 128k | 0.30 | RAG, tool-use, docs |

\* default `temperature` tuned for bmchat: low (0.2–0.3) = deterministic, test-safe. Raise to 0.5 only for docs/ideas.

All configs document `model`, `provider`, `context_window`, `max_output_tokens`, `temperature`, `top_p`, `system_prompt`, and `prompts` (performance/security/refactor/testing/docs).

## How to Use

### 1. Pick a config

```bash
cat ai/config/anthropic-claude-3.5-sonnet.json | jq .system_prompt
# or via symlink
cat ai/llms/openai-gpt4o.json | jq .prompts.performance
```

Copy `system_prompt` into your LLM's system instruction, then copy the task prompt you need from `prompts.*`.

### 2. Use task prompts

```bash
ls ai/prompts/
cat ai/prompts/performance.md        # paste into chat
cat ai/prompts/security-audit.md
```

Each `ai/prompts/*.md` is self-contained and already includes bmchat context — you don't need to re-explain the project.

### 3. Load the skill (OpenCode / any agent)

Any agent that reads `ai/skills/bmchat-optimizer.md` learns:

- What bmchat is (P2P Bitmessage, PoW 1000/1000, ECIES secp256k1, streams, no servers)
- Architecture (`bmchat/core`, `crypto`, `net`, `gui`, `protocol`, `util` + 7 Design Patterns)
- Known bottlenecks & how to optimize (see skill § Bottlenecks)
- Guardrails (554 tests, PT-BR/EN, ruff/mypy, no wire break)

For OpenCode, the skill frontmatter (`name`, `description`) makes it auto-discoverable.

### 4. Environment variables (optional)

```bash
export BMCHAT_LLM_CONFIG="ai/config/openai-gpt4o.json"
export BMCHAT_LLM_PROVIDER="openai"
# your runner can read the JSON and inject system_prompt
```

## Prompt Quick Start

| Goal | File | One-liner |
|---|---|---|
| Speed up chat & PoW | `ai/prompts/performance.md` | "Optimize `gui/app.py:_redraw_chat` and `crypto/pow/standard.py` — profile, cache, virtual scroll" |
| Security audit | `ai/prompts/security-audit.md` | "Audit ECIES, WIF, `Image.open()` allowlist, PoW targets vs CVEs in SECURITY.md" |
| Refactor safely | `ai/prompts/refactor.md` | "Refactor using existing 7 patterns — Strategy/Repository/Observer — keep `client.db` compat" |
| Add tests | `ai/prompts/testing.md` | "Add unit/integration/stress tests to reach >95% on logic, mock PoW/net, no Tk" |
| Write docs | `ai/prompts/documentation.md` | "Update EN/PT-BR docs, keep TOC, add diagrams, preserve `branch.md` history" |

## Validation

```bash
# JSON validity
for f in ai/config/*.json; do echo -n "$f: "; python3 -m json.tool "$f" > /dev/null && echo OK || echo FAIL; done

# YAML compatibility (if you have yq)
python3 -c "import json, glob; [json.load(open(p)) for p in glob.glob('ai/config/*.json')]; print('all JSON valid')"

# Skill frontmatter
head -20 ai/skills/bmchat-optimizer.md
```

## Updating

- Add a new LLM: copy an existing JSON, change `model/provider/context_window`, keep `system_prompt` and `prompts` structure.
- Keep `ai/README.pt-BR.md` in sync (same structure, translated).
- Never break `pytest -q` — 554 tests are the contract (see skill § Rules).

## References

- Main docs: `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `branch.md`
- Tests: `tests/` (`unit/` 470+ · `integration/` 15 · `stress/` 15)
- Design patterns: `ARCHITECTURE.md` § Implemented Patterns

---
*Maintained in branch `feat/ai-llm-config-20260910` — rolling-release will merge via `--no-ff`.*
