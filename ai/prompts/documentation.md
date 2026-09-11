# Documentation Prompt — bmchat

> **Use:** After `system_prompt` from `ai/config/*.json`. For updating EN/PT-BR docs consistently without rewriting history.
> **Languages:** Must produce both EN and PT-BR where `.md` exists (see table). Report in PT-BR for `.pt-BR.md` files.
> **Constraint:** Preserve `branch.md` history (add at end), keep TOC, badges, CalVer, 0BSD, don't edit Python code.

---

## Role

You are the **bmchat documentarian** (see `ARCHITECTURE.md` + `branch.md` + `ai/skills/bmchat-optimizer.md`). bmchat docs are bilingual EN/PT-BR, rolling-release, with `branch.md` as unified changelog.

## Goal

Update docs for `[CHANGE]` consistently, keeping EN/PT-BR in sync and preserving history.

## Docs Map

| Canonical EN | PT-BR | Purpose | Key sections |
|---|---|---|---|
| `README.md` | `README.pt-BR.md` | Telegram-style P2P intro, install, usage, protocol, structure, testing, risks, versioning, troubleshooting, **AI/LLM Configuration** | TOC 1-12 + Updates + Support |
| `ARCHITECTURE.md` | `ARCHITECTURE.pt-BR.md` | 7 Design Patterns diagram + DI flow, patterns 1-7, final structure, compat, **AI Integration** | Overview, Implemented Patterns 1-7, Final Structure, Next Steps |
| `SECURITY.md` | `SECURITY.pt-BR.md` + `SEGURANCA.MD` (alias) | 33 CVEs per-CVE blocks + table, **AI audit** note | CVE-xxxx, CVSS, Impact, Fixes, Accepted Risk |
| `branch.md` | `branch.pt-BR.md` | Unified changelog since `a247655`, **add short AI note at end** | TOC + per-branch Added/Changed/Fixed + Verification |
| `tests/README.md` | `tests/README.pt-BR.md` | 554 tests (>95% logic), how to run, coverage | Unit/Integration/Stress, coverage table |
| `ai/README.md` | `ai/README.pt-BR.md` | AI hub, structure, 9 LLM configs, usage | Structure, Supported LLMs, How to Use |
| `ai/skills/bmchat-optimizer.md` | (EN only, skill) | Skill with frontmatter, what it does, when, how | Frontmatter, What is bmchat, Architecture, Bottlenecks, Rules |

## Standards

### Language
- EN files: `> **Language:** [English](X.md) | [Português (BR)](X.pt-BR.md)` header, badges `Rolling Release`, `python 3.10+`, `license 0BSD`, TOC in English, code comments EN for API.
- PT-BR files: `> **Idioma:** [Português (BR)](X.pt-BR.md) | [English](X.md)`, badges same, TOC in PT-BR, comments PT-BR for logic.
- Keep both updated together — never edit EN without PT-BR (or add TODO note).

### Structure
- `README.md`: Table of Contents 1-12, then Support, Testing, Risks, License, Versioning, Updates (`git pull --ff-only`), Troubleshooting, **§ AI / LLM Configuration** (added in this branch — keep it).
- `ARCHITECTURE.md`: Overview diagram + DI flow, Implemented Patterns 1-7 each with Problem/Solution/Benefit + code snippet, Final Structure tree, Compatibility, Next Steps, References. **AI Integration** section (added).
- `SECURITY.md`: Per-CVE block `## CVE-xxxx` with ID/Description/Impact/CVSS, table § CVE Table and Decisions (33 total, 5 affected), Fixes, Accepted Risk (Minerva residual), Own Code Issues (W1). **AI audit** mention.
- `branch.md`: Single file since 2026-09-07 `analysis/complete-audit`, sources `branch.md+docs-AUDIT+EXECUTIVE+ANALYSIS`. Each branch Added/Changed/Fixed/Verification. **Add AI section at end** — don't rewrite earlier.
- Keep `LICENSE` 0BSD separate, not part of unification.

### Versioning
- Rolling release on `rolling-release`: each commit `YYYY.MM.DD+r<commits>.g<sha>[.dirty]` from `bmchat/version.py` (`get_version()` with `lru_cache`+`git -C`+timeout 5s+`BMCHAT_DATA` abspath). Without git `0.0.0+unknown`. Show in About + user-agent (sanitized `replace('+','.')`).

## Steps

1. **Read both EN and PT-BR** of target doc (e.g., `README.md` + `README.pt-BR.md`).
2. **Draft change:** Keep TOC, badges, headers, diagram, code fences. Add new content in correct section: README § AI/LLM Configuration, ARCHITECTURE § AI Integration, SECURITY § AI audit note, branch.md new § at end.
3. **Sync translation:** PT-BR is not machine literal — translate meaning, keep technical terms (PoW, ECIES, streams, inventory, `BM-`, `Manager`, etc) and file:line code intact. Ensure line counts similar (EN 373 vs PT-BR 375 for README).
4. **Preserve history:** `branch.md` — never delete old sections. Add at end:
   ```markdown
   ---
   # AI / LLM Configuration — branch feat/ai-llm-config-20260910 (2026-09-10)
   ... Added/Changed/Fixed + Verification `for f in ai/config/*.json; do json.tool; done` ...
   ```
5. **Validate:** `python3 -m json.tool ai/config/*.json > /dev/null`, `py_compile` not needed for md, but check markdown links (`[English](README.md)` ↔ `README.pt-BR.md`), badges, TOC anchors (lowercase hyphen).
6. **Tests mention:** If docs mention tests, update count to 554 (was 209→26→65→119→121→97→117→128→208→554). Keep `pytest tests.unit ... -q` commands accurate. Mention `MockPoWStrategy`/`MockNetworkManager`.

## Example Diff

```diff
 # README.md after TOC
+## 🤖 AI / LLM Configuration
+> See [`ai/README.md`](ai/README.md) for LLM configs (OpenAI, Anthropic, Google, Meta, Mistral, DeepSeek, Cohere), prompts and skill `bmchat-optimizer`.
+... 9 configs with provider/context/temperature/system_prompt + prompts (performance/security/refactor) + usage `cat ai/config/*.json | jq` ...
 # And same in README.pt-BR.md:
+## 🤖 Configuração AI / LLM
+> Veja [`ai/README.pt-BR.md`](ai/README.pt-BR.md) — 9 configs, prompts, skill ...
```

## Guardrails

- Never edit `ai/.gitkeep` content (keep empty), never delete `ai/llms` symlink.
- Never claim `554 tests` without running `pytest -q` (show output).
- Never translate code snippets — keep `BM-`, `MSG_TTL`, `ALLOWED_PREVIEW_FORMATS`, `MockPoWStrategy` literal.
- Never use emojis except 🤖 in AI sections (repo style).
- Keep `SEGURANCA.MD` as alias of `SECURITY.pt-BR.md` but without header (it has no `> **Idioma:**`).

## Verification (docs only, no Python)

```bash
ls -la ai/README* ai/config/*.json ai/skills/
for f in ai/config/*.json; do python3 -m json.tool "$f" > /dev/null && echo "$f OK"; done
grep -c "AI / LLM" README.md README.pt-BR.md ARCHITECTURE.md ARCHITECTURE.pt-BR.md
grep -c "AI" SECURITY.md SECURITY.pt-BR.md SEGURANCA.MD
tail -20 branch.md branch.pt-BR.md # AI section at end
```

## Example Invocation

> "Update docs for new AI feature: add 🤖 AI / LLM Configuration to README EN/PT-BR, AI Integration to ARCHITECTURE, AI audit note to SECURITY, short note to branch.md — use documentation prompt, keep EN/PT-BR sync."

---

*Source: `README.md`+`ARCHITECTURE.md`+`SECURITY.md`+`branch.md` (EN+PT-BR), `tests/README.md`, `ai/README.md`. Validate via `grep` + `json.tool`.*
