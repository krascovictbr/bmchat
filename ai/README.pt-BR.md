> **Idioma:** [Português (BR)](README.pt-BR.md) | [English](README.md)

# 🤖 Configuração AI / LLM — bmchat

> Hub central de configurações AI/LLM para otimizar, auditar e evoluir o **bmchat** — mensageiro P2P estilo Telegram sobre o protocolo Bitmessage (Python + Tkinter, sem servidores).

## Propósito

Esta pasta (`ai/`) é a **fonte única de verdade** para qualquer agente AI/LLM trabalhando no bmchat. Ela oferece:

- **Configs prontas** para as 7 famílias principais de LLMs (OpenAI, Anthropic, Google, Meta, Mistral, DeepSeek, Cohere) com system prompts ajustados ao bmchat e prompts por tarefa.
- **Prompts otimizados** para tarefas comuns (performance, auditoria de segurança, refactor, testes, documentação).
- **Definição de skill** (`skills/bmchat-optimizer.md`) que ensina qualquer agente o que é o bmchat, sua arquitetura, gargalos e regras.

Use para obter **saídas consistentes e verificadas** independente do LLM — todas as configs embutem o mesmo contexto e restrições do bmchat.

## Estrutura

```
ai/
├── README.md                    # EN
├── README.pt-BR.md              # este arquivo
├── .gitkeep
├── config/  (alias: llms/)      # JSON por LLM (JSON válido, compatível com YAML)
│   ├── openai-gpt4o.json
│   ├── openai-gpt4o-mini.json
│   ├── anthropic-claude-3.5-sonnet.json
│   ├── google-gemini-1.5-pro.json
│   ├── google-gemini-1.5-flash.json
│   ├── meta-llama-3.1.json
│   ├── mistral-large.json
│   ├── deepseek-v3.json
│   └── cohere-command-r-plus.json
├── prompts/                     # prompts por tarefa (markdown, prontos para copiar)
│   ├── performance.md
│   ├── security-audit.md
│   ├── refactor.md
│   ├── testing.md
│   ├── documentation.md
│   └── code-review.md
└── skills/
    └── bmchat-optimizer.md      # skill OpenCode com frontmatter
```

- `ai/config/` é canônico; `ai/llms/` é symlink (`llms -> config`) para descoberta — ambos funcionam.
- Todas as configs são **JSON válido** (YAML também é aceito se converter — estrutura idêntica).

## LLMs Suportados

| Provedor | Modelo(s) | Arquivo | Contexto | Temp* | Melhor para |
|---|---|---|---|---|---|
| **OpenAI** | GPT-4o | `openai-gpt4o.json` | 128k | 0,20 | raciocínio profundo, refactor, arquitetura |
| **OpenAI** | GPT-4o-mini | `openai-gpt4o-mini.json` | 128k | 0,20 | iteração rápida, docs, testes |
| **Anthropic** | Claude 3.5 Sonnet | `anthropic-claude-3.5-sonnet.json` | 200k | 0,20 | auditoria de segurança, review longo |
| **Google** | Gemini 1.5 Pro | `google-gemini-1.5-pro.json` | 2M | 0,25 | codebase enorme, análise cross-file |
| **Google** | Gemini 1.5 Flash | `google-gemini-1.5-flash.json` | 1M | 0,25 | varreduras rápidas, CI |
| **Meta** | Llama 3.1 405B/70B/8B | `meta-llama-3.1.json` | 128k | 0,30 | open-source, self-hosted |
| **Mistral** | Mistral Large 2 | `mistral-large.json` | 128k | 0,25 | geração de código, multilíngue |
| **DeepSeek** | DeepSeek-V3 / R1 | `deepseek-v3.json` | 128k | 0,20 | custo-benefício, tarefas de código |
| **Cohere** | Command R+ | `cohere-command-r-plus.json` | 128k | 0,30 | RAG, tool-use, docs |

\* `temperature` padrão ajustada para bmchat: baixa (0,2–0,3) = determinística, segura para testes. Suba para 0,5 só para docs/ideias.

Todas documentam `model`, `provider`, `context_window`, `max_output_tokens`, `temperature`, `top_p`, `system_prompt` e `prompts` (performance/security/refactor/testing/docs).

## Como Usar

### 1. Escolha uma config

```bash
cat ai/config/anthropic-claude-3.5-sonnet.json | jq .system_prompt
# ou via symlink
cat ai/llms/openai-gpt4o.json | jq .prompts.performance
```

Copie `system_prompt` para a instrução de sistema do seu LLM, depois copie o prompt da tarefa que precisa em `prompts.*`.

### 2. Use os prompts de tarefa

```bash
ls ai/prompts/
cat ai/prompts/performance.md        # cole no chat
cat ai/prompts/security-audit.md
```

Cada `ai/prompts/*.md` já inclui contexto do bmchat — não precisa re-explicar o projeto.

### 3. Carregue a skill (OpenCode / qualquer agente)

Qualquer agente que ler `ai/skills/bmchat-optimizer.md` aprende:

- O que é bmchat (P2P Bitmessage, PoW 1000/1000, ECIES secp256k1, streams, sem servidores)
- Arquitetura (`bmchat/core`, `crypto`, `net`, `gui`, `protocol`, `util` + 7 Design Patterns)
- Gargalos conhecidos e como otimizar (ver skill § Gargalos)
- Regras (554 testes, PT-BR/EN, ruff/mypy, não quebrar wire com PyBitmessage)

No OpenCode, o frontmatter (`name`, `description`) torna a skill auto-descobrível.

### 4. Variáveis de ambiente (opcional)

```bash
export BMCHAT_LLM_CONFIG="ai/config/openai-gpt4o.json"
export BMCHAT_LLM_PROVIDER="openai"
# seu runner pode ler o JSON e injetar system_prompt
```

## Início Rápido por Objetivo

| Objetivo | Arquivo | Resumo |
|---|---|---|
| Acelerar chat & PoW | `ai/prompts/performance.md` | "Otimize `gui/app.py:_redraw_chat` e `crypto/pow/standard.py` — profile, cache, scroll virtual" |
| Auditoria de segurança | `ai/prompts/security-audit.md` | "Audite ECIES, WIF, allowlist `Image.open()`, alvos PoW vs CVEs em SECURITY.md" |
| Refactor seguro | `ai/prompts/refactor.md` | "Refatore usando os 7 patterns existentes — Strategy/Repository/Observer — mantenha compat `client.db`" |
| Adicionar testes | `ai/prompts/testing.md` | "Adicione unit/integration/stress para >95% na lógica, mock PoW/net, sem Tk" |
| Escrever docs | `ai/prompts/documentation.md` | "Atualize docs EN/PT-BR, mantenha índice, adicione diagramas, preserve histórico `branch.md`" |

## Validação

```bash
# validade JSON
for f in ai/config/*.json; do echo -n "$f: "; python3 -m json.tool "$f" > /dev/null && echo OK || echo FAIL; done

# Skill frontmatter
head -20 ai/skills/bmchat-optimizer.md
```

## Atualização

- Novo LLM: copie um JSON existente, troque `model/provider/context_window`, mantenha estrutura `system_prompt` e `prompts`.
- Mantenha `ai/README.pt-BR.md` em sync (mesma estrutura, traduzido).
- Nunca quebre `pytest -q` — 554 testes são o contrato (ver skill § Regras).

## Referências

- Docs principais: `README.pt-BR.md`, `ARCHITECTURE.pt-BR.md`, `SECURITY.pt-BR.md` / `SEGURANCA.MD`, `branch.pt-BR.md`
- Testes: `tests/` (`unit/` 470+ · `integration/` 15 · `stress/` 15)
- Design patterns: `ARCHITECTURE.pt-BR.md` § Padrões Implementados

---
*Mantido na branch `feat/ai-llm-config-20260910` — rolling-release fará merge via `--no-ff`.*
