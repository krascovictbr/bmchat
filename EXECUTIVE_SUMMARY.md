# BMCHAT — Resumo Executivo (EXECUTIVE_SUMMARY.md)

- **Branch:** `analysis/complete-audit-20260907` · Base `d199a10` · 2026-09-07 UTC
- **Escopo:** 33 `.py`, 7471 linhas · flake8 82 avisos · mypy 0 · bandit H3/M2/L112 · pytest amostral 6 passed

## Veredito em 30 segundos

O núcleo cripto/protocolo está **correto e interoperável** (MAGIC, PoW-mínimo, ECIES/ECDSA, objetos v1/v4/v5 conferem com PyBitmessage). Não há SQLi nem import circular. O risco está em **fluxo e ciclo de vida**: primeiro envio DM queima PoW e não anuncia (A1), PoW incancelável que prende processos (A2), chans funcionam no backend mas são invisíveis na GUI (A3), retry/reannounce com comportamento errado (B6/B7), rede permissiva a flood (B11–B13), e chaves em claro sem permissão de diretório (A5). Nada disso exige re-arquitetura — são fixes locais priorizados abaixo.

## Top 5 (corrigir primeiro)

1. **A1 — 1º envio DM trava ~10 min** (`client.py:557` sem `done_cb`) — 0.5h.
2. **A2/A4 — PoW não cancela / trava no exit** (`pow.py` step 1<<54) — 1 dia.
3. **A3 — Chans inalcançáveis na GUI** (`app.py:1118` só lista contatos) — 1–2 dias.
4. **B6/B7/B8 — reannounce 1-shot, retry fork-bomb, stop sem join** — 1–2 dias.
5. **A5 — chaves em claro + `makedirs` sem 0o700 + update sem verify** — 1h (permissão) + 1 dia (verify).

Próximos: B11/B12/B13 (rede antiflood), B14 (teto body antes do PoW), B9/B10 (target float, chave 0).

## Números

- Achados validados: **5 críticos, 16 altos, 40 médios, ~35 baixos**
- Categorias: Lógica 38% · Consistência 18% · Concorrência 14% · Segurança 12% · Performance 12%
- Funções >50 linhas: 13 (pior: `_build_widgets` 196, `_redraw_chat` 161)
- Falsos-positivos descartados: bandit B413/B404/B603/B606/B608/B104, `elif`-como-nesting, `checksumfailed`.

## O que já está bom (manter)

- Imports/símbolos 100% conferem; `mypy` limpo; sem SQLi (tudo `?`); sem ciclo circular (lazies intencionais).
- Protocolo/cripto núcleo idêntico à referência; `requirements` compatível; README §§_fluxo/ACK/suporte/update batem (só overclaims pontuais a ajustar).
- H1/H2 de broadcast já fixados em `d199a10` + 2 testes de regressão.

## Plano (4 branches)

1. Hotfix envio (A1+B4+B14+B2) · 2. PoW/estabilidade (A2+B1+B7+B3) · 3. Rede antiflood (B11+B12+B13+C5) · 4. Ciclo de vida + GUI chans + endurecimento (B6+B8+A3+A5). Higiene (bloco D) no contínuo + `pip audit`/`pytest-cov` no CI.

Detalhes, código antes/depois e estimativas por item: ver `ANALYSIS_REPORT.md`.
