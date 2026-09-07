# branch.md — changelog e auditorias unificadas

> Arquivo único de documentação de branches/auditorias. Unificado em 2026-09-07 na branch `analysis/complete-audit-20260907`.
> Origens: `branch.md` (ui-optimization) + `docs-AUDIT-anti-hallucination.md` + `EXECUTIVE_SUMMARY.md` + `ANALYSIS_REPORT.md`.
> `README.md` e `LICENSE` permanecem separados (não fazem parte desta unificação).

## Índice

- [ui-optimization (2026-09-07)](#ui-optimization--2026-09-07)
- [audit/anti-hallucination-20260907](#auditoria-anti-alucinação--auditanti-hallucination-20260907)
- [analysis/complete-audit-20260907 — resumo executivo](#analysiscomplete-audit-20260907--resumo-executivo)
- [analysis/complete-audit-20260907 — relatório completo](#bmchat--relatório-completo-de-auditoria-analysis_reportmd)

---

# Changelog — branch `ui-optimization`

Registro das atualizações vindas do branch `ui-optimization`
(merge fast-forward `57a0d15` em `rolling-release`, 2026-09-07;
base `a247655`). Formato: Adicionado / Mudado / Corrigido.

## [ui-optimization] — 2026-09-07

### Adicionado
- Paginação do chat: últimas 200 mensagens + pílula "carregar mensagens
  anteriores" (+200 por clique).
- Cache de quebra de linha `(texto, largura)`, cap 500 FIFO.
- Debounce de 80 ms no hover e no redimensionar da lista de conversas.
- Coalescing de eventos de mensagem (200 ms) e limite de 1 atualização/s
  no progresso do PoW.
- Scrollbar visível na lista de conversas.
- `transient(parent)` nos 7 popups próprios.
- Foco no campo de texto ao abrir conversa; placeholder "Mensagem" com
  restauração ao perder o foco.
- Consentimento explícito no envio de diagnóstico ao suporte (checkbox
  destrava o Enviar).
- Singleton no popup de emoji.
- `messages_for_conversation(address, limit=None)` no banco (default
  preserva o comportamento antigo).
- Validação no envio: identidade obsoleta e contato removido avisam em vez
  de criar mensagem fantasma/órfã; rascunho limpo ao trocar de conversa.
- Menus dispensam em qualquer clique fora; removidos menubar nativo e botão
  `⋮` (só hambúrguer ☰); entrada "Verificar POW ativos" no hambúrguer.
- Diálogos com esqueleto comum, foco inicial, Enter/Escape, centralização,
  scrollbar e altura dinâmica no `choose`, abertura sem cintilação e grab
  sempre liberado.

### Mudado
- Redraw do chat: pula relayout se a largura não mudou; doodle só no
  viewport (era até 6000 px).
- `_fit_width` com busca binária; prévia da conversa e não-lidas com menos
  queries (1 `GROUP BY` + `LIMIT 1`).
- Placeholder em português; fonte do welcome reutilizada em vez de recriada.
- `_poll` mostra erro de handler conhecido e ignora evento malformado sem
  matar o loop.
- Diálogo de diagnóstico/backup/log/rede: rodapé de botões empacotado
  primeiro (botões sempre visíveis).
- Tela de suporte e backup com botão "Enviar diagnóstico".

### Corrigido
- Palavra gigante sem espaço congelava a interface (`_wrap_lines` O(n²) →
  ~4 medições por trecho).
- Índice de seleção obsoleto quebrava ao abrir conversa.
- Mensagem de checksum errado inalcançável (código real `'checksumfailed'`).
- "Verificar POW" contava conexões ainda negociando (agora só estabelecidas).
- Códigos de atualização em inglês cru traduzidos.
- `db.close()` duplo levantava exceção.

### Verificação
- `pytest tests/ -q`: **24 passed**.
- Smokes Tkinter: paginação (250 msgs → 1907 itens), hover, scrollbar,
  envio, 71 checks de diálogos, consentimento, menus, startup e fechamento
  sem erros de callback.
- Medido: redraw 500 msgs 1382 ms → 216 ms; lista 100 conversas 1062 ms →
  682 ms; preview 20 conversas ~99 ms → ~19 ms.

---

## Auditoria anti-alucinação — `audit/anti-hallucination-20260907`

Branch isolada (sem conflito com `rolling-release`): `audit/anti-hallucination-20260907`
Data: 2026-09-07 · Base: `rolling-release@22964ff`
Escopo: todo `bmchat/` + `run.py` + `tests/` (7386 linhas)

Método: 4 frentes paralelas (imports/símbolos, APIs/assinaturas, dead-code/refs, protocolo/cripto vs PyBitmessage),
com `py_compile`, `pyflakes`/`ruff` (zero `F821`/`F822`), `import` em runtime de todos os módulos,
cruzamento AST `def` × chamadas, e reprodução executada dos suspeitos.

### 1. Alucinações reais — CORRIGIDAS

#### H1 [CRÍTICO] `bmchat/core/client.py:499` — `incoming.stream` inexistente
Antes:
```python
channel_address = reverse.get(parsed.data[:32], incoming.stream)
```
`IncomingBroadcast.__slots__` (`protocol/objects.py:283`) só tem
`sender_version`/`sender_stream` — nunca `stream` (`stream` só existe em
`ParsedObject` e `AddressKeys`). Avaliação eager fazia a linha levantar
`AttributeError` em **todo** broadcast; como `_on_object` engole exceção,
tudo era logado como `erro ao processar objeto` e descartado. Além disso o
fallback seria `int` onde se espera endereço (`str`).
Teste antigo não pegava: `test_chan_subscribe_and_post` chamava
`objects.process_broadcast` direto, nunca `Client._on_broadcast`.

Depois:
```python
channel_address = reverse.get(parsed.data[:32])
if channel_address is None:
    return
```
Se a tag foi decifrada, ela está em `reverse` por construção; se houve
corrida (inscrição removida no meio), apenas ignora em vez de gravar tipo errado.

#### H2 [ALTO] dono do chan sem inscrição perdia posts — `encryption_private_from_address=None`
`AddressKeys.from_private_keys`/`generate_keys`/`chan_keys_from_name` nunca
preenchem `encryption_private_from_address` (só `from_address` preenche).
`_on_broadcast` registrava a identidade chan via `self.identities.get(...)`
com esse campo `None`; `process_broadcast` → `ecies.decrypt(..., None)` →
`TypeError` → `return None` (descarte silencioso). Só funcionava por acidente
quando o dono também estava inscrito (`setdefault` preservava a entrada boa).

Correção no mesmo bloco: identidades chan agora entram via
`AddressKeys.from_address(channel['address'])` (chave de decrypt derivável
do endereço, igual ao PyBitmessage), com `try/except` e `setdefault` mantidos:
```python
for channel in self.db.all_identities(enabled_only=False):
    if channel['chan'] and channel['enabled']:
        try:
            keys = AddressKeys.from_address(channel['address'])
        except Exception:
            continue
        subscriptions.setdefault(keys.tag, keys)
        reverse.setdefault(keys.tag, channel['address'])
```

Reprodução validada (script efêmero, depois virado em teste):
- com inscrição → 1 mensagem + evento `('broadcast', addr, ...)`
- dono chan sem inscrição → 1 mensagem (antes: 0)

### 2. Verificado e LIMPO (sem alucinação)

- **Imports/símbolos:** todos os `from X import Y` conferem (`client`, `keys`,
  `ecc`, `ecies`, `objects`, `packets`, `const`, `manager`, `peer`, `proxy`,
  `app`, `dialogs`, `run`, `tests`). `py_compile` OK nos 33 arquivos.
  Terceiros conferem: `ecdsa.SECP256k1/SigningKey/VerifyingKey/Point`,
  `Crypto.Cipher.AES/Padding/RIPEMD160`, `socks.PROXY_TYPE_*/socksocket`, `tkinter`.
- **APIs/assinaturas:** `Database`, `NetworkManager`, `packets`, `objects.*`,
  `PowExecutor`, `keys.*`, `proxy.ProxyProfile`, `dialogs.*`,
  `update.check/perform/restart`, `SUPPORT_*`, `__version__` — aridades, kwargs
  e ordens de tupla conferem. `connection.is_alive()` é `Thread.is_alive` herdado.
- **Protocolo/cripto vs referência:** `MAGIC=0xE9BEB4D9`, porta `8444`, ver `3`,
  `NODE_NETWORK=1/SSL=2/DANDELION=8`, tipos `0/1/2/3`, `tor/addr/I2P`,
  `MAX_*`, comandos `version/verack/addr/inv/getdata/object/ping/pong/dinv/error`,
  layouts `version/addr/inv/getdata`, header objeto, `getpubkey v4/pubkey v4/msg v1/
  broadcast v5`, ECIES (`IV+R+CT+MAC`, `KDF=sha512(X)`), ECDSA DER/SHA256,
  fórmula PoW, janela `-1h/+28d+3h`, `ripe/tag/chan/WIF/varint/base58` — todos
  idênticos à referência (`PyBitmessage/src`, `/tmp/opencode/bmsrc`).
- **`requirements.txt`:** cobre `socks`, `Crypto`, `ecdsa`; resto é stdlib;
  `tkinter` corretamente fora (stdlib, declarado no README).
- **Paths/env:** `~/.bmchat`/`$BMCHAT_DATA`/`bmchat.db`/`knownnodes.dat`/`run.py`
  existem e batem com README. Sem `TODO/FIXME`.
- **Falso-positivo esclarecido:** `branch.md:49` dizia "checksumfailed inalcançável";
  hoje `gui/app.py:2226` trata `checksumfailed` — está vivo.

### 3. Não-alucinações documentadas (não corrigidas aqui de propósito)

Para não gerar conflito nem mudar comportamento, registrado apenas:

- **Dead code (nunca chamado):** `database.delete_identity/set_identity_label/
  set_identity_difficulty/get_message/messages_for/messages_for_contact/
  mark_conversation_read/recent_messages/object_type_of/get_pubkey`,
  `address.validate_address/add_bm_prefix`, `packets.assemble_version/
  version_packet_command/is_onion`, `proxy.resolve_hostname`, `ecc.ecdh_x`,
  `keys.public_encryption_point`, `hashing.sha256/sha512_obj/sha512_hash_id`,
  `client.create_channel/broadcast/broadcast_chan/cancel_pow`,
  `peers.PeerStore.add_peer`, `Peer.__eq__/__hash__`, `app._unread_for/
  _last_message_row/_last_message_for/_ChatTextAdapter.get/tag_names/see/config/
  _ConvListAdapter.size/get/selection_clear/selection_set/bind`,
  `varint` raise inalcançável. Constantes só definidas: `NODE_SSL/DANDELION`,
  `OBJECT_ONIONPEER/ADDR/I2P`, `MAX_ADDR/MSG/PAYLOAD/COUNT/TIME_OFFSET`,
  `DEFAULT_PORT`, `ENCODING_IGNORE/SIMPLE/EXTENDED`, `SELF_NONCE`, `X_LEN`,
  `ORDER_BYTES`, `dialogs.DIM`, `APP_NAME/APP_VERSION`.
- **Status sem consumidor específico** (caem em `else` genérico, por design):
  `address.*`, `update 'unknown'`, `app {'status':'error'}`,
  `broadcast 'error/mismatch/noname'`, `add_contact 'unsupported'`,
  `import_identity 'invalid/exists'`, evento `('status',id,'sending')`.
- **Divergências de protocolo (tolerantes, consenso-válidas, sem fix):**
  `peer.py:137` aceita 16 MB (ref 1.6 MB); `manager.py:171` tolera +44 B e sem
  mínimos por tipo; porta local hard `8444`; services sempre `1`; getpubkey
  sempre v4 (contato v3 nunca completa, mas README já diz v2/v3 recusados);
  `MSG/GETPUBKEY_TTL=4d` vs `4.25d/2.5d+backoff` ref; `address.py` frouxo em
  tamanhos ripe; só `pubkey v4/broadcast v5`; janela `addr` sem filtro stream/
  alive; onion v3 vira `0.0.0.0`; só `SHA256` (sem fallback `SHA1` legado);
  só envia `TRIVIAL`, `SIMPLE` mostra `Subject/Body` cru, `EXTENDED` vira lixo;
  `dinv` tratado como `inv`; sem PoW custom por destinatário. Nada inventado,
  só permissivo/estrito em pontos — anotado para decisão futura, fora do escopo
  anti-alucinação.

### 4. Arquivos tocados (mínimo, sem conflito)

- `bmchat/core/client.py` — bloco `_on_broadcast` (H1+H2), ~10 linhas.
- `tests/test_anti_hallucination.py` — NOVO, 2 testes de regressão.
- Este documento.

### 5. Validação

- `pytest tests/test_anti_hallucination.py -q`: **2 passed**.
- `pytest tests/ -q`: **24 passed** (suite original) + 2 novos = 26 no total da branch.
- `pyflakes`: só `F401/F841` (unused) — zero `F821/F822`.
- `compileall`: OK.

### 6. Como fundir sem conflito

```bash
git checkout rolling-release
git merge --ff-only audit/anti-hallucination-20260907
## ou, se rolling-release andou: git merge --no-ff audit/anti-hallucination-20260907
python3 -m pytest tests/ -q
```
Reversão segura: `git revert` do commit de `client.py` (testes novos podem ficar).

---

## analysis/complete-audit-20260907 — resumo executivo

- **Branch:** `analysis/complete-audit-20260907` · Base `d199a10` · 2026-09-07 UTC
- **Escopo:** 33 `.py`, 7471 linhas · flake8 82 avisos · mypy 0 · bandit H3/M2/L112 · pytest amostral 6 passed

### Veredito em 30 segundos

O núcleo cripto/protocolo está **correto e interoperável** (MAGIC, PoW-mínimo, ECIES/ECDSA, objetos v1/v4/v5 conferem com PyBitmessage). Não há SQLi nem import circular. O risco está em **fluxo e ciclo de vida**: primeiro envio DM queima PoW e não anuncia (A1), PoW incancelável que prende processos (A2), chans funcionam no backend mas são invisíveis na GUI (A3), retry/reannounce com comportamento errado (B6/B7), rede permissiva a flood (B11–B13), e chaves em claro sem permissão de diretório (A5). Nada disso exige re-arquitetura — são fixes locais priorizados abaixo.

### Top 5 (corrigir primeiro)

1. **A1 — 1º envio DM trava ~10 min** (`client.py:557` sem `done_cb`) — 0.5h.
2. **A2/A4 — PoW não cancela / trava no exit** (`pow.py` step 1<<54) — 1 dia.
3. **A3 — Chans inalcançáveis na GUI** (`app.py:1118` só lista contatos) — 1–2 dias.
4. **B6/B7/B8 — reannounce 1-shot, retry fork-bomb, stop sem join** — 1–2 dias.
5. **A5 — chaves em claro + `makedirs` sem 0o700 + update sem verify** — 1h (permissão) + 1 dia (verify).

Próximos: B11/B12/B13 (rede antiflood), B14 (teto body antes do PoW), B9/B10 (target float, chave 0).

### Números

- Achados validados: **5 críticos, 16 altos, 40 médios, ~35 baixos**
- Categorias: Lógica 38% · Consistência 18% · Concorrência 14% · Segurança 12% · Performance 12%
- Funções >50 linhas: 13 (pior: `_build_widgets` 196, `_redraw_chat` 161)
- Falsos-positivos descartados: bandit B413/B404/B603/B606/B608/B104, `elif`-como-nesting, `checksumfailed`.

### O que já está bom (manter)

- Imports/símbolos 100% conferem; `mypy` limpo; sem SQLi (tudo `?`); sem ciclo circular (lazies intencionais).
- Protocolo/cripto núcleo idêntico à referência; `requirements` compatível; README §§_fluxo/ACK/suporte/update batem (só overclaims pontuais a ajustar).
- H1/H2 de broadcast já fixados em `d199a10` + 2 testes de regressão.

### Plano (4 branches)

1. Hotfix envio (A1+B4+B14+B2) · 2. PoW/estabilidade (A2+B1+B7+B3) · 3. Rede antiflood (B11+B12+B13+C5) · 4. Ciclo de vida + GUI chans + endurecimento (B6+B8+A3+A5). Higiene (bloco D) no contínuo + `pip audit`/`pytest-cov` no CI.

Detalhes, código antes/depois e estimativas por item: ver `ANALYSIS_REPORT.md`.

---

## BMCHAT — Relatório Completo de Auditoria (analysis/complete-audit-20260907)

- **Branch de análise:** `analysis/complete-audit-20260907` (criada a partir de `audit/anti-hallucination-20260907@d199a10`)
- **Base auditada:** `d199a10` (inclui fix H1/H2 de broadcast) · anterior `rolling-release@22964ff`
- **Data/hora (UTC):** 2026-09-07 · Python 3.14.7 · Linux
- **Escopo:** 33 arquivos `.py` (29 em `bmchat/` + `run.py` + 4 em `tests/`), **7471 linhas** totais
- **Ferramentas executadas:** `flake8` (82 avisos, 0 bloqueantes), `mypy --ignore-missing-imports` (0 issues em 29 arquivos), `bandit` (Low 112 / Medium 2 / High 3), `py_compile` OK, `pytest` amostral (6 passed), AST próprio (funções >50 linhas, imports circulares, SQLi)
- **Metodologia:** Fases 1–5 do prompt (estrutural, estática por arquivo, comportamental, consistência, dependências/segurança). 4 subagentes paralelos + validação manual dos CRÍTICOS por leitura direta do código. Nenhum arquivo de produto foi alterado nesta branch — só estes relatórios.

> Convenção: cada achado segue `[TIPO] - SEVERIDADE`, arquivo:linha, função, descrição, código, impacto, solução, prioridade, estimativa. CRÍTICO/ALTO estão detalhados; MÉDIO/BAIXO estão em tabelas condensadas (mesmo conteúdo, sem repetição). Falsos-positivos do ferramental estão marcados como `[OK]` para não virarem issues.

---

### FASE 1 — Mapeamento estrutural

#### 1.1 Árvore e módulos

```
bmchat/ (5755 LOC varridas pelo bandit; 7471 com tests/run.py)
  __init__.py (9)       # APP_NAME/APP_VERSION/SUPPORT_* (SUPPORT vivo, APP_* morto)
  version.py (44)       # CalVer rolling git + user-agent; 4x subprocess por chamada, sem cache
  update.py (96)        # check (fetch) / perform (merge --ff-only) / restart (execv)
  core/
    client.py (812)     # ORQUESTRADOR: identidades, contatos, subs/chans, envio, ACK, PoW, retry, reannounce
    database.py (365)   # SQLite: schema+CRUD+settings; 44 funcs; sem FK/NOT NULL/user_version
  crypto/
    ecc.py (90)         # ECDSA DER/SHA256 sobre secp256k1 (ecdsa lib)
    ecies.py (80)       # ECIES (ECDH+AES-256-CBC+HMAC) envelope IV+R+CT+MAC
    keys.py (125)       # AddressKeys v4, tag/ripe, WIF, chan determinístico
    pow.py (128)        # PoW Bitmessage (target float! + ProcessPoolExecutor)
  protocol/
    address.py (72)     # base58+varint+checksum (v1–v4, mas só v4 suportado de fato)
    const.py (37)       # MAGIC/PORT/VER/NODE_*/OBJECT_*/MAX_*/TTL/ENCODING + USER_AGENT (IO no import)
    packets.py (149)    # header+version/addr/inv/getdata (+helpers onion)
    objects.py (372)    # getpubkey/pubkey/msg/broadcast + ParsedObject + validação
  net/
    manager.py (352)    # inventário 8000, known_hashes ilimitado, relay, snapshot, DNS seeds
    peer.py (270)       # handshake version/verack, comandos, limites 16MB (vs 2MB dos objetos)
    peers.py (146)      # PeerStore JSON (load frágil + save não-atômico + sem cap)
    proxy.py (84)       # Direto/Tor/I2P via PySocks; presets 9050/9150/4447/4444
  gui/
    app.py (2843)       # Tkinter Telegram-like; 143 funcs; 7 com >50 linhas (máx 196)
    dialogs.py (287)    # ask_simple/choose/info/warn/confirm (sem import de app — OK)
  util/ base58.py hashing.py varint.py (112)
run.py (17)             # entry: BMCHAT_DATA ou ~/.bmchat → gui.app.main
tests/ (842): test_integration (587), test_wire (135), test_interop (124), test_update (67), test_anti_hallucination (64)
```

#### 1.2 Arquitetura (fluxo real)

```
GUI (app.py poll 250ms ← ui_queue) ←→ Client ←→ NetworkManager ←→ PeerConnection ×N
  ↑↓ DB (sqlite, 1 conn+Lock)      ↑ PoW (ProcessPool × msg)   ↑ PySocks/Tor/I2P
Crypto (keys/ecc/ecies/pow) ←→ Protocol (address/objects/packets) ←→ Tests
```

#### 1.3 Dependências

`requirements.txt`: `PySocks>=1.7.1`, `pycryptodome>=3.15.0`, `ecdsa>=0.18.0` — todas usadas e presentes (1.7.1 / 3.23.0 / 0.19.2). `tkinter` é stdlib (corretamente fora do requirements). Restante só stdlib (`sqlite3`, `threading`, `subprocess`, `socket`, `hashlib`, `hmac`, `concurrent.futures`, etc.). Sem dependência obsoleta funcional (bandit reclama de `pycrypto` por heurística — na verdade é `pycryptodome`, mantido).

#### 1.4 Funções >50 linhas (AST, confirmado)

| Arquivo | Função | Linhas |
|---|---|---|
| gui/app.py | `_build_widgets` | 196 |
| gui/app.py | `_redraw_chat` | 161 |
| gui/app.py | `_build_support_report` | 85 |
| gui/app.py | `__init__` | 76 |
| gui/app.py | `_handle_event` | 55 |
| gui/app.py | `_draw_conversations` | 55 |
| gui/app.py | `_fill_backup_window` | 58 |
| core/client.py | `import_keys_dat` | 57 |
| core/database.py | `_create_schema` | 68 |
| protocol/objects.py | `process_broadcast` | 64 |
| protocol/objects.py | `_parse_msg_plaintext` | 56 |
| net/manager.py | `snapshot` | 55 |
| dialogs.py | `choose` | 60 |

Aninhamento real >3 confirmado só em: `client._reannounce_pubkeys` (4), `pow.run` (5), `manager._prune_connections` (4), `app._wrap_lines`/`_redraw_chat` (4). `peer._handle` e `app._poll/_handle_event` com `elif` longos são falsos-positivos de contador ingênuo.

---

### FASE 2+3+4+5 — Achados (deduplicados e validados por leitura)

#### BLOCO A — CRÍTICOS (corrigir primeiro; 5 itens)

##### [LÓGICA] - CRÍTICO — A1. Primeiro envio DM nunca anuncia o getpubkey
- Arquivo: `bmchat/core/client.py:553-557` · Função: `send_message`
- Descrição: quando o contato não tem pubkey, o código faz PoW mas **descarta o resultado** porque não passa `done_cb`; `_run_pow_and_done:659` só anuncia/executa callback `if done_cb is not None`.
- Código problemático:
```python
unsigned = objects.build_getpubkey_unsigned(
    int(time.time()) + GETPUBKEY_TTL, stream, 4, contact_keys.tag)
target = calculate_target(1000, 1000, len(unsigned) + 8, GETPUBKEY_TTL)
self._pow_and_publish(unsigned, target)  # sem done_cb → PoW queimado e jogado fora
return 'success', None
```
- Impacto: 1º envio para contato novo trava em `awaiting-pubkey` até o retry de ~10 min (`request_pubkey:521` passa `done_cb` e se recupera). Validado por leitura (contraposto com `request_pubkey`).
- Solução sugerida:
```python
self._pow_and_publish(unsigned, target,
    done_cb=lambda complete, nonce: self.net.announce_object(complete))
```
- Prioridade: Alta · Estimativa: 0.5h + teste de regressão (mock `_pow_and_publish`, assert announce chamado).

##### [CONCORRÊNCIA] - CRÍTICO — A2. Cancelamento de PoW não funciona (filhos queimam CPU até o fim)
- Arquivo: `bmchat/crypto/pow.py:51-77,89-108` · Funções: `search_range`, `PowExecutor.run`
- Descrição: `search_range` nunca consulta `stop_event`; pai só checa no `wait(timeout=0.4)`. `budget = 1<<54` por worker. `cancel_pow`/`stop` setam o evento mas os filhos continuam até o fim do range; `with ProcessPoolExecutor` ainda espera os filhos no `__exit__`.
- Código problemático:
```python
def search_range(args):
    initial_hash, target, start, budget = args
    ...
    while done < end:  # end-start pode ser 1<<54; sem checagem de stop_event
        ...
def run(self, ...):
    step = 1 << 54
    ...
    with ProcessPoolExecutor(max_workers=self.workers) as pool:  # __exit__ espera tudo
```
- Impacto: fechar app / cancelar PoW deixa processos órfãos a 100% CPU; `stop()` não retorna rápido. `_quick_pow:615` usa evento local incancelável (piora).
- Solução sugerida: budget pequeno (ex. `1<<20`) com re-submit (o loop pai já faz re-submit — basta reduzir `step`); ou evento compartilhado checado no filho; + `pool.shutdown(wait=False, cancel_futures=True)` no caminho de cancel. Teste: dispara PoW, cancela em <1s, assert processos encerram.
- Prioridade: Alta · Estimativa: 1 dia (inclui teste de processo).

##### [LÓGICA] - CRÍTICO — A3. Chans invisíveis na GUI (backend funciona, UI inalcançável)
- Arquivo: `bmchat/gui/app.py:1118-1127` (+ `1008,1024,1474,1447`) · Função: `_refresh_conversations`
- Descrição: lista só `all_contacts`; `all_subscriptions`/chans nunca entram em `_conv_meta`. Eventos `broadcast`/`broadcast-sent` chegam mas não há conversa para abrir; `_reload_chat` recarrega `current_address` (contato).
- Código problemático:
```python
def _refresh_conversations(self):
    self._conv_meta = []
    for contact in self.client.db.all_contacts():  # subs/chans ignorados
        self._conv_meta.append(('contact', contact['address']))
```
- Impacto: post de canal gravado no DB mas inalcançável — transição quebrada fim-a-fim. Quando listar, `_open_conversation:1499` e `_remove_entry:1447` ainda tratam tudo como contato (bug latente B2).
- Solução sugerida: incluir `all_subscriptions()` + identidades chan em `_conv_meta` com `kind`, ou aba dedicada; branch por `kind` em open/remove/unread/preview.
- Prioridade: Alta · Estimativa: 1–2 dias (UI + testes de navegação).

##### [LÓGICA] - CRÍTICO — A4. `PowExecutor.run` pode travar no `__exit__` após sucesso (já listado como ALTA na fase 2, elevado aqui por hang)
- Arquivo: `bmchat/crypto/pow.py:99-104` · Função: `run`
- Descrição: ao achar nonce, dá `cancel()` nos pendentes mas `cancel()` não interrompe tarefa em execução; `return nonce` dentro do `with` aguarda os workers terminarem o range gigante.
- Código: ver A2 (mesmo bloco).
- Impacto: mesmo com PoW rápido, thread trava até filhos esgotarem `1<<54` (na prática hang). Mesma correção de A2.
- Prioridade: Alta · Estimativa: incluída em A2.

##### [SEGURANÇA] - CRÍTICO (contextual) — A5. Chaves privadas em claro + diretório sem permissão
- Arquivo: `bmchat/core/database.py:10,18-45`, `run.py:9`, `bmchat/update.py:71` · Função: `Database.__init__`, `data_dir_default`, `perform_update`
- Descrição: `priv_signing/priv_encryption BLOB` sem cifragem; `makedirs(~/.bmchat, exist_ok=True)` sem `mode=0o700`; backup escreve WIF sem `chmod 0o600`; update faz `fetch+merge --ff-only` sem `verify-commit` e dá `execv` (RCE pós-comprometimento do remoto).
- Código problemático:
```python
os.makedirs(path, exist_ok=True)  # run.py:11 — sem 0o700
## database schema: priv_signing BLOB, priv_encryption BLOB (claro)
os.execv(sys.executable, [sys.executable, run_path])  # update.py:96
```
- Impacto: roubo de identidade por leitura de disco/backup; supply-chain se o remoto for comprometido. README já avisa "banco não cifrado" — o gap é permissão + update sem verificação.
- Solução sugerida (sem re-arquitetura): `makedirs(..., mode=0o700)` + `chmod 0o700/0o600` em DB/backup existentes; `git verify-commit` ou pin de chave no update (ou ao menos documentar risco + exigir confirmação); documentar "sem forward secrecy / sem anonimato garantido" (já existe — manter).
- Prioridade: Alta (permissão: imediata, 1h) / Média (verify-commit: 1 dia) · Estimativa total: 1–2 dias.
- Nota bandit: `B413 pycrypto` é falso-positivo de nome (é `pycryptodome` mantido); `B404/B603/B606 subprocess` são usos legítimos (`git`, `execv`) — manter, só endurecer args.

> H1/H2 da auditoria anterior (`incoming.stream`, chan-owner sem sub) já estão corrigidos em `d199a10` e cobertos por `tests/test_anti_hallucination.py` — não repetidos aqui como abertos.

---

#### BLOCO B — ALTOS (detalhados; 16 itens)

##### [LÓGICA] - ALTO — B1. Reenvio duplica PoW/announce (sem estado `sending` nem in-flight)
- Arquivo: `bmchat/core/client.py:88-97,549-551,560-600` · Funções: `_retry_awaiting`, `send_message`, `_pow_and_publish_message`
- Código: insere `awaiting-pubkey`, se `in pubkeys` dispara PoW mas status só vira `sent` no `done:588`; retry vê `in pubkeys` e re-dispara para o mesmo `message_id`.
- Impacto: 2× CPU + objeto duplicado na rede.
- Solução: status `sending` + `set[(message_id)]` in-flight com guarda; retry pula in-flight. Prioridade Alta · 4h.

##### [LÓGICA] - ALTO — B2. `subject` persistido mas nunca trafega
- Arquivo: `bmchat/core/client.py:539-547,578-580` + `protocol/objects.py:93` · Função: `send_message`
- Código: `add_message(..., subject ...)` mas `build_msg_unsigned(..., body, encoding, ack)` sem subject.
- Impacto: perda silenciosa / interop confusa. Solução: remover param ou prefixar no body / rejeitar `subject!=''`. Prioridade Média · 2h.

##### [LÓGICA] - ALTO — B3. Envio sem ACK silencioso quando `_quick_pow` falha
- Arquivo: `bmchat/core/client.py:573-580,608-617` · Função: `_pow_and_publish_message`, `_build_ack_packet`
- Código: `ack_packet, watch = _build_ack_packet(stream)`; se falha retorna `(b'', None)` e o envio segue sem ACK/sem watch.
- Impacto: remetente fica em `sent` para sempre. Solução: abortar com erro visível ou retry do ACK. Prioridade Alta · 3h.

##### [LÓGICA] - ALTO — B4. `send_message` quebra para v2/v3 (raise não tratado)
- Arquivo: `bmchat/core/client.py:541-544` · Função: `send_message`
- Código: `decode` aceita v2/v3 mas `AddressKeys.from_address` só v4 (`raise`).
- Impacto: crash na GUI ao enviar para contato v3 (permitido em `add_contact:327`). Solução: validar `version==4` + `try`. Prioridade Alta · 1h.

##### [LÓGICA] - ALTO — B5. Relay aceita/propaga PoW mínimo mesmo quando deveria exigir mais
- Arquivo: `bmchat/net/manager.py:178` + `crypto/pow.py:35-44` · Função: `received_object`
- Código: `is_proof_of_work_sufficient(raw)` com defaults `0,0` → 1000/1000.
- Impacto: spam propagado; risco de punição por pares. Solução: documentar relay permissivo + rate-limit, ou extrair dificuldade real. Prioridade Média · 4h.

##### [LÓGICA] - ALTO — B6. `_reannounce_pubkeys` roda uma vez e morre (sem loop)
- Arquivo: `bmchat/core/client.py:55-57,778-805` · Função: `_reannounce_pubkeys`
- Código: thread `client-reannounce` sem `while/sleep`; `LIMIT 200` global pode não cobrir todas as identidades (loop O(I×R) ainda por cima).
- Impacto: após `PUBKEY_TTL` identidade some da rede. Solução: loop 24h + query por identidade + índice tag. Prioridade Alta · 4h.

##### [LÓGICA] - ALTO — B7. Retry sem limite pode forkar o sistema
- Arquivo: `bmchat/core/client.py:66-97` · Função: `_retry_loop`, `_retry_awaiting`
- Código: 10 min fixos sem jitter; um PoW (`ProcessPool × cpu`) por endereço pendente, mesmo offline.
- Impacto: 1000 pendentes → fork-bomb/OOM. Solução: pular se `established==0`, concorrência limitada + backoff. Prioridade Alta · 1 dia.

##### [LÓGICA] - ALTO — B8. `stop()` fecha DB sem join (race com threads)
- Arquivo: `bmchat/core/client.py:59-64` + `database.py:105` · Função: `stop`
- Código: `db.close()` imediato; retry/maintenance/peers/PoW podem estar em query; `_on_object` ainda enfileira sem consumidor.
- Impacto: `ProgrammingError: closed database`. Solução: sinalizar, join com timeout, só então fechar; `query/execute` checar `closed`. Prioridade Alta · 4h.

##### [LÓGICA] - ALTO — B9. `calculate_target` retorna float (erro além de 2^53)
- Arquivo: `bmchat/crypto/pow.py:13-25` · Função: `calculate_target`
- Código: `return (2**64) / denominator` (float; ex. `1470226177730.2756`).
- Impacto: borda incorreta em dificuldades altas. Solução: `(2**64)//denominator` int. Prioridade Alta · 1h + teste vetorial.

##### [LÓGICA] - ALTO — B10. ECDH aceita chave 0 → INFINITY
- Arquivo: `bmchat/crypto/ecc.py:27-50` · Funções: `point_mult`, `point_from_secret`, `ecdh_point`
- Código: `value = int.from_bytes(secret) % ORDER` sem rejeitar 0.
- Impacto: crash posterior / ECDH fraco. Solução: `if not 1<=v<ORDER: raise`. Prioridade Alta · 2h.

##### [LÓGICA] - ALTO — B11. `send_packet` sem guarda derruba announce e conexão
- Arquivo: `bmchat/net/peer.py:47-58` + `manager.py:203-214` · Função: `send_packet`, `announce_object`
- Código: `sock.sendall` sem checar `None/closing` e sem `try` por peer; 1 falha aborta o laço e sobe até matar a thread de leitura.
- Impacto: perda de propagação + queda por falha isolada. Solução: guarda + `try/except` por conexão. Prioridade Alta · 3h.

##### [LÓGICA] - ALTO — B12. Teto de header 16MB + sem checksum (amplificação)
- Arquivo: `bmchat/net/peer.py:60-68,132-139` · Funções: `_recv_exact`, `_read_header`
- Código: `length>16MB` (8× o `MAX_OBJECT_LENGTH+64`); checksum desembrulhado e ignorado.
- Impacto: 16MB×8 conns = 128MB acionável; payload corrompido processado. Solução: teto `MAX_OBJECT_LENGTH+HEADER`, verificar `sha512[:4]`, `bytearray/recv_into`. Prioridade Alta · 4h.

##### [SEGURANÇA] - ALTO — B13. PeerStore sem cap + `best()` ordena tudo (envenenamento)
- Arquivo: `bmchat/net/peers.py:96-105,130-147` + `peer.py:241-253` · Funções: `add`, `best`
- Código: `add` sem limite/evicção/validação; `_on_addr` aceita 200/msg.
- Impacto: flood de `addr` → RAM+CPU. Solução: cap 2–5k + evicção por rating/seen + validar host/port + só promover após sucesso. Prioridade Alta · 1 dia.

##### [LÓGICA] - ALTO — B14. Sem teto de `body` antes do PoW (falso `sent`)
- Arquivo: `bmchat/core/client.py:580,679,737` · Funções: `_pow_and_publish_message`, `broadcast`, `broadcast_chan`
- Código: nenhum `len(body.encode)+overhead < MAX_OBJECT_LENGTH` antes de `calculate_target+PoW`.
- Impacto: queima PoW para objeto descartado, mas marca `sent`. Solução: validar e rejeitar com erro UI. Prioridade Alta · 2h.

##### [CONSISTÊNCIA] - ALTO — B15. `assemble_addr` ignora `services` (contrato mente)
- Arquivo: `bmchat/protocol/packets.py:95-104` · Função: `assemble_addr`
- Código: `struct.pack('>q', 1)` hardcoded; chamador `peer.py:233` passa `services` real.
- Impacto: anuncia capacidade errada (baixo hoje pois services sempre 1, mas latente). Solução: empacotar `services`. Prioridade Média · 1h.

##### [LÓGICA] - ALTO — B16. `process_broadcast`/`_parse_msg` sem cheques de comprimento + `ack_watch` sem expiração
- Arquivo: `bmchat/protocol/objects.py:171-200,287-325` + `client.py:384-395` · Funções: `_parse_msg_plaintext`, `process_broadcast`, `_maybe_mark_ack`
- Código: `b'\x04'+plain[pos:pos+64]` sem checar restante; `_take_varint` mascara truncamento (`return 0`); `_ack_watch` só `get/set`.
- Impacto: robustez + leak + replay spam. Solução: `len` checks, `pop`+TTL no watch. Prioridade Média · 3h.

---

#### BLOCO C — MÉDIOS (tabela condensada; todos confirmados por leitura)

| ID | Arquivo:linha (função) | Problema → Impacto → Sugestão |
|---|---|---|
| C1 | client.py:88,515,530 (retry/request/queued) | Sem dedup/rate-limit; cada chamada = thread+PoW → explosão CPU. Fila única/debounce por endereço. |
| C2 | client.py:406 (`_on_pubkey`) | `for contact: from_address+decrypt` O(N) → DoS CPU. Índice tag→contato. |
| C3 | client.py:455 (`_relay_ack`) | Thread ilimitada por ACK → amplificador. Pool + cache de já-retransmitidos. |
| C4 | client.py:476 (`_on_broadcast`) | Reconstrói subs+reverse por objeto O(S). Cache invalidado em subscribe/unsubscribe. |
| C5 | client.py:397 (`_on_getpubkey`) | Responde PoW a qualquer pedido sem throttle; usa stream do solicitante. Throttle + validar stream. |
| C6 | client.py:318,423,389 (estado) | `identities/pubkeys/_ack_watch` sem lock (lock só em 158,180,621). Proteger com `_lock`. |
| C7 | client.py:109 (`_refresh_streams`) | Sobrescreve `their_streams` com os nossos. Não tocar em `their_*`. |
| C8 | client.py:598 (`_build_ack_packet`) | Ramos 28d/7d mortos (MSG_TTL=4d). Simplificar `24h+jitter`. |
| C9 | client.py:322 vs 341 | `add_contact` rejeita <3, `subscribe` aceita v1/v2. Unificar `==4`. |
| C10 | client.py:163 (`create_channel`) | `return None` vs tupla dos demais → unpack crash. Padronizar `(status,msg)`. |
| C11 | client.py:335 (`remove_contact`) | Emite `contact-added` na remoção. Emitir `contact-removed`. |
| C12 | database.py:87 (`_migrate…`) | 2 UPDATE full-scan todo boot. `PRAGMA user_version` one-shot. |
| C13 | database.py:219 (`add_subscription`) | `ON CONFLICT name=excluded` apaga nome com `''` → `noname` futuro. Só atualizar se não-vazio. |
| C14 | database.py:312 vs app.py:1509 | `mark_conversation_read` estreito nunca chamado; app faz UPDATE cru; broadcasts nunca marcados. Unificar + caso canal. |
| C15 | database.py:21-83,256 (schema) | Sem FK/NOT NULL/CHECK/UNIQUE(obj_hash). Órfãos + duplicata em race. Adicionar constraints + índices `(status,direction)`, `(expires)`. |
| C16 | keys.py:34,48,97,80 | `from_private_keys/from_address/chan/generate` sem validar len/range/stream/None. Validar + timeout em generate. |
| C17 | pow.py:35 (`is_sufficient`) | Defaults 0,0 + clamp TTL sem rejeitar expirado. Exigir dificuldade + rejeitar expirado no relay. |
| C18 | ecies.py:30,45,51 | Sem validar ponto (on-curve/infinito) nem inputs. `contains_point` + try no chamador. |
| C19 | ecc.py:37 (`decode_point`) | Sem validar on-curve/subgrupo. Validar. |
| C20 | base58.py:4,17 | Sem leading-zero; sem limite + `index` O(n). Prefixar `1`, limite ~100, dict lookup. |
| C21 | objects.py:275 | `max(ntpb,1000)` sem teto → dificuldade impossível. Cap máximo. |
| C22 | packets.py:34,122,133 | `encode_host` sem try; `parse_inv/addr` sem cap 50k/1k. Validar + truncar. |
| C23 | packets.py:34/71 | Onion v3 → `0.0.0.0`. Suportar ou documentar. |
| C24 | address.py:15,40 | Duplo-zero não-mínimo (`if`→`elif`); aceita v1/stream0. Endurecer. |
| C25 | const.py:36 + version.py:26 | `USER_AGENT`/`__version__` com IO (git 4×) no import, sem cache. `lru_cache` + lazy. |
| C26 | manager.py:168-179 | Parse antes dos gates baratos (len/tempo/PoW). Reordenar: len→parse→tempo→PoW. |
| C27 | manager.py:126,48,87 | `_prune` depth4 + `connection_count/stop` sem lock + `stats` sem lock. Extrair helper + locks. |
| C28 | manager.py:235-254 | `on_getdata`: query por hash em loop. `WHERE hash IN (...)` em lote. |
| C29 | manager.py:282-294 | `wipe_objects` com lock através de DELETE. Só `clear` sob lock. |
| C30 | manager.py:162 | Evicção por `min(bytes)` (lexicográfica, não idade) + O(N). `OrderedDict`/timestamp. |
| C31 | peers.py:48,75,96 | `load` 1-ruim zera tudo; `save` não-atômico; `add` não atualiza/valida. try-por-item + tmp+rename + validação. |
| C32 | proxy.py:27,45,80 | `kind` None silencioso; `from_dict` sem try; `resolve` ignora timeout + vaza .onion em modo direto. Validar + bloquear DNS p/ .onion/.i2p direto. |
| C33 | peer.py:166-172 | `version` descartada sem min_version. Guardar + rejeitar obsoleto. |
| C34 | app.py:2642,1474,2161,2199 | Proxy restart sem try; UPDATE-read sem try; send sem limite; stream sem clamp. try+limites. |
| C35 | app.py:2100-2136 | `row.get` vs `sqlite3.Row` → copiar vazio. Padronizar `dict(row)`. |
| C36 | app.py:928,1001,1057 | `ui_queue` ilimitada + poll floods PoW; `_handle` sem else; `snapshot`+COUNT a cada 1.5s na UI thread. Coalescer + log unknown + 3–5s. |
| C37 | app.py:811,1608,1892 | Busca sem debounce; COUNT por reload; full-repaint sem virtualização. Debounce + heurístico + virtualizar. |
| C38 | update.py:57,91 | `ahead-only` vira `up-to-date`; `execv` perde argv. Status `ahead` + `+sys.argv[1:]`. |
| C39 | run.py:9-18 | `makedirs` sem 0o700; `BMCHAT_DATA` sem abspath/validação. Endurecer. |
| C40 | README vs código | “Só P2P sem canais” vs “suporta canais”; “formatos exatos” vs tolerâncias; retry “ao reabrir” vs 10min; flash “enviado” vs enfileirado. Unificar textos. |

#### BLOCO D — BAIXOS / higiene (tabela; correção oportunista)

`__import__('queue')`→`import queue`; `_on_object source`→`_source`; `_publish_pubkey force` remover; `import_keys_dat/_create_schema/_parse_msg/process_broadcast/snapshot/choose/_build_widgets*` extrair helpers; `messages_for_conversation limit` clampar; `set_message_status` whitelist; `wif_encode` checar 32B; `chan_keys None` validar; `search_range` validar 64B; `find_nonce` max; `ecies.X_LEN/ecc.ORDER_BYTES/SELF_NONCE/version_packet_command/is_onion/resolve_hostname/public_encryption_point/sha256-wrapper` remover/usar; `os/hashlib/sha512/ripemd160` não-usados remover; `Peer` não-usado remover; `end_of_pubkey` remover; `E402` (imports após código) reordenar; `E501` 20 linhas >79 quebrar; `W292` newline no EOF (24 arquivos); `E731` lambda em test_wire; `F841` alice/bob/end_of_pubkey; `F811` sys redefinido; `E305` blank lines; `varint ''→0` vs raise; `_take_varint` mascaramento; `assemble_addr ''`→`encode_varint(0)`; `peer magic/version` `_` explícito; `short version` fechar; `parse_streams` validar posição; `log payload[:200]`→`.hex()`; `send_initial best(30)` cachear; `proxy AF_INET`→`create_connection`; `backup clipboard` auto-limpar + `chmod 0o600` + `Entry show='•'` p/ WIF; `refresh_log/diagnostics` skip se igual; `_pow_last` limpar; `status/ack` usar payload; `pow_workers` expor com clamp; `get_setting vs get_int` unificar; `peer get_int try` morto remover.

#### [OK] Falsos-positivos (não abrir issue)

- Bandit `B413 pycrypto` em `ecies.py:4-5`, `hashing.py:4` — é `pycryptodome` mantido, não `pycrypto` morto.
- Bandit `B404/B603/B606` (`subprocess git`, `execv`) — usos legítimos; endurecer, não remover.
- Bandit `B608` SQLi em `app.py:1233` — query parametrizada (`?` + tupla), heurística errou.
- Bandit `B104` bind-all em `packets.py:73` — é `0.0.0.0` como bytes de endereço remoto em payload, não `bind()`.
- `peer.py:116 magic` ignorado — validado em `_read_header:135`.
- `peer._handle elif` longo, `app._poll/_handle_event` try+elif — não são nesting real.
- `branch.md:49 checksumfailed` — hoje vivo em `app.py:2226`, doc desatualizado.

---

### FASE 5 — Dependências e compatibilidade

- **Instalado vs exigido:** OK (PySocks 1.7.1, pycryptodome 3.23.0, ecdsa 0.19.2). Sem conflito de versão.
- **Python:** README diz 3.10+ (testado 3.14) — confere (3.14.7 aqui; sem sintaxe >3.10 detectada; `mypy` limpo).
- **SO/HW:** puro-Python + Tk; PoW usa `ProcessPoolExecutor` (fork/spawn por SO) — em Windows/macOS o custo de spawn por mensagem é maior (agravante de B1/B7). Sem `safety` instalado — rodar `pip audit` antes de release.
- **Recomendação:** pinar `requirements.txt` com hashes para release + `pip audit` no CI; avaliar `cryptography` no lugar de `pycryptodome` só se houver motivo (hoje sem motivo — bandit B413 é ruído).

---

### MÉTRICAS

- Arquivos analisados: **33** (29 produto + 1 run + 4 tests + README/branch/docs como referência)
- Linhas totais: **7471** (produto+tests+run); núcleo varrido bandit: 5755
- Funções: ~300+ (143 só em `app.py`); >50 linhas: **13** (lista na Fase 1.4)
- Achados únicos validados: **5 críticos + 16 altos + 40 médios + ~35 baixos** ≈ 96 (sem contar 82 avisos flake8 / 117 bandit-low, majoritariamente higiene)
- Severidade: CRÍTICO 5% · ALTO 17% · MÉDIO 42% · BAIXO 36%
- Categorias: Lógica 38% · Concorrência 14% · Segurança 12% · Consistência 18% · Performance 12% · Estilo 6%
- Complexidade: pontos críticos em `pow.run` (depth 5), `_reannounce` (4), `_prune` (4), `_redraw_chat` (161 linhas), `_build_widgets` (196) — sem `radon` instalado; estimativa por AST acima.
- Testes: suite original 24 passed; regressão broadcast 2 passed; amostral rápido 6 passed. Cobertura formal (`pytest-cov`) não rodada — recomendado.

---

### PLANO DE AÇÃO (ordem sugerida, branches separados por risco)

1. **Hotfix funcional (0.5–1 dia, 1 branch):** A1 (done_cb getpubkey) + B4 (validar v4) + B14 (teto body) + B2 (subject) — todos em `send_message`/broadcast, mesmo teste de regressão.
2. **Estabilidade PoW/processos (1–2 dias, 1 branch):** A2/A4 (budget+shutdown) + B1 (in-flight) + B7 (retry com limite) + B3 (sem downgrade silencioso).
3. **Rede/antiflood (1–2 dias, 1 branch):** B11 (send try) + B12 (teto+checksum) + B13 (PeerStore cap) + C5 (throttle getpubkey) + C26/C30 (ordem gates + evicção correta).
4. **Ciclo de vida (1 dia, 1 branch):** B6 (reannounce loop) + B8 (stop com join) + sessão (lockfile + persistir `_ack_watch`).
5. **GUI chans (1–2 dias, 1 branch):** A3 + B15 latente + C-leituras (unread/preview por canal) + B16-parcial.
6. **Endurecimento (1–2 dias, 1 branch):** A5 (chmod+verify-commit) + B9/B10 (target int + chave 0) + B16 (len checks) + índices/constraints C13–C15.
7. **Higiene (contínuo):** bloco D + `W292/E501/E402` + `black` + `pytest-cov` + `pip audit` no CI.

**Issues críticas a criar:** A1, A2/A4, A3, A5, B6, B7, B11, B12, B13, B14 (10). Demais como checklist de refatoração.

---

### EVIDÊNCIAS / VALIDAÇÃO MANUAL

- Leitura direta de `client.py:553-557` vs `request_pubkey:521` e `_run_pow_and_done:659` (A1).
- Leitura de `pow.py:51-111` (step 1<<54, sem stop no filho, `with` que espera) (A2/A4).
- Leitura de `app.py:1118-1127` + grep `\.broadcast|subscribe|create_channel` em `app.py` = zero chamadores (A3) + `manager.py:162-164 min(bytes)` (evicção) + `peer.py:132-139` (16MB, checksum ignorado).
- `flake8/mypy/bandit/AST/pytest` saídas na Fase 0 (baseline acima). Logs completos não anexados (saídas longas) — reproduzível com os comandos iniciais do prompt.
- INÍCIO: 2026-09-07T (UTC) · FIM: mesmo dia · Log de ações: branches criados, baselines rodados, 4 subagentes paralelos, validação manual, 2 relatórios commitados.

### RISCOS / LIMITES DESTA AUDITORIA

- Sem execução de rede real P2P nem fuzzing de peers maliciosos — extremos simulados por leitura.
- Sem `pylint/safety/pytest-cov/radon` (não instalados) — substituídos por flake8/mypy/bandit/AST; rodar no CI antes de release.
- GUI validada por leitura (Tk não exercitado aqui além dos smokes citados em `branch.md`).
