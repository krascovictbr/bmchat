# BMCHAT — Relatório Completo de Auditoria (ANALYSIS_REPORT.md)

- **Branch de análise:** `analysis/complete-audit-20260907` (criada a partir de `audit/anti-hallucination-20260907@d199a10`)
- **Base auditada:** `d199a10` (inclui fix H1/H2 de broadcast) · anterior `rolling-release@22964ff`
- **Data/hora (UTC):** 2026-09-07 · Python 3.14.7 · Linux
- **Escopo:** 33 arquivos `.py` (29 em `bmchat/` + `run.py` + 4 em `tests/`), **7471 linhas** totais
- **Ferramentas executadas:** `flake8` (82 avisos, 0 bloqueantes), `mypy --ignore-missing-imports` (0 issues em 29 arquivos), `bandit` (Low 112 / Medium 2 / High 3), `py_compile` OK, `pytest` amostral (6 passed), AST próprio (funções >50 linhas, imports circulares, SQLi)
- **Metodologia:** Fases 1–5 do prompt (estrutural, estática por arquivo, comportamental, consistência, dependências/segurança). 4 subagentes paralelos + validação manual dos CRÍTICOS por leitura direta do código. Nenhum arquivo de produto foi alterado nesta branch — só estes relatórios.

> Convenção: cada achado segue `[TIPO] - SEVERIDADE`, arquivo:linha, função, descrição, código, impacto, solução, prioridade, estimativa. CRÍTICO/ALTO estão detalhados; MÉDIO/BAIXO estão em tabelas condensadas (mesmo conteúdo, sem repetição). Falsos-positivos do ferramental estão marcados como `[OK]` para não virarem issues.

---

## FASE 1 — Mapeamento estrutural

### 1.1 Árvore e módulos

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

### 1.2 Arquitetura (fluxo real)

```
GUI (app.py poll 250ms ← ui_queue) ←→ Client ←→ NetworkManager ←→ PeerConnection ×N
  ↑↓ DB (sqlite, 1 conn+Lock)      ↑ PoW (ProcessPool × msg)   ↑ PySocks/Tor/I2P
Crypto (keys/ecc/ecies/pow) ←→ Protocol (address/objects/packets) ←→ Tests
```

### 1.3 Dependências

`requirements.txt`: `PySocks>=1.7.1`, `pycryptodome>=3.15.0`, `ecdsa>=0.18.0` — todas usadas e presentes (1.7.1 / 3.23.0 / 0.19.2). `tkinter` é stdlib (corretamente fora do requirements). Restante só stdlib (`sqlite3`, `threading`, `subprocess`, `socket`, `hashlib`, `hmac`, `concurrent.futures`, etc.). Sem dependência obsoleta funcional (bandit reclama de `pycrypto` por heurística — na verdade é `pycryptodome`, mantido).

### 1.4 Funções >50 linhas (AST, confirmado)

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

## FASE 2+3+4+5 — Achados (deduplicados e validados por leitura)

### BLOCO A — CRÍTICOS (corrigir primeiro; 5 itens)

#### [LÓGICA] - CRÍTICO — A1. Primeiro envio DM nunca anuncia o getpubkey
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

#### [CONCORRÊNCIA] - CRÍTICO — A2. Cancelamento de PoW não funciona (filhos queimam CPU até o fim)
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

#### [LÓGICA] - CRÍTICO — A3. Chans invisíveis na GUI (backend funciona, UI inalcançável)
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

#### [LÓGICA] - CRÍTICO — A4. `PowExecutor.run` pode travar no `__exit__` após sucesso (já listado como ALTA na fase 2, elevado aqui por hang)
- Arquivo: `bmchat/crypto/pow.py:99-104` · Função: `run`
- Descrição: ao achar nonce, dá `cancel()` nos pendentes mas `cancel()` não interrompe tarefa em execução; `return nonce` dentro do `with` aguarda os workers terminarem o range gigante.
- Código: ver A2 (mesmo bloco).
- Impacto: mesmo com PoW rápido, thread trava até filhos esgotarem `1<<54` (na prática hang). Mesma correção de A2.
- Prioridade: Alta · Estimativa: incluída em A2.

#### [SEGURANÇA] - CRÍTICO (contextual) — A5. Chaves privadas em claro + diretório sem permissão
- Arquivo: `bmchat/core/database.py:10,18-45`, `run.py:9`, `bmchat/update.py:71` · Função: `Database.__init__`, `data_dir_default`, `perform_update`
- Descrição: `priv_signing/priv_encryption BLOB` sem cifragem; `makedirs(~/.bmchat, exist_ok=True)` sem `mode=0o700`; backup escreve WIF sem `chmod 0o600`; update faz `fetch+merge --ff-only` sem `verify-commit` e dá `execv` (RCE pós-comprometimento do remoto).
- Código problemático:
```python
os.makedirs(path, exist_ok=True)  # run.py:11 — sem 0o700
# database schema: priv_signing BLOB, priv_encryption BLOB (claro)
os.execv(sys.executable, [sys.executable, run_path])  # update.py:96
```
- Impacto: roubo de identidade por leitura de disco/backup; supply-chain se o remoto for comprometido. README já avisa "banco não cifrado" — o gap é permissão + update sem verificação.
- Solução sugerida (sem re-arquitetura): `makedirs(..., mode=0o700)` + `chmod 0o700/0o600` em DB/backup existentes; `git verify-commit` ou pin de chave no update (ou ao menos documentar risco + exigir confirmação); documentar "sem forward secrecy / sem anonimato garantido" (já existe — manter).
- Prioridade: Alta (permissão: imediata, 1h) / Média (verify-commit: 1 dia) · Estimativa total: 1–2 dias.
- Nota bandit: `B413 pycrypto` é falso-positivo de nome (é `pycryptodome` mantido); `B404/B603/B606 subprocess` são usos legítimos (`git`, `execv`) — manter, só endurecer args.

> H1/H2 da auditoria anterior (`incoming.stream`, chan-owner sem sub) já estão corrigidos em `d199a10` e cobertos por `tests/test_anti_hallucination.py` — não repetidos aqui como abertos.

---

### BLOCO B — ALTOS (detalhados; 16 itens)

#### [LÓGICA] - ALTO — B1. Reenvio duplica PoW/announce (sem estado `sending` nem in-flight)
- Arquivo: `bmchat/core/client.py:88-97,549-551,560-600` · Funções: `_retry_awaiting`, `send_message`, `_pow_and_publish_message`
- Código: insere `awaiting-pubkey`, se `in pubkeys` dispara PoW mas status só vira `sent` no `done:588`; retry vê `in pubkeys` e re-dispara para o mesmo `message_id`.
- Impacto: 2× CPU + objeto duplicado na rede.
- Solução: status `sending` + `set[(message_id)]` in-flight com guarda; retry pula in-flight. Prioridade Alta · 4h.

#### [LÓGICA] - ALTO — B2. `subject` persistido mas nunca trafega
- Arquivo: `bmchat/core/client.py:539-547,578-580` + `protocol/objects.py:93` · Função: `send_message`
- Código: `add_message(..., subject ...)` mas `build_msg_unsigned(..., body, encoding, ack)` sem subject.
- Impacto: perda silenciosa / interop confusa. Solução: remover param ou prefixar no body / rejeitar `subject!=''`. Prioridade Média · 2h.

#### [LÓGICA] - ALTO — B3. Envio sem ACK silencioso quando `_quick_pow` falha
- Arquivo: `bmchat/core/client.py:573-580,608-617` · Função: `_pow_and_publish_message`, `_build_ack_packet`
- Código: `ack_packet, watch = _build_ack_packet(stream)`; se falha retorna `(b'', None)` e o envio segue sem ACK/sem watch.
- Impacto: remetente fica em `sent` para sempre. Solução: abortar com erro visível ou retry do ACK. Prioridade Alta · 3h.

#### [LÓGICA] - ALTO — B4. `send_message` quebra para v2/v3 (raise não tratado)
- Arquivo: `bmchat/core/client.py:541-544` · Função: `send_message`
- Código: `decode` aceita v2/v3 mas `AddressKeys.from_address` só v4 (`raise`).
- Impacto: crash na GUI ao enviar para contato v3 (permitido em `add_contact:327`). Solução: validar `version==4` + `try`. Prioridade Alta · 1h.

#### [LÓGICA] - ALTO — B5. Relay aceita/propaga PoW mínimo mesmo quando deveria exigir mais
- Arquivo: `bmchat/net/manager.py:178` + `crypto/pow.py:35-44` · Função: `received_object`
- Código: `is_proof_of_work_sufficient(raw)` com defaults `0,0` → 1000/1000.
- Impacto: spam propagado; risco de punição por pares. Solução: documentar relay permissivo + rate-limit, ou extrair dificuldade real. Prioridade Média · 4h.

#### [LÓGICA] - ALTO — B6. `_reannounce_pubkeys` roda uma vez e morre (sem loop)
- Arquivo: `bmchat/core/client.py:55-57,778-805` · Função: `_reannounce_pubkeys`
- Código: thread `client-reannounce` sem `while/sleep`; `LIMIT 200` global pode não cobrir todas as identidades (loop O(I×R) ainda por cima).
- Impacto: após `PUBKEY_TTL` identidade some da rede. Solução: loop 24h + query por identidade + índice tag. Prioridade Alta · 4h.

#### [LÓGICA] - ALTO — B7. Retry sem limite pode forkar o sistema
- Arquivo: `bmchat/core/client.py:66-97` · Função: `_retry_loop`, `_retry_awaiting`
- Código: 10 min fixos sem jitter; um PoW (`ProcessPool × cpu`) por endereço pendente, mesmo offline.
- Impacto: 1000 pendentes → fork-bomb/OOM. Solução: pular se `established==0`, concorrência limitada + backoff. Prioridade Alta · 1 dia.

#### [LÓGICA] - ALTO — B8. `stop()` fecha DB sem join (race com threads)
- Arquivo: `bmchat/core/client.py:59-64` + `database.py:105` · Função: `stop`
- Código: `db.close()` imediato; retry/maintenance/peers/PoW podem estar em query; `_on_object` ainda enfileira sem consumidor.
- Impacto: `ProgrammingError: closed database`. Solução: sinalizar, join com timeout, só então fechar; `query/execute` checar `closed`. Prioridade Alta · 4h.

#### [LÓGICA] - ALTO — B9. `calculate_target` retorna float (erro além de 2^53)
- Arquivo: `bmchat/crypto/pow.py:13-25` · Função: `calculate_target`
- Código: `return (2**64) / denominator` (float; ex. `1470226177730.2756`).
- Impacto: borda incorreta em dificuldades altas. Solução: `(2**64)//denominator` int. Prioridade Alta · 1h + teste vetorial.

#### [LÓGICA] - ALTO — B10. ECDH aceita chave 0 → INFINITY
- Arquivo: `bmchat/crypto/ecc.py:27-50` · Funções: `point_mult`, `point_from_secret`, `ecdh_point`
- Código: `value = int.from_bytes(secret) % ORDER` sem rejeitar 0.
- Impacto: crash posterior / ECDH fraco. Solução: `if not 1<=v<ORDER: raise`. Prioridade Alta · 2h.

#### [LÓGICA] - ALTO — B11. `send_packet` sem guarda derruba announce e conexão
- Arquivo: `bmchat/net/peer.py:47-58` + `manager.py:203-214` · Função: `send_packet`, `announce_object`
- Código: `sock.sendall` sem checar `None/closing` e sem `try` por peer; 1 falha aborta o laço e sobe até matar a thread de leitura.
- Impacto: perda de propagação + queda por falha isolada. Solução: guarda + `try/except` por conexão. Prioridade Alta · 3h.

#### [LÓGICA] - ALTO — B12. Teto de header 16MB + sem checksum (amplificação)
- Arquivo: `bmchat/net/peer.py:60-68,132-139` · Funções: `_recv_exact`, `_read_header`
- Código: `length>16MB` (8× o `MAX_OBJECT_LENGTH+64`); checksum desembrulhado e ignorado.
- Impacto: 16MB×8 conns = 128MB acionável; payload corrompido processado. Solução: teto `MAX_OBJECT_LENGTH+HEADER`, verificar `sha512[:4]`, `bytearray/recv_into`. Prioridade Alta · 4h.

#### [SEGURANÇA] - ALTO — B13. PeerStore sem cap + `best()` ordena tudo (envenenamento)
- Arquivo: `bmchat/net/peers.py:96-105,130-147` + `peer.py:241-253` · Funções: `add`, `best`
- Código: `add` sem limite/evicção/validação; `_on_addr` aceita 200/msg.
- Impacto: flood de `addr` → RAM+CPU. Solução: cap 2–5k + evicção por rating/seen + validar host/port + só promover após sucesso. Prioridade Alta · 1 dia.

#### [LÓGICA] - ALTO — B14. Sem teto de `body` antes do PoW (falso `sent`)
- Arquivo: `bmchat/core/client.py:580,679,737` · Funções: `_pow_and_publish_message`, `broadcast`, `broadcast_chan`
- Código: nenhum `len(body.encode)+overhead < MAX_OBJECT_LENGTH` antes de `calculate_target+PoW`.
- Impacto: queima PoW para objeto descartado, mas marca `sent`. Solução: validar e rejeitar com erro UI. Prioridade Alta · 2h.

#### [CONSISTÊNCIA] - ALTO — B15. `assemble_addr` ignora `services` (contrato mente)
- Arquivo: `bmchat/protocol/packets.py:95-104` · Função: `assemble_addr`
- Código: `struct.pack('>q', 1)` hardcoded; chamador `peer.py:233` passa `services` real.
- Impacto: anuncia capacidade errada (baixo hoje pois services sempre 1, mas latente). Solução: empacotar `services`. Prioridade Média · 1h.

#### [LÓGICA] - ALTO — B16. `process_broadcast`/`_parse_msg` sem cheques de comprimento + `ack_watch` sem expiração
- Arquivo: `bmchat/protocol/objects.py:171-200,287-325` + `client.py:384-395` · Funções: `_parse_msg_plaintext`, `process_broadcast`, `_maybe_mark_ack`
- Código: `b'\x04'+plain[pos:pos+64]` sem checar restante; `_take_varint` mascara truncamento (`return 0`); `_ack_watch` só `get/set`.
- Impacto: robustez + leak + replay spam. Solução: `len` checks, `pop`+TTL no watch. Prioridade Média · 3h.

---

### BLOCO C — MÉDIOS (tabela condensada; todos confirmados por leitura)

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

### BLOCO D — BAIXOS / higiene (tabela; correção oportunista)

`__import__('queue')`→`import queue`; `_on_object source`→`_source`; `_publish_pubkey force` remover; `import_keys_dat/_create_schema/_parse_msg/process_broadcast/snapshot/choose/_build_widgets*` extrair helpers; `messages_for_conversation limit` clampar; `set_message_status` whitelist; `wif_encode` checar 32B; `chan_keys None` validar; `search_range` validar 64B; `find_nonce` max; `ecies.X_LEN/ecc.ORDER_BYTES/SELF_NONCE/version_packet_command/is_onion/resolve_hostname/public_encryption_point/sha256-wrapper` remover/usar; `os/hashlib/sha512/ripemd160` não-usados remover; `Peer` não-usado remover; `end_of_pubkey` remover; `E402` (imports após código) reordenar; `E501` 20 linhas >79 quebrar; `W292` newline no EOF (24 arquivos); `E731` lambda em test_wire; `F841` alice/bob/end_of_pubkey; `F811` sys redefinido; `E305` blank lines; `varint ''→0` vs raise; `_take_varint` mascaramento; `assemble_addr ''`→`encode_varint(0)`; `peer magic/version` `_` explícito; `short version` fechar; `parse_streams` validar posição; `log payload[:200]`→`.hex()`; `send_initial best(30)` cachear; `proxy AF_INET`→`create_connection`; `backup clipboard` auto-limpar + `chmod 0o600` + `Entry show='•'` p/ WIF; `refresh_log/diagnostics` skip se igual; `_pow_last` limpar; `status/ack` usar payload; `pow_workers` expor com clamp; `get_setting vs get_int` unificar; `peer get_int try` morto remover.

### [OK] Falsos-positivos (não abrir issue)

- Bandit `B413 pycrypto` em `ecies.py:4-5`, `hashing.py:4` — é `pycryptodome` mantido, não `pycrypto` morto.
- Bandit `B404/B603/B606` (`subprocess git`, `execv`) — usos legítimos; endurecer, não remover.
- Bandit `B608` SQLi em `app.py:1233` — query parametrizada (`?` + tupla), heurística errou.
- Bandit `B104` bind-all em `packets.py:73` — é `0.0.0.0` como bytes de endereço remoto em payload, não `bind()`.
- `peer.py:116 magic` ignorado — validado em `_read_header:135`.
- `peer._handle elif` longo, `app._poll/_handle_event` try+elif — não são nesting real.
- `branch.md:49 checksumfailed` — hoje vivo em `app.py:2226`, doc desatualizado.

---

## FASE 5 — Dependências e compatibilidade

- **Instalado vs exigido:** OK (PySocks 1.7.1, pycryptodome 3.23.0, ecdsa 0.19.2). Sem conflito de versão.
- **Python:** README diz 3.10+ (testado 3.14) — confere (3.14.7 aqui; sem sintaxe >3.10 detectada; `mypy` limpo).
- **SO/HW:** puro-Python + Tk; PoW usa `ProcessPoolExecutor` (fork/spawn por SO) — em Windows/macOS o custo de spawn por mensagem é maior (agravante de B1/B7). Sem `safety` instalado — rodar `pip audit` antes de release.
- **Recomendação:** pinar `requirements.txt` com hashes para release + `pip audit` no CI; avaliar `cryptography` no lugar de `pycryptodome` só se houver motivo (hoje sem motivo — bandit B413 é ruído).

---

## MÉTRICAS

- Arquivos analisados: **33** (29 produto + 1 run + 4 tests + README/branch/docs como referência)
- Linhas totais: **7471** (produto+tests+run); núcleo varrido bandit: 5755
- Funções: ~300+ (143 só em `app.py`); >50 linhas: **13** (lista na Fase 1.4)
- Achados únicos validados: **5 críticos + 16 altos + 40 médios + ~35 baixos** ≈ 96 (sem contar 82 avisos flake8 / 117 bandit-low, majoritariamente higiene)
- Severidade: CRÍTICO 5% · ALTO 17% · MÉDIO 42% · BAIXO 36%
- Categorias: Lógica 38% · Concorrência 14% · Segurança 12% · Consistência 18% · Performance 12% · Estilo 6%
- Complexidade: pontos críticos em `pow.run` (depth 5), `_reannounce` (4), `_prune` (4), `_redraw_chat` (161 linhas), `_build_widgets` (196) — sem `radon` instalado; estimativa por AST acima.
- Testes: suite original 24 passed; regressão broadcast 2 passed; amostral rápido 6 passed. Cobertura formal (`pytest-cov`) não rodada — recomendado.

---

## PLANO DE AÇÃO (ordem sugerida, branches separados por risco)

1. **Hotfix funcional (0.5–1 dia, 1 branch):** A1 (done_cb getpubkey) + B4 (validar v4) + B14 (teto body) + B2 (subject) — todos em `send_message`/broadcast, mesmo teste de regressão.
2. **Estabilidade PoW/processos (1–2 dias, 1 branch):** A2/A4 (budget+shutdown) + B1 (in-flight) + B7 (retry com limite) + B3 (sem downgrade silencioso).
3. **Rede/antiflood (1–2 dias, 1 branch):** B11 (send try) + B12 (teto+checksum) + B13 (PeerStore cap) + C5 (throttle getpubkey) + C26/C30 (ordem gates + evicção correta).
4. **Ciclo de vida (1 dia, 1 branch):** B6 (reannounce loop) + B8 (stop com join) + sessão (lockfile + persistir `_ack_watch`).
5. **GUI chans (1–2 dias, 1 branch):** A3 + B15 latente + C-leituras (unread/preview por canal) + B16-parcial.
6. **Endurecimento (1–2 dias, 1 branch):** A5 (chmod+verify-commit) + B9/B10 (target int + chave 0) + B16 (len checks) + índices/constraints C13–C15.
7. **Higiene (contínuo):** bloco D + `W292/E501/E402` + `black` + `pytest-cov` + `pip audit` no CI.

**Issues críticas a criar:** A1, A2/A4, A3, A5, B6, B7, B11, B12, B13, B14 (10). Demais como checklist de refatoração.

---

## EVIDÊNCIAS / VALIDAÇÃO MANUAL

- Leitura direta de `client.py:553-557` vs `request_pubkey:521` e `_run_pow_and_done:659` (A1).
- Leitura de `pow.py:51-111` (step 1<<54, sem stop no filho, `with` que espera) (A2/A4).
- Leitura de `app.py:1118-1127` + grep `\.broadcast|subscribe|create_channel` em `app.py` = zero chamadores (A3) + `manager.py:162-164 min(bytes)` (evicção) + `peer.py:132-139` (16MB, checksum ignorado).
- `flake8/mypy/bandit/AST/pytest` saídas na Fase 0 (baseline acima). Logs completos não anexados (saídas longas) — reproduzível com os comandos iniciais do prompt.
- INÍCIO: 2026-09-07T (UTC) · FIM: mesmo dia · Log de ações: branches criados, baselines rodados, 4 subagentes paralelos, validação manual, 2 relatórios commitados.

## RISCOS / LIMITES DESTA AUDITORIA

- Sem execução de rede real P2P nem fuzzing de peers maliciosos — extremos simulados por leitura.
- Sem `pylint/safety/pytest-cov/radon` (não instalados) — substituídos por flake8/mypy/bandit/AST; rodar no CI antes de release.
- GUI validada por leitura (Tk não exercitado aqui além dos smokes citados em `branch.md`).
