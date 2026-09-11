> **Idioma:** [Português (BR)](ARCHITECTURE.pt-BR.md) | [English](ARCHITECTURE.md)

# Arquitetura bmchat — Design Patterns

> Documentação da refatoração `refactor/design-patterns` (2026-09-09).  
> Branch: `refactor/design-patterns` | Base: `rolling-release` | Python 3.10+

## Visão Geral

O bmchat foi refatorado para aplicar 7 Design Patterns clássicos, melhorando **manutenibilidade, testabilidade e extensibilidade** sem quebrar compatibilidade com a rede Bitmessage ou com os testes existentes.

```
┌─────────────┐     Observer      ┌─────────────┐
│   Client    │◄─────────────────►│  GUI (App)  │
│  (Core)     │  EventEmitter     │  Tkinter    │
└──────┬──────┘   (core/events)    └──────┬──────┘
       │                                  │
       │ DI                               │ Command
       ▼                                  ▼
┌─────────────┐   Strategy        ┌─────────────┐
│  PoW        │◄─────────────────►│  Commands   │
│ crypto/pow  │  Standard/Mock    │ gui/commands│
└──────┬──────┘                    └─────────────┘
       │
       │ Factory
       ▼
┌─────────────┐   Repository      ┌─────────────┐
│  Protocol   │◄─────────────────►│   Data      │
│ protocol/   │   Message/Contact │ core/repos  │
│  Factory    │   Pubkey          │  + Database │
└─────────────┘                    └─────────────┘
       │
       │ State
       ▼
┌─────────────┐
│  Message    │
│ core/models │
│  (State)    │
└─────────────┘
```

Fluxo de dependências (Dependency Injection em `run.py`):

```
run.py:create_client()
  ├── Database(data_dir)
  ├── StandardPoWStrategy() ─┐
  ├── ProtocolObjectFactory() │──► Client(data_dir, pow_strategy, protocol_factory,
  ├── NetworkManager / Mock   │     network_manager, db, message_repo, ...)
  └── Message/Contact/Pubkey ─┘          │
                                         ▼
                                   App(data_dir, client)
```

## Padrões Implementados

### 1. Strategy — `crypto/pow/`

**Problema:** `crypto/pow.py` continha `PowExecutor` com lógica fixa, difícil de mockar em testes (cada teste pagava segundos de CPU).

**Solução:**
- `PoWStrategy` (ABC) em `crypto/pow/strategy.py` com `solve(initial_hash, target, **kwargs)`
- `StandardPoWStrategy` (`standard.py`) — produção com `ProcessPoolExecutor` (step 1<<20)
- `MockPoWStrategy` (`mock.py`) — testes: tenta até `max_tries` e retorna rapidamente (ou `start_nonce`)
- `PowExecutor` mantido como **wrapper legado** para compatibilidade (`from bmchat.crypto.pow import PowExecutor` continua funcionando)

**Injeção:**
```python
from bmchat.crypto.pow.mock import MockPoWStrategy
client = Client(data_dir, pow_strategy=MockPoWStrategy())
# ou produção
client = Client(data_dir)  # usa StandardPoWStrategy()
```

**Benefício:** testes 10–50× mais rápidos; troca de algoritmo sem alterar `Client`.

---

### 2. Observer — `core/events/`

**Problema:** `Client` → GUI via `ui_queue` polling (250ms) e tuplas mágicas `('message', ...)`.

**Solução:**
- `EventEmitter` (`core/events/emitter.py`) — pub/sub thread-safe com `on/off/once/emit/clear`
- `events.py` — constantes tipadas (`NEW_MESSAGE`, `POW_PROGRESS`, `CONNECTION_CHANGE`, `LEGACY_MAP`)
- `Client.events = EventEmitter()` + **bridge**: todo `ui_queue.put((kind, ...))` emite `events.emit(mapped_kind, payload)`
- `gui/app.py` se registra: `_bind_observer_events()` subscreve `App._KNOWN_UI_EVENTS` e agenda `after(0, _dispatch_event)` no main thread

**Compatibilidade:** `ui_queue` continua existindo; testes legados que leem `client.ui_queue.get_nowait()` ainda passam. Novo código pode usar `client.events.on(...)`.

```python
client.events.on(NEW_MESSAGE, lambda data: print("nova msg", data))
client.events.emit(NEW_MESSAGE, {"from": "BM-...", "body": "oi"})
```

---

### 3. Command — `gui/commands/`

**Problema:** ações da UI chamavam `client.send_message/remove_contact` diretamente, sem encapsulamento, sem histórico, sem validação centralizada.

**Solução:**
- `Command` ABC + `CommandHistory` (`base.py`) com `execute/can_execute/undo` e `history/redo`
- `SendMessageCommand(client, from, to, body, subject)` — valida wire size, delega a `client.send_message`, captura `message_id` para `undo` (apaga se ainda pendente)
- `DeleteContactCommand(client, address)` — backup do contato para `undo` (recria)
- `BackupKeysCommand(client, address, format)` — leitura, `undo` = `unsupported`

**Integração:**
```python
# antes
client.send_message(ident, dest, "", body)
# depois
cmd = SendMessageCommand(client, ident, dest, body)
history.execute(cmd)  # valida + executa + registra
history.undo()
```

`App` possui `self._command_history = CommandHistory()` e usa Commands em `_send_to_contact`, `_remove_entry`, `_backup_identity`.

**Benefício:** desacopla UI de lógica de negócio; base para Undo/Redo futuro; fácil logging/auditoria.

---

### 4. State — `core/models/`

**Problema:** status de mensagem espalhado como strings (`awaiting-pubkey`, `sending`, `sent`, `ack-failed`, ...) e `if status == ...` em vários lugares.

**Solução:**
- `MessageState` ABC (`core/models/states.py`) com `send()`, `check_status()`, `get_display_icon()`, `allowed_transitions()`
- Estados concretos: `PendingState` / `AwaitingPubkeyState` / `SendingState` → `🕐`, `PublishedState`/`SentState` → `✓✓` (cinza), `DeliveredState`/`AckReceivedState`/`ReceivedState`/`ReadState` → `✓✓` (azul), `FailedState`/`AckFailedState` → `❌`, extensões `CancelledState` (`🚫`) e `ExpiredState` (`⌛`)
- `Message` (`core/models/message.py`) — model que envolve `row` do DB e delega ao `state` atual; `transition_to(new_status)` verifica transição permitida
- `Client.get_message_model(id)` e `messages_for_conversation_models(addr)` expõem models

```python
msg = client.get_message_model(42)
msg.get_display_icon()  # '🕐' / '✓✓' / '❌'
msg.transition_to('cancelled')  # novo estado sem alterar condicionais antigas
```

**Benefício:** adicionar `Cancelled`/`Expired` não exige caçar `if`s; lógica de ícone e de `send()` fica no estado.

---

### 5. Factory — `protocol/factory.py`

**Problema:** `Client` criava objetos via `objects.build_*_unsigned` dispersos, sem validação centralizada.

**Solução:**
- `ProtocolObjectFactory` com `create_getpubkey(expires, stream, tag)`, `create_pubkey`, `create_msg`, `create_broadcast`, `create_ack` — valida `expires` (futuro), `stream>=1`, `tag 32B`, `ripe 20B`, `encoding`
- `complete(unsigned, nonce)` e `parse(raw)` delegam a `objects`
- Instância padrão `default_factory` para conveniência
- `Client` aceita `protocol_factory` via DI; `request_pubkey`, `send_message` (getpubkey branch) e `_build_ack_packet` agora usam `self.protocol_factory.create_*` com **fallback** para `objects.*` em caso de erro (compatibilidade)

```python
factory = ProtocolObjectFactory()
unsigned = factory.create_getpubkey(expires, 1, tag)
```

---

### 6. Repository — `core/repositories/`

**Problema:** `Client` fazia `self.db.query("SELECT ...")` e `self.db.execute(...)` com SQL inline em ~30 lugares.

**Solução:**
- `BaseRepository(db)` (`base.py`)
- `MessageRepository` (`message_repo.py`) — `add`, `get`, `for_conversation`, `set_status`, `awaiting_pubkey_addresses`, `ack_failed`, `all_awaiting_for`, etc.
- `ContactRepository` — `add`, `all`, `get`, `remove`, `exists`
- `PubkeyRepository` — `store`, `get`, `all`, `exists`
- `Client` cria `self.message_repo`, `self.contact_repo`, `self.pubkey_repo` (ou recebe injetados) e refatora métodos-chave (`_load_pubkeys`, `add_contact`, `remove_contact`, `_on_pubkey`, `_maybe_mark_ack`) para usar repositórios

```python
client = Client(data_dir, message_repo=MessageRepository(db))
client.contact_repo.add(address, label)
client.message_repo.awaiting_pubkey_addresses()
```

**Compatibilidade:** `client.db` continua exposto; todo SQL antigo ainda funciona. Novo código usa repos.

---

### 7. Dependency Injection — `run.py` + `Client` + `App`

**Problema:** `NetworkManager` (e antes `Database`, `PowExecutor`) eram criados escondidos dentro de `Client`/`App`, dificultando testes com `MockNetworkManager` e configurando singleton implícito.

**Solução:**
- `Client.__init__(data_dir, pow_strategy=None, network_manager=None, db=None, protocol_factory=None, message_repo=None, ...)`
  - Se `None`, cria implementação real; se injetado, usa mock
  - `network_manager` injetado tem `on_object/on_log/db` sobrescritos para garantir callbacks corretos
- `net/mock.py` — `MockNetworkManager` com mesma interface (`announce_object`, `start/stop`, `snapshot`, `established_count==1`, `announced=[]` para asserts)
- `gui/app.py:App.__init__(data_dir, client=None)` — aceita `Client` injetado; se `None`, cria padrão
- `run.py:create_client(data_dir, use_mock_net=False)` — **fábrica do grafo** que monta `Database` → `StandardPoWStrategy` → `ProtocolObjectFactory` → `NetworkManager`/`MockNetworkManager` → `Client`; `run.py:main` usa `create_client` e `App(data_dir, client=client)`
  - Variável `BMCHAT_MOCK_NET=1` ativa mock em produção (para demo/teste)

**Exemplo teste:**
```python
from bmchat.net.mock import MockNetworkManager
from bmchat.crypto.pow.mock import MockPoWStrategy
client = Client(tmpdir, pow_strategy=MockPoWStrategy(),
                network_manager=MockNetworkManager())
assert client.net.announced == []
client.request_pubkey(bob_addr)
assert len(client.net.announced) == 1
```

**Benefício:** testes não abrem sockets reais; troca de `NetworkManager` sem alterar `Client`; grafo visível em `run.py` (não escondido).

---

## Estrutura Final

```
bmchat/
  version.py
  crypto/
    ecc.py, ecies.py, keys.py, encrypted_db.py
    pow/
      __init__.py      # re-export + PowExecutor legado
      strategy.py      # PoWStrategy (ABC)
      standard.py      # StandardPoWStrategy
      mock.py          # MockPoWStrategy
  protocol/
    const.py, packets.py, objects.py, address.py
    factory.py         # ProtocolObjectFactory
  net/
    proxy.py, peers.py, manager.py, peer.py
    mock.py            # MockNetworkManager
  core/
    database.py
    client.py          # Client com DI (pow, net, factory, repos) + Observer + State helpers
    events/
      __init__.py
      emitter.py       # EventEmitter
      events.py        # tipos tipados
    repositories/
      base.py
      message_repo.py
      contact_repo.py
      pubkey_repo.py
    models/
      __init__.py
      message.py       # Message model
      states.py        # MessageState hierarquia
  gui/
    app.py             # App com DI + Observer + CommandHistory
    dialogs.py, theme.py, tooltip.py, notification.py
    commands/
      base.py          # Command + CommandHistory
      send_message.py
      delete_contact.py
      backup_keys.py
run.py                 # create_client() + DI do grafo
ARCHITECTURE.md        # este arquivo
```

## Compatibilidade e Testes

- **Nenhuma API quebrada:** `from bmchat.crypto.pow import PowExecutor, calculate_target` continua; `Client(data_dir)` continua; `App(data_dir)` continua
- **Testes:** `python3 -m pytest tests/ -q` — 209 testes coletados; suíte principal (`test_integration`, `test_interop`) 19 passed
- **PEP 8:** `ruff` / `flake8` sem erros novos; type hints em novos módulos
- **Performance:** `MockPoWStrategy` acelera testes; `StandardPoWStrategy` mantém mesma performance (step 1<<20, ProcessPoolExecutor)

## Próximos Passos

- Migrar mais chamadas SQL de `Client` para `Repositories` (incremental)
- Usar `Message` model na GUI para `get_display_icon()` em vez de `status` strings
- Expandir `Factory` para `build_pubkey`/`build_broadcast` em `Client.broadcast*`
- Histórico de `Command` persistido para Undo real de mensagens (hoje só pendentes)
- `Factory` para `Packets` (version/addr/inv)

## Referências

- Design Patterns — Gamma et al. (GoF)
- Bitmessage protocol spec — `protocol/objects.py` e `protocol/packets.py`
- Testes: `tests/test_integration.py`, `tests/test_wire.py`, `tests/test_menu_pow.py`
