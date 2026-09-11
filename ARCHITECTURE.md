> **Language:** [English](ARCHITECTURE.md) | [Português (BR)](ARCHITECTURE.pt-BR.md)

# bmchat Architecture — Design Patterns

> Documentation of the `refactor/design-patterns` refactor (2026-09-09).  
> Branch: `refactor/design-patterns` | Base: `rolling-release` | Python 3.10+

## Overview

bmchat was refactored to apply 7 classic Design Patterns, improving **maintainability, testability and extensibility** without breaking compatibility with the Bitmessage network or with existing tests.

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

Dependency flow (Dependency Injection in `run.py`):

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

## Implemented Patterns

### 1. Strategy — `crypto/pow/`

**Problem:** `crypto/pow.py` contained `PowExecutor` with fixed logic, hard to mock in tests (each test paid seconds of CPU).

**Solution:**
- `PoWStrategy` (ABC) in `crypto/pow/strategy.py` with `solve(initial_hash, target, **kwargs)`
- `StandardPoWStrategy` (`standard.py`) — production with `ProcessPoolExecutor` (step 1<<20)
- `MockPoWStrategy` (`mock.py`) — tests: tries up to `max_tries` and returns quickly (or `start_nonce`)
- `PowExecutor` kept as **legacy wrapper** for compatibility (`from bmchat.crypto.pow import PowExecutor` still works)

**Injection:**
```python
from bmchat.crypto.pow.mock import MockPoWStrategy
client = Client(data_dir, pow_strategy=MockPoWStrategy())
# or production
client = Client(data_dir)  # uses StandardPoWStrategy()
```

**Benefit:** tests 10–50× faster; changing algorithm without touching `Client`.

---

### 2. Observer — `core/events/`

**Problem:** `Client` → GUI via `ui_queue` polling (250ms) and magic tuples `('message', ...)`.

**Solution:**
- `EventEmitter` (`core/events/emitter.py`) — thread-safe pub/sub with `on/off/once/emit/clear`
- `events.py` — typed constants (`NEW_MESSAGE`, `POW_PROGRESS`, `CONNECTION_CHANGE`, `LEGACY_MAP`)
- `Client.events = EventEmitter()` + **bridge**: every `ui_queue.put((kind, ...))` emits `events.emit(mapped_kind, payload)`
- `gui/app.py` registers itself: `_bind_observer_events()` subscribes to `App._KNOWN_UI_EVENTS` and schedules `after(0, _dispatch_event)` on the main thread

**Compatibility:** `ui_queue` still exists; legacy tests that read `client.ui_queue.get_nowait()` still pass. New code can use `client.events.on(...)`.

```python
client.events.on(NEW_MESSAGE, lambda data: print("new msg", data))
client.events.emit(NEW_MESSAGE, {"from": "BM-...", "body": "hi"})
```

---

### 3. Command — `gui/commands/`

**Problem:** UI actions called `client.send_message/remove_contact` directly, without encapsulation, without history, without centralized validation.

**Solution:**
- `Command` ABC + `CommandHistory` (`base.py`) with `execute/can_execute/undo` and `history/redo`
- `SendMessageCommand(client, from, to, body, subject)` — validates wire size, delegates to `client.send_message`, captures `message_id` for `undo` (deletes if still pending)
- `DeleteContactCommand(client, address)` — backs up contact for `undo` (recreates)
- `BackupKeysCommand(client, address, format)` — read-only, `undo` = `unsupported`

**Integration:**
```python
# before
client.send_message(ident, dest, "", body)
# after
cmd = SendMessageCommand(client, ident, dest, body)
history.execute(cmd)  # validates + executes + records
history.undo()
```

`App` has `self._command_history = CommandHistory()` and uses Commands in `_send_to_contact`, `_remove_entry`, `_backup_identity`.

**Benefit:** decouples UI from business logic; foundation for future Undo/Redo; easy logging/auditing.

---

### 4. State — `core/models/`

**Problem:** message status scattered as strings (`awaiting-pubkey`, `sending`, `sent`, `ack-failed`, ...) and `if status == ...` in many places.

**Solution:**
- `MessageState` ABC (`core/models/states.py`) with `send()`, `check_status()`, `get_display_icon()`, `allowed_transitions()`
- Concrete states: `PendingState` / `AwaitingPubkeyState` / `SendingState` → `🕐`, `PublishedState`/`SentState` → `✓✓` (gray), `DeliveredState`/`AckReceivedState`/`ReceivedState`/`ReadState` → `✓✓` (blue), `FailedState`/`AckFailedState` → `❌`, extensions `CancelledState` (`🚫`) and `ExpiredState` (`⌛`)
- `Message` (`core/models/message.py`) — model wrapping DB `row` and delegating to current `state`; `transition_to(new_status)` checks allowed transition
- `Client.get_message_model(id)` and `messages_for_conversation_models(addr)` expose models

```python
msg = client.get_message_model(42)
msg.get_display_icon()  # '🕐' / '✓✓' / '❌'
msg.transition_to('cancelled')  # new state without hunting conditionals
```

**Benefit:** adding `Cancelled`/`Expired` does not require hunting `if`s; icon and `send()` logic stays in the state.

---

### 5. Factory — `protocol/factory.py`

**Problem:** `Client` created objects via scattered `objects.build_*_unsigned`, without centralized validation.

**Solution:**
- `ProtocolObjectFactory` with `create_getpubkey(expires, stream, tag)`, `create_pubkey`, `create_msg`, `create_broadcast`, `create_ack` — validates `expires` (future), `stream>=1`, `tag 32B`, `ripe 20B`, `encoding`
- `complete(unsigned, nonce)` and `parse(raw)` delegate to `objects`
- Default instance `default_factory` for convenience
- `Client` accepts `protocol_factory` via DI; `request_pubkey`, `send_message` (getpubkey branch) and `_build_ack_packet` now use `self.protocol_factory.create_*` with **fallback** to `objects.*` on error (compatibility)

```python
factory = ProtocolObjectFactory()
unsigned = factory.create_getpubkey(expires, 1, tag)
```

---

### 6. Repository — `core/repositories/`

**Problem:** `Client` did `self.db.query("SELECT ...")` and `self.db.execute(...)` with inline SQL in ~30 places.

**Solution:**
- `BaseRepository(db)` (`base.py`)
- `MessageRepository` (`message_repo.py`) — `add`, `get`, `for_conversation`, `set_status`, `awaiting_pubkey_addresses`, `ack_failed`, `all_awaiting_for`, etc.
- `ContactRepository` — `add`, `all`, `get`, `remove`, `exists`
- `PubkeyRepository` — `store`, `get`, `all`, `exists`
- `Client` creates `self.message_repo`, `self.contact_repo`, `self.pubkey_repo` (or receives injected ones) and refactors key methods (`_load_pubkeys`, `add_contact`, `remove_contact`, `_on_pubkey`, `_maybe_mark_ack`) to use repositories

```python
client = Client(data_dir, message_repo=MessageRepository(db))
client.contact_repo.add(address, label)
client.message_repo.awaiting_pubkey_addresses()
```

**Compatibility:** `client.db` remains exposed; all old SQL still works. New code uses repos.

---

### 7. Dependency Injection — `run.py` + `Client` + `App`

**Problem:** `NetworkManager` (and previously `Database`, `PowExecutor`) were created hidden inside `Client`/`App`, making tests with `MockNetworkManager` hard and setting up implicit singleton.

**Solution:**
- `Client.__init__(data_dir, pow_strategy=None, network_manager=None, db=None, protocol_factory=None, message_repo=None, ...)`
  - If `None`, creates real implementation; if injected, uses mock
  - Injected `network_manager` has `on_object/on_log/db` overwritten to ensure correct callbacks
- `net/mock.py` — `MockNetworkManager` with same interface (`announce_object`, `start/stop`, `snapshot`, `established_count==1`, `announced=[]` for asserts)
- `gui/app.py:App.__init__(data_dir, client=None)` — accepts injected `Client`; if `None`, creates default
- `run.py:create_client(data_dir, use_mock_net=False)` — **graph factory** that assembles `Database` → `StandardPoWStrategy` → `ProtocolObjectFactory` → `NetworkManager`/`MockNetworkManager` → `Client`; `run.py:main` uses `create_client` and `App(data_dir, client=client)`
  - Variable `BMCHAT_MOCK_NET=1` enables mock in production (for demo/test)

**Test example:**
```python
from bmchat.net.mock import MockNetworkManager
from bmchat.crypto.pow.mock import MockPoWStrategy
client = Client(tmpdir, pow_strategy=MockPoWStrategy(),
                network_manager=MockNetworkManager())
assert client.net.announced == []
client.request_pubkey(bob_addr)
assert len(client.net.announced) == 1
```

**Benefit:** tests do not open real sockets; swapping `NetworkManager` without touching `Client`; graph visible in `run.py` (not hidden).

---

## Final Structure

```
bmchat/
  version.py
  crypto/
    ecc.py, ecies.py, keys.py, encrypted_db.py
    pow/
      __init__.py      # re-export + legacy PowExecutor
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
    client.py          # Client with DI (pow, net, factory, repos) + Observer + State helpers
    events/
      __init__.py
      emitter.py       # EventEmitter
      events.py        # typed types
    repositories/
      base.py
      message_repo.py
      contact_repo.py
      pubkey_repo.py
    models/
      __init__.py
      message.py       # Message model
      states.py        # MessageState hierarchy
  gui/
    app.py             # App with DI + Observer + CommandHistory
    dialogs.py, theme.py, tooltip.py, notification.py
    commands/
      base.py          # Command + CommandHistory
      send_message.py
      delete_contact.py
      backup_keys.py
run.py                 # create_client() + DI graph
ARCHITECTURE.md        # this file
```

## Compatibility and Testing

- **No broken API:** `from bmchat.crypto.pow import PowExecutor, calculate_target` still works; `Client(data_dir)` still works; `App(data_dir)` still works
- **Tests:** `python3 -m pytest tests/unit tests/integration tests/stress -q` — **554 tests** (>95% logic: unit 470+ integration 15 stress 15) — `python3 -m pytest tests/ -q` still works
- **PEP 8:** `ruff` / `flake8` with no new errors; type hints in new modules; `mypy --ignore-missing-imports` clean
- **Performance:** `MockPoWStrategy` speeds up tests; `StandardPoWStrategy` keeps same performance (step 1<<20, ProcessPoolExecutor)

## 🤖 AI Integration

> See [`ai/README.md`](ai/README.md) and [`ai/skills/bmchat-optimizer.md`](ai/skills/bmchat-optimizer.md) (branch `feat/ai-llm-config-20260910`).

bmchat now includes a dedicated `ai/` folder so any LLM can reason about the architecture without hallucinating:

- **9 configs** (`ai/config/` alias `ai/llms/`) for 7 families: OpenAI GPT-4o/mini (128k), Anthropic Claude 3.5 Sonnet (200k), Google Gemini 1.5 Pro (2M)/Flash (1M), Meta Llama 3.1 (128k self-hosted), Mistral Large 2 (128k PT-BR), DeepSeek V3/R1 (128k) and Cohere Command R+ (128k). Each JSON has `model/provider/context_window/temperature/system_prompt/prompts` tuned for bmchat (PoW/ECIES/streams/inventory/554 tests).
- **6 prompts** (`ai/prompts/`): `performance.md` (virtual scroll, receiveQueue 10000+4 workers), `security-audit.md` (33 CVEs + W1), `refactor.md` (7 patterns), `testing.md` (>95% logic), `documentation.md` (EN/PT-BR), `code-review.md` (file:line checklist).
- **Skill** `ai/skills/bmchat-optimizer.md` (frontmatter `name: bmchat-optimizer`) — teaches any agent: what is bmchat (P2P Bitmessage, PoW 1000/1000, ECIES/ECDSA, streams, no servers), architecture above, known bottlenecks (e.g., `gui/app.py:_redraw_chat` 161 lines, `manager.py` queues, `peers.py` flood) and rules (554 tests, EN/PT-BR, ruff/mypy, wire compat, 0o700/0o600, Pillow allowlist).

**DI graph with AI:** agents should use `run.py:create_client()` to inject `MockPoWStrategy`/`MockNetworkManager`/`ProtocolObjectFactory`/`MessageRepository` etc., keeping `client.db` compat. The Observer bridge (`ui_queue` ↔ `EventEmitter`) and legacy `PowExecutor` wrapper stay intact.

```bash
cat ai/config/openai-gpt4o.json | jq .system_prompt
cat ai/prompts/refactor.md
for f in ai/config/*.json; do python3 -m json.tool "$f" > /dev/null && echo "$f OK"; done
```

## Next Steps

- Migrate more SQL calls from `Client` to `Repositories` (incremental)
- Use `Message` model in GUI for `get_display_icon()` instead of `status` strings
- Expand `Factory` to `build_pubkey`/`build_broadcast` in `Client.broadcast*`
- Persisted `Command` history for real Undo of messages (today only pending)
- `Factory` for `Packets` (version/addr/inv)

## References

- Design Patterns — Gamma et al. (GoF)
- Bitmessage protocol spec — `protocol/objects.py` and `protocol/packets.py`
- Tests: `tests/test_integration.py`, `tests/test_wire.py`, `tests/test_menu_pow.py`
