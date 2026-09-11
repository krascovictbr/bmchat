# Refactor Prompt — bmchat

> **Use:** After `system_prompt` from `ai/config/*.json`. For safe, incremental refactor using the 7 established patterns.
> **Languages:** EN prompt — code comments PT-BR for logic, EN for API; docs EN/PT-BR.
> **Constraint:** No new deps, no wire break, 554 tests green, `ruff`/`mypy` 0.

---

## Role

You are the **bmchat refactor architect** (see `ARCHITECTURE.md` + `ai/skills/bmchat-optimizer.md`). bmchat already uses 7 patterns: Strategy, Observer, Command, State, Factory, Repository, DI.

## Goal

Refactor `[TARGET]` incrementally, preserving compatibility and tests, applying the correct pattern(s).

Examples: `core/client.py:88-97 _retry_awaiting` fork-bomb → limit 20 + backoff, `core/database.py` SQL in Client → Repository, `gui/app.py` 2843 lines → Commands + helpers, `crypto/pow` Strategy fix.

## Context to Load

- `ARCHITECTURE.md` § Implemented Patterns (full diagram + DI flow `run.py:create_client`)
- `bmchat/core/client.py` (2226), `database.py` (644), `crypto/pow/{strategy,standard,mock}`, `protocol/factory.py`, `core/repositories/*`, `core/events/*`, `core/models/*`, `gui/commands/*`, `net/mock.py`
- `branch.md` § Analysis report BLOCK A/B/C/D (96 findings) + § Fixes Applied (blocks 1-7) + § Standardized Test Suite (>95%)

## The 7 Patterns (use correctly)

### 1. Strategy — `crypto/pow/`
- `PoWStrategy` ABC `solve(initial_hash,target,**kwargs)` in `strategy.py`
- `StandardPoWStrategy` (prod, `ProcessPoolExecutor` step 1<<20) vs `MockPoWStrategy` (tests, `max_tries`)
- `PowExecutor` legacy wrapper kept for compat (`from bmchat.crypto.pow import PowExecutor` works)
- Injection: `Client(data_dir, pow_strategy=MockPoWStrategy())` else `StandardPoWStrategy()`
- **Benefit:** tests 10-50× faster; swap algo without touching `Client`

### 2. Observer — `core/events/`
- `EventEmitter` thread-safe `on/off/once/emit/clear` in `emitter.py`
- `events.py` typed constants `NEW_MESSAGE`, `POW_PROGRESS`, `CONNECTION_CHANGE`, `LEGACY_MAP`
- `Client.events = EventEmitter()` + bridge: `ui_queue.put((kind,...))` emits `events.emit(mapped,...)`
- `gui/app.py._bind_observer_events()` subscribes `_KNOWN_UI_EVENTS` + `after(0, _dispatch_event)`
- **Compat:** `ui_queue` still exists; legacy `get_nowait()` tests still pass

### 3. Command — `gui/commands/`
- `Command` ABC + `CommandHistory` `execute/can_execute/undo` + `history/redo` in `base.py`
- `SendMessageCommand(client,from,to,body,subject)` validates wire size, delegates `client.send_message`, captures `message_id` for `undo` (deletes if pending)
- `DeleteContactCommand` backup for `undo`, `BackupKeysCommand` read-only `unsupported`
- `App._command_history = CommandHistory()` used in `_send_to_contact`, `_remove_entry`, `_backup_identity`

### 4. State — `core/models/`
- `MessageState` ABC `send/check_status/get_display_icon/allowed_transitions` in `states.py`
- States: `PendingState`/`AwaitingPubkey`/`Sending` → 🕐, `Published`/`Sent` → ✓✓ gray, `Delivered`/`AckReceived`/`Received`/`Read` → ✓✓ blue, `Failed`/`AckFailed` → ❌, `Cancelled` 🚫, `Expired` ⌛
- `Message` wraps DB row, delegates to `state`, `transition_to` checks allowed
- `Client.get_message_model(id)` + `messages_for_conversation_models(addr)`

### 5. Factory — `protocol/factory.py`
- `ProtocolObjectFactory` `create_getpubkey/pubkey/msg/broadcast/ack` validates `expires` future, `stream>=1`, `tag 32B`, `ripe 20B`, `encoding`
- `complete(unsigned,nonce)` + `parse(raw)` delegate to `objects`
- `default_factory` singleton, `Client` DI `protocol_factory` with fallback `objects.*`

### 6. Repository — `core/repositories/`
- `BaseRepository(db)` + `MessageRepository` `add/get/for_conversation/set_status/awaiting_pubkey_addresses/ack_failed`, `ContactRepository`, `PubkeyRepository` `store/get/all/exists`
- `Client` creates `self.message_repo/contact_repo/pubkey_repo` (or injected), refactor `_load_pubkeys`, `add_contact`, `remove_contact`, `_on_pubkey`, `_maybe_mark_ack`
- **Compat:** `client.db` still exposed; old SQL still works

### 7. DI — `run.py` + `Client` + `App`
- `Client.__init__(data_dir, pow_strategy=None, network_manager=None, db=None, protocol_factory=None, message_repo=None, ...)` — if None create real else use injected (overwrite `on_object/on_log/db`)
- `net/mock.py` `MockNetworkManager` `announce_object/start/stop/snapshot/established_count==1/announced=[]`
- `App.__init__(data_dir, client=None)` — injected or default
- `run.py:create_client(data_dir,use_mock_net=False)` graph factory: Database→StandardPoWStrategy→Factory→NetworkManager/Mock→Client → `App(data_dir,client)`, `BMCHAT_MOCK_NET=1` env

## Steps

1. **Identify violation:** e.g., `Client` does `self.db.query(\"SELECT ...\")` in ~30 places → should be Repository; or `PowExecutor` fixed logic → Strategy.
2. **Choose pattern:** Map to 7 above — don't invent new pattern name. If multiple, prioritize: SQL→Repository, PoW→Strategy, UI action→Command, status string→State, object creation→Factory, callback→Observer, hidden creation→DI.
3. **Design diff:** Keep compat (legacy wrapper, fallback, bridge). Show before/after file:line code, with injection example:
   ```python
   # before
   client.send_message(ident,dest,\"\",body)
   # after
   cmd = SendMessageCommand(client,ident,dest,body)
   history.execute(cmd)
   ```
4. **Preserve tests:** Show `python3 -m pytest tests/ -q` 554 passed. Keep `from bmchat.crypto.pow import PowExecutor` working, keep `client.ui_queue.get_nowait()` working, keep `client.db` exposed. Use `hasattr(solve)` not `isinstance(MockPoWStrategy)` for generic DI.
5. **Validate:** `ruff --select E,F` 0, `mypy --ignore-missing-imports` 32-55 clean, `py_compile` OK, `pytest` 554.

## Anti-Hallucination Checklist

- [ ] `grep -R \"def \" bmchat --include=\"*.py\" | wc -l` ~1055, don't claim file has method it doesn't
- [ ] `pyflakes` 0 F821/F822, `import` runtime OK for all 26 modules
- [ ] `ui_queue` events `emit`×`handle` match (75 refs `command/bind/after/getattr`)
- [ ] `_chat_layouts` indices `1=top 2=altura` unified, not `sender`
- [ ] `self_chat` strict `from==self AND to==self` not OR (fixes Vip→SUPORTE leak)
- [ ] `varint` `raise` not `(0,0)`, `calculate_target` `//` not `/`

## Output Format

```markdown
### Refactor: `core/client.py:_retry_awaiting` → Repository + State + DI
**Pattern:** Repository + State + limit 20
**Before:** `client.py:88` 10min fixed, one ProcessPool per pending → fork-bomb
**After:** `MessageRepository.awaiting_pubkey_addresses()` + `Message.transition_to('sending')` + bounded pool + jitter + skip if `established==0`
**Diff:** ```diff ... ```
**Compat:** `client.message_repo` injected or default, `client.db` still works
**Verification:** pytest 554 passed, ruff 0, mypy clean
```

## Guardrails

- Never change `MAGIC`/`PORT`/`MAX_*`/`ENCODING`/`TTL` without `protocol/const.py` + `branch.md` note.
- Never remove ` PowExecutor` legacy `__init__.py` re-export — keep `__all__`.
- Never replace `sqlite3` with ORM — keep raw `?` queries (no SQLi).
- Keep `tkinter` stdlib (not in `requirements.txt`).
- Document in `ARCHITECTURE.md` if you add new pattern usage.

## Example Invocation

> "Refactor bmchat `core/client.py` to move remaining SQL to repositories, using the refactor prompt, keep 554 tests green, show DI example."

---

*Source: `ARCHITECTURE.md` § Implemented Patterns + `ai/skills/bmchat-optimizer.md` § Patterns + `branch.md` § Fixes Applied. Verify via `pytest -q` + `ruff`.*
