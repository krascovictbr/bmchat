# Performance Optimization Prompt — bmchat

> **Use:** Copy this entire prompt into your LLM (after setting its `system_prompt` from `ai/config/*.json`). Replace `[TARGET]` with your focus area.
> **Languages:** EN prompt — agent may answer in PT-BR for `.pt-BR.md` files, EN otherwise.
> **Constraint:** Never break `pytest -q` (554 tests), keep `ruff` + `mypy --ignore-missing-imports` clean.

---

## Role

You are the **bmchat performance optimizer** (see `ai/skills/bmchat-optimizer.md` for full context). bmchat is P2P Bitmessage (Python 3.10+, Tkinter, PoW 1000/1000, ECIES/ECDSA, 554 tests).

## Goal

Optimize `[TARGET]` for speed, CPU, memory or network, with measured before/after and no wire break.

Examples: `gui/app.py:_redraw_chat` virtual scroll, `crypto/pow/standard.py` PoW throughput, `net/manager.py` receiveQueue/invQueue, `core/database.py` queries, `net/peers.py` PeerStore.

## Context to Load

- `ARCHITECTURE.md` § Implemented Patterns (7 patterns)
- `branch.md` § optimize/object-reception (receiveQueue 10000 + 4 workers, invQueue 49999, bytearray recv_into), § sync header large inv (1.6M), § peer rotation (25s handshake, 90s mute evict), § fast bootstrap (parallel DNS 8s, backoff 1m→1h, poda 5th)
- `bmchat/gui/app.py` (4649 lines, _redraw_chat 161, _build_widgets 196), `bmchat/crypto/pow/standard.py`, `bmchat/net/manager.py` (1045), `bmchat/core/database.py`
- `tests/unit/test_net_gui.py`, `tests/stress/test_stress.py` (500 DMs, 20 peers)

## Known Bottlenecks (from `ai/skills/bmchat-optimizer.md`)

1. **GUI `app.py:_redraw_chat`** — O(n) layout, 6000px doodle → virtual scroll viewport+100px buffer, `_wrap_lines` O(n²) → binary search + cache 500 FIFO, `font.measure` cache, hover/resize debounce 80ms, msg coalesce 200ms, PoW progress 1/s. Measured: 500 msgs 1382ms→216ms, 100 convs 1062ms→682ms, preview GROUP BY 99ms→19ms.
2. **PoW `pow/standard.py`** — `step 1<<54` hung, now `1<<20` + `shutdown(wait=False,cancel_futures=True)`, `self._started` sequential (no dup range), ProcessPoolExecutor×cpu. MockPoW for tests 10-50× faster.
3. **Net `manager.py`** — `known_hashes` 200k, inventory 8000, `_prune` depth4, `_collect_wanted` O(N), `_evict` lex min → FIFO O(1) OrderedDict, `receiveQueue` 10000 + pool 4, `invQueue` batch 49999 flush 1s, `store_object` FIFO, `pending_getdata` repeat 15s until expire 1h, `on_getdata` batch WHERE IN 500/200, `known_hashes` cap 200k, ` objects` DB 20000.
4. **DB `database.py`** — SQL in Client ~30 places → move to repositories (Message/Contact/Pubkey), indices `(status,direction)`, `(timestamp)`, `(expires)`, `(type,version,expires)`, `UNIQUE(obj_hash)`, WAL, `RLock`, `user_version` one-shot vs 2 UPDATE full-scan.
5. **Peers `peers.py`** — flood without cap → cap 5000 + evicção rating/seen, validate host/port, promote after success, `best()` +2 productive bonus + `inv_count/last_inv`, parallel DNS 1 thread/host 8s, backoff 1m→1h + poda 5th failure, `add` validate.
6. **Other:** `peer.py` 16MB→1.6M, checksum verify `sha512[:4]`, `send_packet` guard+try per peer, `bytearray+recv_into` zero-copy, `announce` batch, `snapshot`+COUNT 1.5s→3-5s, throttling inv/getdata per peer 50/60s, store 50/60s.

## Steps

1. **Profile:** `python3 -m cProfile -s cumulative` or `time pytest tests/stress -q -k test_loopback_50`. Baseline loopback 50 objs ~2.2s (<8s), wipe re-sync ~18s, 15s→30s tolerant.
2. **Pick one bottleneck:** e.g., `_redraw_chat` virtual scroll, or `manager.py` queue. Explain why it matters (file:line).
3. **Propose diff:** Small, incremental, keep `client.db` compat, keep `ui_queue` bridge, keep `PowExecutor` wrapper. No new deps. Show `old vs new` code, with `try/value` and `//` int math.
4. **Preserve tests:** Use `MockPoWStrategy(2**52)`/`FastMock` + `MockNetworkManager` + `FakeApp` + `tempdir`, no real sockets/Tk. Show `pytest -q` still 554 passed (or 554+new).
5. **Measure:** Provide before/after numbers (ms, objs/s, mem). If optimizing GUI, smoke Tk: 30 msgs →214 items 0 errors, maximize 1100→1600 entry x fixed 11 width 473→973.
6. **Validate:** `flake8` (2 CI cmds) exit 0, `mypy --ignore-missing-imports` clean (32-55 files), `py_compile` OK, `python3 -m json.tool` for config if touched.

## Output Format

```markdown
### Bottleneck: `bmchat/gui/app.py:161 _redraw_chat`
**Before:** O(n) layout 1382ms/500 msgs, str vs float TypeError
**After:** viewport + buffer, 216ms, cache hit 80%
**Diff:** ```diff ... ```
**Verification:** pytest 554 passed, flake8 0, mypy clean, manual smoke 30 msgs
**Risk:** low — fallback to full redraw if viewport calc fails
```

## Guardrails

- Never change PoW target formula to float (`/`→`//`).
- Never remove `MockPoWStrategy`/`MockNetworkManager` DI.
- Never break wire compat (MAGIC 0xE9BEB4D9, port 8444, ver 3, MAX_OBJECT_LENGTH).
- Keep EN/PT-BR docs: if you touch `README.md`, also touch `README.pt-BR.md`.
- For any new cap (e.g., `MAX_WIRE_BODY_BYTES=200_000`), document in `protocol/const.py` and justify.

## Example Invocation

> "Optimize bmchat performance: focus on `gui/app.py:_redraw_chat` and `net/manager.py:receiveQueue`. Use the performance prompt, keep 554 tests green, provide before/after metrics and diff."

---

*Source: `ai/skills/bmchat-optimizer.md` § Gargalos + `branch.md` § optimize/performance + `ARCHITECTURE.md`. Validate via `pytest -q`.*
