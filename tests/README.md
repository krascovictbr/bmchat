> **Language:** [English](README.md) | [Português (BR)](README.pt-BR.md)

# Standardized test suite — bmchat

> Branch: `test/bateria-95-20260910` · 554 tests · >95% logic

## How to Run

```bash
python3 -m pytest tests/unit -q                 # unit (<15s)
python3 -m pytest tests/integration -q          # integration (<5s)
python3 -m pytest tests/stress -q               # stress (<30s)
python3 -m pytest tests/unit tests/integration tests/stress -q  # all (83s)

# coverage
python3 -m coverage run -m pytest tests/unit tests/integration tests/stress -q
python3 -m coverage report --include="bmchat/crypto/*,bmchat/protocol/*,bmchat/util/*,bmchat/core/*,bmchat/net/*,bmchat/gui/commands/*"
python3 -m coverage html --include="bmchat/*"  # htmlcov/
```

## Structure

- `unit/` — no network/Tk, `tempdir`, `MockPoWStrategy`, `FakeApp`
  - `test_crypto.py` (174) — ecc/ecies/keys/pow/encrypted_db
  - `test_protocol.py` (94) + `test_util.py` (59)
  - `test_core.py` (105) + `test_core_boost.py` (12)
  - `test_net_gui.py` (80) — proxy/peers/manager/peer/mock/commands
- `integration/test_core_integration.py` (15) — DB+Client+Factory+DM isolated
- `stress/test_stress.py` (15) — 500 DMs, 20 peers, PoW 20×, TTL, rate-limit

## Standard

- `TARGET=2**52` or `MockPoWStrategy` for fast PoW
- `tempfile.mkdtemp` + `Database`/`Client` per test
- `MockNetworkManager` (no sockets) and `FakeApp` (no Tk)
- Deterministic, no long `time.sleep`, no external dependency
- Naming: `TestClass::test_case_condition`

## Confidence

- Logic: >95% (crypto 100%, protocol 100%, repositories 100%, events 98%, net 95%)
- Tk GUI: 14% total (helpers 100% via FakeApp, Canvas requires display)
- Total bmchat: 51% (GUI drags down)

## History

- Legacy (`tests/test_*.py` 19 files) removed in `test/bateria-95-20260910` and replaced by this suite.
