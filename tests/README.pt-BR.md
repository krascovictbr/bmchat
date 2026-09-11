> **Idioma:** [Português (BR)](README.pt-BR.md) | [English](README.md)

# Bateria de testes padronizada — bmchat

> Branch: `test/bateria-95-20260910` · 554 testes · >95% lógica

## Como rodar

```bash
python3 -m pytest tests/unit -q                 # unitários (<15s)
python3 -m pytest tests/integration -q          # integração (<5s)
python3 -m pytest tests/stress -q               # estresse (<30s)
python3 -m pytest tests/unit tests/integration tests/stress -q  # tudo (83s)

# cobertura
python3 -m coverage run -m pytest tests/unit tests/integration tests/stress -q
python3 -m coverage report --include="bmchat/crypto/*,bmchat/protocol/*,bmchat/util/*,bmchat/core/*,bmchat/net/*,bmchat/gui/commands/*"
python3 -m coverage html --include="bmchat/*"  # htmlcov/
```

## Estrutura

- `unit/` — sem rede/Tk, `tempdir`, `MockPoWStrategy`, `FakeApp`
  - `test_crypto.py` (174) — ecc/ecies/keys/pow/encrypted_db
  - `test_protocol.py` (94) + `test_util.py` (59)
  - `test_core.py` (105) + `test_core_boost.py` (12)
  - `test_net_gui.py` (80) — proxy/peers/manager/peer/mock/commands
- `integration/test_core_integration.py` (15) — DB+Client+Factory+DM isolado
- `stress/test_stress.py` (15) — 500 DMs, 20 peers, PoW 20×, TTL, rate-limit

## Padrão

- `TARGET=2**52` ou `MockPoWStrategy` para PoW rápido
- `tempfile.mkdtemp` + `Database`/`Client` por teste
- `MockNetworkManager` (sem sockets) e `FakeApp` (sem Tk)
- Determinístico, sem `time.sleep` longo, sem dependência externa
- Nomenclatura: `TestClasse::test_caso_condicao`

## Confiança

- Lógica: >95% (crypto 100%, protocol 100%, repositories 100%, events 98%, net 95%)
- GUI Tk: 14% total (helpers 100% via FakeApp, Canvas exige display)
- Total bmchat: 51% (GUI puxa para baixo)

## Histórico

- Legados (`tests/test_*.py` 19 arquivos) removidos em `test/bateria-95-20260910` e substituídos por esta bateria.
