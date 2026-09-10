"""MockNetworkManager — Dependency Injection para testes.

Simula a rede sem abrir sockets reais. Útil para testar Client
sem depender de peers ou PoW de rede.

Implementa a mesma interface de NetworkManager usada pelo Client:
- announce_object(raw, source=None)
- start(streams), stop(), snapshot(), add_peer(), etc.
"""

import time


class MockNetworkManager:
    """Mock leve da camada de rede."""

    def __init__(self, data_dir=None, db=None, on_object=None, on_log=None):
        self.data_dir = data_dir
        self.db = db
        self.on_object = on_object or (lambda *a, **k: None)
        self.on_log = on_log or (lambda *a, **k: None)
        self.running = False
        self.streams = []
        self.started_at = None
        self.inventory = {}
        self.announced = []  # lista de raws anunciados (para assert em testes)
        self.stats = {
            "objects_received": 0,
            "objects_announced": 0,
            "invs": 0,
            "getdatas": 0,
            "dial_attempts": 0,
        }

    def start(self, streams):
        self.running = True
        self.started_at = time.time()
        self.streams = list(streams)

    def stop(self):
        self.running = False

    def announce_object(self, raw, source=None):
        try:
            self.announced.append(bytes(raw))
            self.stats["objects_announced"] += 1
        except Exception:
            pass

    def add_peer(self, host, port, stream=1, services=1):
        pass

    def snapshot(self):
        return {
            "proxy": "Mock",
            "streams": list(self.streams),
            "running": self.running,
            "uptime": int(time.time() - self.started_at) if self.started_at else 0,
            "stats": dict(self.stats),
            "net_state": "conectado" if self.running else "parado",
            "connection_count": 0,
            "peers_stored": 0,
            "peers_backoff": 0,
            "inventory": len(self.inventory),
            "known_hashes": 0,
            "objects_stored": 0,
            "pending_getdata": 0,
            "timeouts": {"handshake": 20, "silent": 60, "connect": 10},
            "resync": {"active": False, "elapsed": 0, "pending": 0, "received": 0, "removed": 0},
            "connections": [],
        }

    @property
    def connection_count(self):
        return 0

    @property
    def established_count(self):
        return 1  # Simula online para não bloquear retry (testes)

    # Compat: métodos que Client pode chamar
    def wipe_objects(self):
        self.inventory.clear()
        return 0

    def received_object(self, raw, source):
        # Simula recepção válida
        self.stats["objects_received"] += 1
        return raw[:32] if raw else None
