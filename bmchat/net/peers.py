import json
import os
import time


DEFAULT_NODES = [
    ('5.45.99.75', 8444),
    ('75.167.159.54', 8444),
    ('95.165.168.168', 8444),
    ('85.180.139.241', 8444),
    ('158.222.217.190', 8080),
    ('178.62.12.187', 8448),
    ('24.188.198.204', 8111),
    ('109.147.204.113', 1195),
    ('178.11.46.221', 8444),
]

DNS_SEEDS = [
    ('bootstrap8080.bitmessage.org', 8080),
    ('bootstrap8444.bitmessage.org', 8444),
]


class Peer:
    __slots__ = ('host', 'port')

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def __eq__(self, other):
        return isinstance(other, Peer) and \
            self.host == other.host and self.port == other.port

    def __hash__(self):
        return hash((self.host, self.port))

    def __repr__(self):
        return '%s:%s' % (self.host, self.port)


def _parse_store_entry(item):
    """Parse one stored peer entry; return ((host, port), info) or None."""
    try:
        if not isinstance(item, dict):
            return None
        peer = item.get('peer', {}) or {}
        info = item.get('info', {}) or {}
        host = str(peer.get('host', '')).strip()
        port = int(peer.get('port', 0))
        if not host or not 1 <= port <= 65535:
            return None
        return (host, port), {
            'stream': int(item.get('stream', 1)),
            'services': info.get('services', 1),
            'last_seen': int(info.get('lastseen', time.time())),
            'rating': float(info.get('rating', 0)),
            'last_try': int(info.get('lasttry', 0)),
            'inv_count': int(info.get('invs', 0) or 0),
            'last_inv': int(info.get('lastinv', 0) or 0),
            'mute_count': int(info.get('mutes', 0) or 0),
        }
    except Exception:
        return None


class PeerStore:

    def __init__(self, path=None):
        self.path = path
        self.entries = {}

    def _read_store_data(self):
        if not self.path or not os.path.exists(self.path):
            return None
        try:
            with open(self.path, 'r', encoding='utf-8') as handle:
                data = json.load(handle)
        except Exception:
            return None
        if not isinstance(data, list):
            return None
        return data

    def load(self):
        data = self._read_store_data()
        if data is None:
            self.seed_defaults()
            return
        for item in data:
            entry = _parse_store_entry(item)
            if entry is not None:
                self.entries[entry[0]] = entry[1]
        if not self.entries:
            self.seed_defaults()

    def seed_defaults(self):
        now = int(time.time())
        for host, port in DEFAULT_NODES:
            self.entries[(host, port)] = {
                'stream': 1, 'services': 1, 'last_seen': now, 'rating': 0,
                'last_try': 0, 'inv_count': 0, 'last_inv': 0,
                'mute_count': 0}

    def save(self):
        if not self.path:
            return
        entries = []
        for (host, port), info in self.entries.items():
            entries.append({
                'stream': info.get('stream', 1),
                'peer': {'host': host, 'port': port},
                'info': {
                    'services': info.get('services', 1),
                    'lastseen': info.get('last_seen', int(time.time())),
                    'rating': info.get('rating', 0),
                    'lasttry': info.get('last_try', 0),
                    'invs': info.get('inv_count', 0),
                    'lastinv': info.get('last_inv', 0),
                    'mutes': info.get('mute_count', 0),
                },
            })
        directory = os.path.dirname(self.path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        tmp = self.path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as handle:
            json.dump(entries, handle, indent=2)
            try:
                handle.flush()
                os.fsync(handle.fileno())
            except Exception:
                pass
        os.replace(tmp, self.path)

    MAX_PEERS = 5000

    def add(self, host, port, stream=1, services=1, rating=0):
        try:
            host = str(host).strip()
            port = int(port)
        except Exception:
            return
        if not host or not 1 <= port <= 65535:
            return
        try:
            stream = int(stream)
        except Exception:
            stream = 1
        key = (host, port)
        entry = self.entries.get(key, {
            'stream': stream, 'services': services,
            'last_seen': int(time.time()), 'rating': rating,
            'last_try': 0, 'inv_count': 0, 'last_inv': 0,
            'mute_count': 0})
        entry['last_seen'] = int(time.time())
        entry['stream'] = stream
        entry['services'] = services
        entry.setdefault('rating', rating)
        entry.setdefault('last_try', 0)
        entry.setdefault('inv_count', 0)
        entry.setdefault('last_inv', 0)
        entry.setdefault('mute_count', 0)
        self.entries[key] = entry
        if len(self.entries) > self.MAX_PEERS:
            # evicta piores (rating baixo, vistos há mais tempo)
            ranked = sorted(
                self.entries.items(),
                key=lambda kv: (kv[1].get('rating', 0),
                                kv[1].get('last_seen', 0)))
            for old_key, _ in ranked[:len(self.entries) - self.MAX_PEERS]:
                self.entries.pop(old_key, None)

    def record_attempt(self, host, port):
        entry = self.entries.get((host, int(port)))
        if entry is not None:
            entry['last_try'] = int(time.time())

    def record_failure(self, host, port):
        entry = self.entries.get((host, int(port)))
        if entry is not None:
            entry['rating'] = entry.get('rating', 0) - 1
            entry['last_try'] = int(time.time())

    def record_success(self, host, port):
        entry = self.entries.get((host, int(port)))
        if entry is not None:
            entry['rating'] = min(entry.get('rating', 0) + 1, 10)
            entry['last_try'] = int(time.time())

    def record_inv(self, host, port):
        """Par entregou inv: marca como produtivo (priorizado no giro).

        Não mexe no rating (handshake continua mandando nisso); só
        registra produtividade para best() preferir quem já falou.
        """
        try:
            entry = self.entries.get((host, int(port)))
        except Exception:
            return
        if entry is None:
            return
        now = int(time.time())
        try:
            entry['inv_count'] = int(entry.get('inv_count', 0) or 0) + 1
        except Exception:
            entry['inv_count'] = 1
        entry['last_inv'] = now

    def record_mute(self, host, port):
        """Par estabelecido que nunca mandou nada útil: desprioriza.

        Penalidade moderada (-2) com last_try atualizado: some do giro
        por ~cooldown (60s) mas NÃO é banido — se a rede só tiver ele,
        volta a ser tentado. Contador mute_count é só diagnóstico.
        """
        try:
            entry = self.entries.get((host, int(port)))
        except Exception:
            return
        if entry is None:
            return
        entry['rating'] = entry.get('rating', 0) - 2
        entry['last_try'] = int(time.time())
        try:
            entry['mute_count'] = int(entry.get('mute_count', 0) or 0) + 1
        except Exception:
            entry['mute_count'] = 1

    def add_peer(self, peer, stream=1, services=1):
        self.add(peer.host, peer.port, stream, services)

    def all(self):
        return [Peer(host, port) for host, port in self.entries]

    def prefer(self, keys):
        """Entries for exact keys, ignoring cooldown.

        Used after a local wipe: peers dropped by us must be retried
        immediately even if a failed attempt penalized them meanwhile.
        """
        result = []
        for key in keys or []:
            try:
                host, port = key
                info = self.entries.get((host, int(port)))
            except Exception:
                continue
            if info is not None:
                result.append((Peer(host, int(port)), info))
        return result

    @staticmethod
    def _effective_rating(info):
        """Rating + bônus limitado por produtividade (já entregou inv).

        +2 coloca o par falante à frente de novato (0) e de morto (-1),
        mas sem blindar: cada falha/mudez derruba o rating e o cooldown
        continua valendo para rating negativo. Sem inv: rating puro.
        """
        try:
            base = float(info.get('rating', 0))
        except Exception:
            base = 0.0
        try:
            productive = int(info.get('inv_count', 0) or 0) > 0
        except Exception:
            productive = False
        return base + (2.0 if productive else 0.0)

    def best(self, limit=None, exclude=None, cooldown=60):
        exclude = exclude or set()
        now = int(time.time())
        ranked = sorted(
            self.entries.items(),
            key=lambda kv: (self._effective_rating(kv[1]),
                            -kv[1].get('last_seen', 0)),
            reverse=True)
        result = []
        for (host, port), info in ranked:
            if (host, port) in exclude:
                continue
            if info.get('rating', 0) < 0 and \
                    now - info.get('last_try', 0) < cooldown:
                continue
            result.append((Peer(host, port), info))
            if limit and len(result) >= limit:
                break
        return result
