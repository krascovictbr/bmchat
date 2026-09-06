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


class PeerStore:

    def __init__(self, path=None):
        self.path = path
        self.entries = {}

    def load(self):
        if not self.path or not os.path.exists(self.path):
            self.seed_defaults()
            return
        try:
            with open(self.path, 'r') as handle:
                data = json.load(handle)
            for item in data:
                peer = item.get('peer', {})
                info = item.get('info', {})
                self.entries[(peer['host'], int(peer['port']))] = {
                    'stream': int(item.get('stream', 1)),
                    'services': info.get('services', 1),
                    'last_seen': int(info.get('lastseen', time.time())),
                    'rating': float(info.get('rating', 0)),
                    'last_try': int(info.get('lasttry', 0)),
                }
        except Exception:
            self.seed_defaults()

    def seed_defaults(self):
        now = int(time.time())
        for host, port in DEFAULT_NODES:
            self.entries[(host, port)] = {
                'stream': 1, 'services': 1, 'last_seen': now, 'rating': 0,
                'last_try': 0}

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
                },
            })
        directory = os.path.dirname(self.path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        with open(self.path, 'w') as handle:
            json.dump(entries, handle, indent=2)

    def add(self, host, port, stream=1, services=1, rating=0):
        key = (host, int(port))
        entry = self.entries.get(key, {
            'stream': stream, 'services': services,
            'last_seen': int(time.time()), 'rating': rating,
            'last_try': 0})
        entry['last_seen'] = int(time.time())
        entry.setdefault('rating', rating)
        entry.setdefault('last_try', 0)
        self.entries[key] = entry

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

    def add_peer(self, peer, stream=1, services=1):
        self.add(peer.host, peer.port, stream, services)

    def all(self):
        return [Peer(host, port) for host, port in self.entries]

    def best(self, limit=None, exclude=None, cooldown=60):
        exclude = exclude or set()
        now = int(time.time())
        ranked = sorted(
            self.entries.items(),
            key=lambda kv: (kv[1].get('rating', 0), -kv[1].get('last_seen', 0)),
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