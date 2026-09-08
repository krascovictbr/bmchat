import os
import threading
import time

from ..protocol import packets
from ..protocol.objects import ParsedObject
from ..protocol.const import MAX_OBJECT_LENGTH
from ..crypto.pow import is_proof_of_work_sufficient
from ..util.hashing import double_sha512
from .peers import PeerStore, DNS_SEEDS

MAX_FUTURE_SKEW = 28 * 24 * 3600 + 10800
MAX_PAST_SKEW = 3600

# A9/A10: limites anti-DoS/anti-OOM.
INV_WANTED_MAX = 200
GETDATA_HASHES_MAX = 100
GETDATA_BLOBS_MAX = 20
GETDATA_BYTES_MAX = 3 * 1024 * 1024
INV_RATE_MAX = 5
INV_RATE_WINDOW = 10.0
GETDATA_RATE_MAX = 10
GETDATA_RATE_WINDOW = 10.0
STORE_RATE_MAX = 50
STORE_RATE_WINDOW = 60.0
INVENTORY_MAX = 8000
DB_OBJECTS_MAX = 20000


class NetworkManager:

    def __init__(self, data_dir, db, on_object=None, on_log=None):
        self.data_dir = data_dir
        self.db = db
        self.on_object = on_object
        self.on_log = on_log or (lambda *a, **k: None)
        self.peers = PeerStore(os.path.join(data_dir, 'knownnodes.dat'))
        self.peers.load()
        self.proxy = self._load_proxy()
        self.inventory = {}
        self.known_hashes = set()
        self.connections = {}
        self.lock = threading.RLock()
        self.running = False
        self.streams = []
        self.nonce = os.urandom(8)
        self.started_at = None
        self.stats = {
            'objects_received': 0,
            'objects_announced': 0,
            'invs': 0,
            'getdatas': 0,
        }
        self._maintenance_thread = None
        # M3: geração evita threads de manutenção órfãs após restart.
        self._generation = 0
        # A9/A10: rate por peer (inv/getdata/store).
        self._inv_hits = {}
        self._getdata_hits = {}
        self._store_hits = {}

    def _load_proxy(self):
        from ..net.proxy import ProxyProfile
        data = self.db.get_json('proxy', {})
        return ProxyProfile.from_dict(data)

    @property
    def connection_count(self):
        return len(self.connections)

    @property
    def established_count(self):
        with self.lock:
            return sum(1 for c in self.connections.values() if c.established)

    def start(self, streams):
        self.running = True
        self.started_at = time.time()
        with self.lock:
            self._generation += 1
            generation = self._generation
        self._prune_expired_objects()
        self._evict_db_to_cap()
        self._load_known_hashes()
        self.streams = list(streams)
        self._maintenance_thread = threading.Thread(
            target=self._maintenance, args=(generation,),
            daemon=True, name='net-maintenance')
        self._maintenance_thread.start()
        resolver = threading.Thread(
            target=self._resolve_seeds, daemon=True, name='net-dnsseeds')
        resolver.start()

    def _resolve_seeds(self):
        import socket as _socket
        for host, port in DNS_SEEDS:
            if not self.running:
                return
            try:
                infos = _socket.getaddrinfo(host, port, _socket.AF_INET,
                                            _socket.SOCK_STREAM)
            except Exception as exc:
                self.on_log('network', 'semente DNS %s: %s' % (host, exc))
                continue
            for info in infos:
                try:
                    self.add_peer(info[4][0], port)
                except Exception:
                    pass
            self.on_log('network', 'semente DNS %s resolvida' % host)

    def stop(self):
        self.running = False
        with self.lock:
            self._generation += 1
        for connection in list(self.connections.values()):
            connection.close()
        self.connections.clear()
        # M3: join da manutenção com timeout (sem travar o stop).
        thread = getattr(self, '_maintenance_thread', None)
        if thread is not None and thread.is_alive():
            try:
                thread.join(timeout=5)
            except Exception:
                pass
        self._maintenance_thread = None
        self.peers.save()

    def set_proxy(self, profile):
        self.proxy = profile
        self.db.set_json('proxy', profile.to_dict())

    def _maintenance(self, generation=None):
        if generation is None:
            with self.lock:
                generation = self._generation
        while self.running:
            with self.lock:
                if generation != self._generation:
                    return
            try:
                self._ensure_connections()
                self._prune_connections()
            except Exception as exc:
                self.on_log('network', 'manutenção: %s' % exc)
            # A10: prune periódica (antes: só no startup).
            try:
                self._prune_expired_objects()
                self._evict_inventory_to_cap()
            except Exception as exc:
                self.on_log('network', 'limpeza: %s' % exc)
            try:
                interval = int(self.db.get_int('maintenance_interval', 5))
            except (TypeError, ValueError):
                interval = 5
            time.sleep(max(2, min(interval, 120)))

    def _ensure_connections(self):
        try:
            max_connections = max(1, min(int(self.db.get_int('max_connections', 8)), 50))
        except Exception:
            max_connections = 8
        with self.lock:
            current = set(c.peer_key for c in self.connections.values())
        missing = max_connections - len(current)
        if missing <= 0:
            return
        for peer, info in self.peers.best(limit=max_connections * 4,
                                          exclude=current):
            if missing <= 0:
                break
            self.peers.record_attempt(peer.host, peer.port)
            self.spawn(peer)
            missing -= 1

    def _prune_connections(self):
        try:
            max_connections = max(1, min(int(self.db.get_int('max_connections', 8)), 50))
        except Exception:
            max_connections = 8
        for connection in list(self.connections.values()):
            if not connection.is_alive():
                with self.lock:
                    self.connections.pop(connection.peer_key, None)
        if len(self.connections) > max_connections:
            with self.lock:
                for connection in sorted(
                        self.connections.values(), key=lambda c: c.started_at):
                    if len(self.connections) <= max_connections:
                        break
                    self.connections.pop(connection.peer_key, None)
                    connection.close()

    def spawn(self, peer):
        if not self.running or not peer:
            return None
        key = (peer.host, peer.port)
        with self.lock:
            if key in self.connections:
                return None
            from .peer import PeerConnection
            connection = PeerConnection(self, peer)
            self.connections[connection.peer_key] = connection
        connection.start()
        return connection

    def add_peer(self, host, port, stream=1, services=1):
        self.peers.add(host, port, stream, services)

    def log(self, message):
        self.on_log('network', message)

    def _bump_stats(self, key):
        # M9: stats sob lock (leitores/escritores em threads distintas).
        with self.lock:
            try:
                self.stats[key] += 1
            except Exception:
                pass

    def _rate_limited(self, table, peer_key, limit, window):
        now = time.time()
        try:
            key = tuple(peer_key) if peer_key is not None else ('?', 0)
        except Exception:
            key = ('?', 0)
        hits = table.get(key)
        if hits is None:
            hits = []
            table[key] = hits
        cutoff = now - window
        while hits and hits[0] < cutoff:
            hits.pop(0)
        if len(hits) >= limit:
            return True
        hits.append(now)
        # Evita crescimento sem limite do mapa.
        if len(table) > 4096:
            try:
                oldest = next(iter(table))
                table.pop(oldest, None)
            except Exception:
                pass
        return False

    def store_object(self, raw):
        obj_hash = double_sha512(raw)[:32]
        with self.lock:
            if obj_hash in self.inventory:
                return obj_hash
            if len(self.inventory) >= INVENTORY_MAX:
                self._evict_inventory_locked(1)
            self.inventory[obj_hash] = raw
            self._trim_known_locked()
            return obj_hash

    def _trim_known_locked(self):
        try:
            if len(self.known_hashes) > 200000:
                self.known_hashes = set(list(self.known_hashes)[-150000:])
        except Exception:
            pass

    @staticmethod
    def _raw_expires(raw):
        import struct as _struct
        try:
            (expires,) = _struct.unpack('>Q', bytes(raw)[8:16])
            return int(expires)
        except Exception:
            return 0

    def _evict_inventory_locked(self, count=1):
        """Evicção por expires (menor expira primeiro). Chamador com lock."""
        # ADV: era `<=` e permitia 8001 (store com len==MAX não evictava
        # e adicionava 1). Com `<`, len==MAX evicta antes de adicionar.
        if len(self.inventory) < INVENTORY_MAX:
            return
        scored = [(self._raw_expires(raw), key)
                  for key, raw in self.inventory.items()]
        scored.sort()
        for _, key in scored[:max(1, count)]:
            self.inventory.pop(key, None)

    def _evict_inventory_to_cap(self):
        with self.lock:
            while len(self.inventory) > INVENTORY_MAX:
                before = len(self.inventory)
                self._evict_inventory_locked(
                    len(self.inventory) - INVENTORY_MAX)
                if len(self.inventory) >= before:
                    break

    def _evict_db_to_cap(self):
        try:
            rows = self.db.query('SELECT COUNT(*) AS n FROM objects')
            total = int(rows[0]['n']) if rows else 0
        except Exception:
            return
        if total <= DB_OBJECTS_MAX:
            return
        try:
            self.db.execute(
                'DELETE FROM objects WHERE hash IN (SELECT hash FROM '
                'objects ORDER BY expires ASC LIMIT ?)',
                (total - DB_OBJECTS_MAX,))
        except Exception as exc:
            self.on_log('network', 'limpeza: %s' % exc)

    def _parse_incoming_object(self, raw):
        try:
            if len(raw) > MAX_OBJECT_LENGTH + 64:
                return None
            parsed = ParsedObject(raw)
            now = time.time()
            if parsed.expires < now - MAX_PAST_SKEW:
                return None
            if parsed.expires > now + MAX_FUTURE_SKEW:
                return None
            if not is_proof_of_work_sufficient(raw):
                return None
        except Exception:
            return None
        return parsed

    def _deliver_object(self, parsed, raw, source):
        if self.on_object is not None:
            try:
                self.on_object(parsed, raw, source)
            except Exception:
                pass
        self.announce_object(raw, source)

    def received_object(self, raw, source):
        parsed = self._parse_incoming_object(raw)
        if parsed is None:
            return None
        # A10: taxa de store por peer (antes: sem limite).
        source_key = self._source_key(source)
        if source_key is not None and self._rate_limited(
                self._store_hits, source_key,
                STORE_RATE_MAX, STORE_RATE_WINDOW):
            return None
        obj_hash = double_sha512(raw)[:32]
        with self.lock:
            if obj_hash in self.known_hashes or obj_hash in self.inventory:
                return obj_hash
            self.known_hashes.add(obj_hash)
        try:
            self.db.store_object(obj_hash, raw, parsed.object_type,
                                 parsed.version, parsed.stream,
                                 parsed.expires)
        except Exception:
            pass
        self.store_object(raw)
        self._bump_stats('objects_received')
        self._deliver_object(parsed, raw, source)
        return obj_hash

    @staticmethod
    def _source_key(source):
        try:
            peer = getattr(source, 'peer', None)
            if peer is None:
                return None
            return (getattr(peer, 'host', '?'), getattr(peer, 'port', 0))
        except Exception:
            return None

    @staticmethod
    def _peer_key(connection):
        try:
            return (connection.peer.host, connection.peer.port)
        except Exception:
            return None

    def _remember_announce(self, obj_hash):
        with self.lock:
            try:
                self.known_hashes.add(obj_hash)
            except Exception:
                pass
            return [c for c in self.connections.values()
                    if c.established]

    def announce_object(self, raw, source=None):
        # A5: passa por store_object (cap/evicção) e marca known_hashes
        # (antes furava o controle de duplicadas/inventário).
        self._bump_stats('objects_announced')
        obj_hash = self._store_announce_blob(raw)
        if obj_hash is None:
            return
        targets = [c for c in self._remember_announce(obj_hash)
                   if c is not source]
        if not targets:
            return
        for connection in targets:
            self._send_single_inv(connection, obj_hash)

    def _store_announce_blob(self, raw):
        try:
            return self.store_object(bytes(raw))
        except Exception:
            pass
        try:
            return double_sha512(bytes(raw))[:32]
        except Exception:
            return None

    def _send_single_inv(self, connection, obj_hash):
        try:
            connection.send_packet(
                b'inv', packets.assemble_inventory([obj_hash]))
        except Exception as exc:
            try:
                self.on_log('network', 'announce falhou p/ %s: %s' % (
                    getattr(connection, 'peer', '?'), exc))
            except Exception:
                pass

    def send_inventory(self, connection):
        with self.lock:
            hashes = list(self.inventory.keys())[:1200]
        if hashes:
            connection.send_packet(b'inv', packets.assemble_inventory(hashes))

    def _collect_wanted(self, hashes):
        wanted = []
        for obj_hash in hashes:
            with self.lock:
                known = (obj_hash in self.inventory or
                         obj_hash in self.known_hashes)
            if known:
                continue
            wanted.append(obj_hash)
            if len(wanted) >= INV_WANTED_MAX:
                break
        return wanted

    def on_inv(self, connection, payload):
        self._bump_stats('invs')
        # A9: rate por peer + cap de wanted (~200).
        peer_key = self._peer_key(connection)
        if peer_key is not None and self._rate_limited(
                self._inv_hits, peer_key, INV_RATE_MAX, INV_RATE_WINDOW):
            return
        try:
            hashes = packets.parse_inventory(payload)[:INV_WANTED_MAX * 2]
        except Exception:
            return
        wanted = self._collect_wanted(hashes)
        for i in range(0, len(wanted), 100):
            try:
                connection.send_packet(b'getdata', packets.assemble_getdata(
                    wanted[i:i + 100]))
            except Exception:
                break

    def _split_cached_objects(self, hashes):
        blobs = []
        missing = []
        with self.lock:
            for obj_hash in hashes:
                raw = self.inventory.get(obj_hash)
                if raw is not None:
                    blobs.append(raw)
                else:
                    missing.append(obj_hash)
        return blobs, missing

    def _load_missing_fallback(self, missing, blobs):
        for obj_hash in missing[:50]:
            try:
                row = self.db.get_object(obj_hash)
                raw = row['raw'] if row else None
                if raw is not None:
                    blobs.append(bytes(raw))
            except Exception:
                pass

    def _load_missing_objects(self, missing):
        blobs = []
        try:
            capped = list(missing[:GETDATA_HASHES_MAX])
            placeholders = ','.join('?' for _ in capped)
            rows = self.db.query(
                'SELECT hash, raw FROM objects WHERE hash IN (%s)' % placeholders,
                tuple(capped))
            by_hash = {bytes(r['hash']): bytes(r['raw']) for r in rows}
            for obj_hash in capped:
                raw = by_hash.get(bytes(obj_hash))
                if raw is not None:
                    blobs.append(raw)
        except Exception:
            self._load_missing_fallback(missing, blobs)
        return blobs

    @staticmethod
    def _cap_blobs(blobs):
        capped = []
        total = 0
        for blob in blobs[:GETDATA_BLOBS_MAX * 2]:
            try:
                size = len(blob)
            except Exception:
                continue
            if capped and total + size > GETDATA_BYTES_MAX:
                break
            if len(capped) >= GETDATA_BLOBS_MAX:
                break
            capped.append(blob)
            total += size
        return capped

    def on_getdata(self, connection, payload):
        self._bump_stats('getdatas')
        # A9: rate por peer + cap de hashes + cap de bytes (2-4MB).
        peer_key = self._peer_key(connection)
        if peer_key is not None and self._rate_limited(
                self._getdata_hits, peer_key,
                GETDATA_RATE_MAX, GETDATA_RATE_WINDOW):
            return
        try:
            hashes = packets.parse_inventory(payload)[:GETDATA_HASHES_MAX]
        except Exception:
            return
        blobs, missing = self._split_cached_objects(hashes)
        if missing:
            blobs.extend(self._load_missing_objects(missing))
        if not blobs:
            return
        capped = self._cap_blobs(blobs)
        if capped:
            try:
                connection.send_packets(b'object', capped)
            except Exception:
                pass

    def _prune_expired_objects(self):
        try:
            self.db.execute(
                'DELETE FROM objects WHERE expires < ?',
                (int(time.time()) - 86400,))
        except Exception as exc:
            self.on_log('network', 'limpeza: %s' % exc)

    def _load_known_hashes(self):
        try:
            rows = self.db.query('SELECT hash FROM objects')
        except Exception as exc:
            self.on_log('network', 'inventário local: %s' % exc)
            return
        with self.lock:
            for row in rows:
                try:
                    self.known_hashes.add(bytes(row['hash']))
                except Exception:
                    pass
        if rows:
            self.on_log('network', '%d objetos já conhecidos '
                        '(sem rebaixar)' % len(rows))

    def wipe_objects(self):
        with self.lock:
            try:
                rows = self.db.query('SELECT COUNT(*) AS n FROM objects')
                total = rows[0]['n'] if rows else 0
            except Exception:
                total = 0
            self.inventory.clear()
            self.known_hashes.clear()
            try:
                self.db.execute('DELETE FROM objects')
            except Exception as exc:
                self.on_log('network', 'limpeza: %s' % exc)
                return 0
        self.on_log('network', '%d objetos apagados' % total)
        return total

    def snapshot(self):
        import struct as _struct
        now = time.time()
        with self.lock:
            connections = list(self.connections.values())
            peers_stored = len(self.peers.entries)
            inventory_size = len(self.inventory)
            known_size = len(self.known_hashes)
            # M9: cópia de stats sob o mesmo lock.
            stats_copy = dict(self.stats)
        rows = []
        for connection in connections:
            version = None
            if connection.their_version and \
                    len(connection.their_version) >= 4:
                try:
                    version, = _struct.unpack(
                        '>L', connection.their_version[0:4])
                except Exception:
                    version = None
            base = connection.connected_at or connection.started_at
            rows.append({
                'host': connection.peer.host,
                'port': connection.peer.port,
                'established': connection.established,
                'version': version,
                'services': connection.their_services,
                'streams': list(connection.their_streams),
                'time_offset': connection.time_offset,
                'rating': self.peers.entries.get(
                    (connection.peer.host,
                     connection.peer.port), {}).get('rating', 0),
                'bytes_sent': connection.bytes_sent,
                'bytes_received': connection.bytes_received,
                'age': max(0, int(now - base)),
            })
        proxy = self.proxy.describe() if self.proxy else 'Direto'
        try:
            stored = self.db.query('SELECT COUNT(*) AS n FROM objects')
            objects_stored = stored[0]['n'] if stored else 0
        except Exception:
            objects_stored = None
        uptime = int(now - self.started_at) if self.started_at else 0
        return {
            'proxy': proxy,
            'streams': list(self.streams),
            'running': self.running,
            'uptime': uptime,
            'stats': stats_copy,
            'connection_count': len(connections),
            'peers_stored': peers_stored,
            'inventory': inventory_size,
            'known_hashes': known_size,
            'objects_stored': objects_stored,
            'connections': sorted(
                rows, key=lambda r: (r['host'], r['port'])),
        }
