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
INV_WANTED_MAX = 1000
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
            'dial_attempts': 0,
        }
        self._maintenance_thread = None
        # Re-download robusto (ver wipe_objects): hashes pedidos via
        # getdata que nunca chegaram (ex.: par real descartou o getdata
        # na janela anti-interseção logo após o handshake) são pedidos
        # de novo até chegarem ou expirarem.
        self.pending_getdata = {}
        self.GETDATA_RETRY_DELAY = 3
        self.PENDING_TTL = 3600
        self.MAX_PENDING = 200000
        self.RESYNC_TIMEOUT = 1800
        self._last_retry_log = 0.0
        # Giro anti-travamento (cenário real: 6 "negociando" com 0B + 1
        # estabelecido mudo + 0 invs em 4min):
        # - HANDSHAKE_TIMEOUT: negociando sem version/verack há Ns →
        #   fecha e tenta outro (punição leve, sem banir). Referência
        #   (connectionpool.py, reaper): não-estabelecido sem TX há 20s
        #   é fechado com "Timeout".
        # - SILENT_TIMEOUT: estabelecido que NUNCA mandou addr/inv/objeto
        #   há Ns → desconecta e desprioriza (record_mute, sem banir).
        #   Só vale para quem nunca foi útil: par que já entregou o
        #   inventário e está quieto é saudável, não sofre evicção.
        # - BOOT_EXTRA_SLOTS: com inventário zerado, negociando NÃO ocupa
        #   slot de estabelecido (até +N half-open) para girar rápido.
        self.HANDSHAKE_TIMEOUT = 20
        self.SILENT_TIMEOUT = 60
        self.BOOT_EXTRA_SLOTS = 6
        self.DNS_REFRESH_INTERVAL = 120
        # Refresh contínuo: re-resolve periódico (30min) independente de
        # o giro ter esgotado — descobre pares novos/rotativos que
        # voltaram sem depender de addr de par mudo.
        self.DNS_PERIODIC_INTERVAL = 1800
        # Timeout curto por hostname: 1 semente lenta não trava as outras.
        self.DNS_RESOLVE_TIMEOUT = 8
        self._last_dns_resolve = 0.0
        self._last_periodic_dns = 0.0
        # Re-sync após wipe: pares derrubados por nós têm prioridade e
        # furam o cooldown até o re-download engrenar ou expirar.
        self.resync = {
            'active': False,
            'started_at': 0.0,
            'last_progress': 0.0,
            'removed': 0,
            'received': 0,
            'dropped': [],
        }
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
        self._last_periodic_dns = time.time()
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

    def _resolve_one_seed(self, host, port):
        """Resolve 1 hostname e mescla na loja (add dedupa por IP:porta)."""
        import socket as _socket
        try:
            infos = _socket.getaddrinfo(host, port, _socket.AF_INET,
                                        _socket.SOCK_STREAM)
        except Exception as exc:
            self.on_log('network', 'semente DNS %s: %s' % (host, exc))
            return 0
        added = 0
        for info in infos:
            try:
                self.add_peer(info[4][0], port)
                added += 1
            except Exception:
                pass
        self.on_log('network', 'semente DNS %s resolvida (%d par(es))'
                    % (host, added))
        return added

    def _resolve_timeout(self):
        try:
            timeout = float(self.DNS_RESOLVE_TIMEOUT)
        except Exception:
            timeout = 8.0
        return max(1.0, min(timeout, 60.0))

    def _spawn_seed_workers(self):
        workers = []
        for host, port in DNS_SEEDS:
            if not self.running:
                break
            try:
                thread = threading.Thread(
                    target=self._resolve_one_seed, args=(host, port),
                    daemon=True, name='net-dnsseed-%s' % host)
                thread.start()
            except Exception:
                continue
            workers.append(thread)
        return workers

    def _join_seed_workers(self, workers, timeout):
        deadline = time.time() + timeout
        for thread in workers:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                thread.join(min(remaining, timeout))
            except Exception:
                pass

    def _resolve_seeds(self):
        """1 thread por hostname + timeout curto + merge.

        Antes era serial e sem timeout: 1 semente lenta travava as
        outras (e o start). Cada worker mescla via add_peer (sem
        duplicar); o join com timeout só limita a espera — worker lento
        mescla quando terminar (daemon, não trava o desligamento).
        """
        self._join_seed_workers(
            self._spawn_seed_workers(), self._resolve_timeout())

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
                self._retry_pending_getdata()
                self._update_resync()
                self._maybe_periodic_refresh()
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

    def _is_cold_start(self):
        """Inventário zerado e nenhum inv visto: boot vazio, girar rápido."""
        try:
            if self.inventory or self.known_hashes:
                return False
            return int(self.stats.get('invs', 0)) == 0
        except Exception:
            return False

    def _maybe_refresh_seeds(self):
        """Re-resolve DNS quando o giro esgotou a lista (throttled).

        _resolve_seeds só rodava 1x no start(): com 715 pares mortos e
        nenhum novo chegando via addr (par mudo não manda addr), o
        cliente reciclava mortos para sempre. Dispara em thread.
        """
        now = time.time()
        try:
            interval = float(self.DNS_REFRESH_INTERVAL)
        except Exception:
            interval = 120.0
        if now - self._last_dns_resolve < max(30.0, interval):
            return
        self._last_dns_resolve = now
        try:
            threading.Thread(
                target=self._resolve_seeds, daemon=True,
                name='net-dnsseeds-refresh').start()
        except Exception:
            pass
        try:
            self.on_log('network', 'procurando pares… (lista esgotada, '
                        're-consultando sementes DNS)')
        except Exception:
            pass

    def _maybe_periodic_refresh(self):
        """Re-resolve periódico (30min), independente de esgotar a lista.

        O re-DNS ao esgotar (120s, _maybe_refresh_seeds) só dispara
        quando não há mais ninguém para tentar; este roda sozinho para
        descobrir pares novos/rotativos que voltaram à rede.
        """
        try:
            interval = float(self.DNS_PERIODIC_INTERVAL)
        except Exception:
            interval = 1800.0
        now = time.time()
        if now - self._last_periodic_dns < max(60.0, interval):
            return
        self._last_periodic_dns = now
        try:
            threading.Thread(
                target=self._resolve_seeds, daemon=True,
                name='net-dnsseeds-periodic').start()
        except Exception:
            pass
        try:
            self.on_log('network', 'atualizando lista de pares '
                        '(re-consulta periódica às sementes DNS)…')
        except Exception:
            pass

    def _resync_candidates(self, current):
        with self.lock:
            if not self.resync.get('active'):
                return []
            dropped = list(self.resync.get('dropped') or [])
        candidates = []
        for peer, _info in self.peers.prefer(dropped):
            if (peer.host, peer.port) not in current:
                candidates.append(peer)
        return candidates

    def _spawn_candidate(self, peer, current):
        """Registra tentativa e abre conexão; devolve True se tentou."""
        if (peer.host, peer.port) in current:
            return False
        self.peers.record_attempt(peer.host, peer.port)
        try:
            self.stats['dial_attempts'] = \
                int(self.stats.get('dial_attempts', 0)) + 1
        except Exception:
            pass
        try:
            self.spawn(peer)
        except Exception:
            pass
        current.add((peer.host, peer.port))
        return True

    def _max_connections(self):
        try:
            return max(1, min(int(
                self.db.get_int('max_connections', 8)), 50))
        except Exception:
            return 8

    def _connection_targets(self, max_connections):
        """(current, goal): meta é ter N ESTABELECIDAS; negociando tem
        orçamento half-open à parte (+BOOT_EXTRA_SLOTS, agora também em
        regime contínuo, não só no boot vazio: com a lista cheia de
        mortos, girar 1-a-1 por tick de 5s nunca acha o vivo)."""
        with self.lock:
            current = set(c.peer_key for c in self.connections.values())
            established = sum(
                1 for c in self.connections.values() if c.established)
        need = max_connections - established
        if need <= 0:
            return current, 0
        try:
            extra = max(0, int(self.BOOT_EXTRA_SLOTS))
        except Exception:
            extra = 0
        budget = max_connections + max(0, extra) - len(current)
        if budget <= 0:
            return current, 0
        return current, min(need, budget)

    def _spawn_best(self, current, max_connections, goal, spawned):
        found = False
        for peer, _info in self.peers.best(limit=max_connections * 4,
                                           exclude=current):
            if spawned >= goal:
                break
            found = True
            if self._spawn_candidate(peer, current):
                spawned += 1
        return spawned, found

    def _ensure_connections(self):
        max_connections = self._max_connections()
        current, goal = self._connection_targets(max_connections)
        if goal <= 0:
            return
        # Antes: missing = max - len(current): 6 negociando mortas
        # ocupavam slot e o giro parava (1 tentativa/5s). Agora a meta
        # conta estabelecidas e há orçamento half-open extra (+4) em
        # qualquer regime, não só no boot vazio.
        spawned = 0
        for peer in self._resync_candidates(current):
            if spawned >= goal:
                break
            if self._spawn_candidate(peer, current):
                spawned += 1
        spawned, found = self._spawn_best(
            current, max_connections, goal, spawned)
        if spawned == 0 and not found:
            # Giro esgotou a lista (só cooldown/mortos): re-DNS throttled.
            self._maybe_refresh_seeds()

    def _evict_connection(self, connection, reason):
        with self.lock:
            if self.connections.get(
                    connection.peer_key) is not connection:
                return False
            self.connections.pop(connection.peer_key, None)
        try:
            connection.close()
        except Exception:
            pass
        try:
            self.on_log('network', reason)
        except Exception:
            pass
        return True

    def _handshake_stalled(self, connection, now):
        """Negociando sem version/verack além do limite?"""
        if connection.established:
            return False
        try:
            started = float(getattr(connection, 'started_at', now))
        except Exception:
            return False
        try:
            limit = float(self.HANDSHAKE_TIMEOUT)
        except Exception:
            limit = 20.0
        return now - started > limit

    def _established_mute(self, connection, now):
        """Estabelecido que NUNCA mandou addr/inv/objeto além do limite?"""
        if not connection.established:
            return False
        if getattr(connection, 'last_useful_at', None) is not None:
            return False
        try:
            base = connection.connected_at or connection.started_at
            base = float(base)
        except Exception:
            return False
        try:
            limit = float(self.SILENT_TIMEOUT)
        except Exception:
            limit = 60.0
        return now - base > limit

    def _established_silent_try(self, connection, now):
        """Progressivo: 30s já tenta outro (sem mute), 60s registra mute."""
        if not connection.established:
            return False
        if getattr(connection, 'last_useful_at', None) is not None:
            return False
        try:
            base = connection.connected_at or connection.started_at
            base = float(base)
        except Exception:
            return False
        try:
            mute_limit = float(self.SILENT_TIMEOUT)
        except Exception:
            mute_limit = 60.0
        try_limit = max(30.0, mute_limit / 2.0)
        # já passou do try mas ainda não do mute -> evicção leve
        return now - base > try_limit and now - base <= mute_limit

    def _evict_if_stalled(self, connection, now):  # noqa: C901
        try:
            peer = connection.peer
            alive = connection.is_alive()
        except Exception:
            return False
        if not alive:
            return False
        if self._handshake_stalled(connection, now):
            try:
                self.peers.record_failure(peer.host, peer.port)
            except Exception:
                pass
            return self._evict_connection(
                connection,
                'par %s handshake sem resposta há %ds; '
                'fechando para tentar outro…'
                % (peer, int(now - connection.started_at)))
        if self._established_mute(connection, now):
            try:
                self.peers.record_mute(peer.host, peer.port)
            except Exception:
                pass
            base = connection.connected_at or connection.started_at
            return self._evict_connection(
                connection,
                'par %s silencioso há %ds (sem addr/inv/objeto); '
                'desconectando para tentar outro…' % (peer, int(now - base)))
        if self._established_silent_try(connection, now):
            base = connection.connected_at or connection.started_at
            return self._evict_connection(
                connection,
                'par %s silencioso há %ds (sem útil); '
                'tentando outro par…' % (peer, int(now - base)))
        return False

    def _prune_stalled(self, now):
        """Fecha handshake travado e par mudo; devolve quantos evictou."""
        evicted = 0
        for connection in list(self.connections.values()):
            try:
                stalled = self._evict_if_stalled(connection, now)
            except Exception:
                continue
            if stalled:
                evicted += 1
        return evicted

    def _trim_over_cap(self, cap):
        if len(self.connections) <= cap:
            return
        with self.lock:
            for connection in sorted(
                    self.connections.values(), key=lambda c: c.started_at):
                if len(self.connections) <= cap:
                    break
                if self.connections.get(
                        connection.peer_key) is not connection:
                    continue
                self.connections.pop(connection.peer_key, None)
                try:
                    connection.close()
                except Exception:
                    pass

    def _prune_connections(self):
        max_connections = self._max_connections()
        for connection in list(self.connections.values()):
            try:
                alive = connection.is_alive()
            except Exception:
                continue
            if not alive:
                with self.lock:
                    if self.connections.get(
                            connection.peer_key) is not connection:
                        continue
                    self.connections.pop(connection.peer_key, None)
        self._prune_stalled(time.time())
        # Mesmo orçamento do _ensure: o burst half-open (+BOOT_EXTRA)
        # vale em regime contínuo, não só no boot vazio — senão o prune
        # decapitaria no mesmo tick as discagens extras recém-abertas.
        try:
            extra = max(0, int(self.BOOT_EXTRA_SLOTS))
        except Exception:
            extra = 0
        self._trim_over_cap(max_connections + extra)

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
        # HEAD: marca par como útil (evita evicção por SILENT_TIMEOUT) — holder que só recebe getdata precisa disto
        try:
            source.last_useful_at = time.time()
        except Exception:
            pass
        obj_hash = double_sha512(raw)[:32]
        with self.lock:
            if obj_hash in self.known_hashes or obj_hash in self.inventory:
                self.pending_getdata.pop(obj_hash, None)
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
        with self.lock:
            self.pending_getdata.pop(obj_hash, None)
            if self.resync.get('active'):
                self.resync['received'] = self.resync.get('received', 0) + 1
                self.resync['last_progress'] = time.time()
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
            hashes = list(self.inventory.keys())
        if not hashes:
            return
        for idx in range(0, len(hashes), 49999):
            chunk = hashes[idx:idx + 49999]
            try:
                connection.send_packet(
                    b'inv', packets.assemble_inventory(chunk))
            except Exception:
                break

    def _remember_pending(self, hashes, now, source_key=None):
        with self.lock:
            for obj_hash in hashes:
                if obj_hash not in self.pending_getdata:
                    self.pending_getdata[obj_hash] = [now, now, source_key]
                else:
                    try:
                        entry = self.pending_getdata[obj_hash]
                        if len(entry) < 3:
                            entry.append(source_key)
                        elif entry[2] is None and source_key is not None:
                            entry[2] = source_key
                    except Exception:
                        pass
            while len(self.pending_getdata) > self.MAX_PENDING:
                try:
                    oldest = min(self.pending_getdata.items(),
                                 key=lambda kv: kv[1][0])[0]
                except Exception:
                    break
                self.pending_getdata.pop(oldest, None)

    def _send_getdata_chunks(self, connection, hashes):
        for i in range(0, len(hashes), 100):
            connection.send_packet(b'getdata', packets.assemble_getdata(
                hashes[i:i + 100]))

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

    def _should_delay_getdata(self, connection):
        try:
            if getattr(connection, 'sock', None) is None:
                return False
            base = getattr(connection, 'connected_at', None)
            if base is None:
                base = getattr(connection, 'started_at', None)
            if base is None:
                return False
            return time.time() - float(base) < 1.5
        except Exception:
            return False

    def _schedule_delayed_getdata(self, connection, hashes):  # noqa: C901
        def _delayed():
            time.sleep(1.0)
            try:
                with self.lock:
                    if connection.peer_key not in self.connections:
                        return
                    cur = self.connections.get(connection.peer_key)
                    if cur is not connection or not cur.established:
                        return
                    still = [h for h in hashes
                             if h in self.pending_getdata
                             and h not in self.inventory
                             and h not in self.known_hashes]
                if still:
                    self._send_getdata_chunks(connection, still)
            except Exception:
                pass
        try:
            threading.Thread(target=_delayed, daemon=True,
                             name='net-getdata-delay').start()
        except Exception:
            try:
                self._send_getdata_chunks(connection, hashes)
            except Exception:
                pass

    def on_inv(self, connection, payload):
        self._bump_stats('invs')
        # A9: rate por peer + cap de wanted (~1000).
        peer_key = self._peer_key(connection)
        if peer_key is not None and self._rate_limited(
                self._inv_hits, peer_key, INV_RATE_MAX, INV_RATE_WINDOW):
            return
        try:
            hashes = packets.parse_inventory(payload)[:INV_WANTED_MAX * 2]
        except Exception:
            return
        # Marca como útil antes de qualquer descarte (evita evicção de par falante)
        try:
            connection.last_useful_at = time.time()
        except Exception:
            pass
        try:
            self.peers.record_inv(
                connection.peer.host, connection.peer.port)
        except Exception:
            pass
        wanted = self._collect_wanted(hashes)
        if wanted:
            self._remember_pending(wanted, time.time(), peer_key)
            if self._should_delay_getdata(connection):
                self._schedule_delayed_getdata(connection, wanted)
            else:
                self._send_getdata_chunks(connection, wanted)

    def _stale_pending(self, now):
        stale = []
        with self.lock:
            for obj_hash, entry in list(self.pending_getdata.items()):
                try:
                    first = entry[0]
                    last = entry[1]
                except Exception:
                    self.pending_getdata.pop(obj_hash, None)
                    continue
                if obj_hash in self.inventory or obj_hash in self.known_hashes:
                    self.pending_getdata.pop(obj_hash, None)
                    continue
                if now - first > self.PENDING_TTL:
                    self.pending_getdata.pop(obj_hash, None)
                    continue
                if now - last >= self.GETDATA_RETRY_DELAY:
                    stale.append(obj_hash)
        stale.sort(key=lambda h: self._pending_last(h, now))
        return stale

    def _pending_last(self, obj_hash, now):
        with self.lock:
            entry = self.pending_getdata.get(obj_hash)
        try:
            return entry[1] if entry else now
        except Exception:
            return now

    def _resend_pending(self, stale, now):  # noqa: C901
        with self.lock:
            targets = [c for c in self.connections.values()
                       if c.established]
        if not targets or not stale:
            return 0
        try:
            tmap = {tuple(c.peer_key): c for c in targets
                    if getattr(c, 'peer_key', None)}
        except Exception:
            tmap = {}
        # Agrupa por source preferencial (P5) — fallback round-robin
        grouped = {}
        orphan = []
        with self.lock:
            pending_copy = dict(self.pending_getdata)
        for obj_hash in stale:
            try:
                entry = pending_copy.get(obj_hash)
                src = entry[2] if entry and len(entry) >= 3 else None
                if src is not None:
                    src = (str(src[0]), int(src[1]))
            except Exception:
                src = None
            if src is not None and src in tmap:
                grouped.setdefault(src, []).append(obj_hash)
            else:
                orphan.append(obj_hash)
        sent = 0
        for src, hashes in grouped.items():
            conn = tmap.get(src)
            if conn is None:
                orphan.extend(hashes)
                continue
            for idx in range(0, len(hashes), 100):
                chunk = hashes[idx:idx + 100]
                try:
                    conn.send_packet(
                        b'getdata', packets.assemble_getdata(chunk))
                except Exception:
                    continue
                sent += len(chunk)
                with self.lock:
                    for obj_hash in chunk:
                        entry = self.pending_getdata.get(obj_hash)
                        if entry is not None:
                            try:
                                entry[1] = now
                            except Exception:
                                pass
        if orphan:
            for index in range(0, len(orphan), 100):
                chunk = orphan[index:index + 100]
                connection = targets[(index // 100) % len(targets)]
                try:
                    connection.send_packet(
                        b'getdata', packets.assemble_getdata(chunk))
                except Exception:
                    continue
                sent += len(chunk)
                with self.lock:
                    for obj_hash in chunk:
                        entry = self.pending_getdata.get(obj_hash)
                        if entry is not None:
                            try:
                                entry[1] = now
                            except Exception:
                                pass
        return sent

    def _retry_pending_getdata(self):
        now = time.time()
        with self.lock:
            empty = not self.pending_getdata
        if empty:
            return
        stale = self._stale_pending(now)
        if not stale:
            return
        sent = self._resend_pending(stale, now)
        if sent and now - self._last_retry_log > 60:
            self._last_retry_log = now
            self.on_log('network', 're-sync: pedindo de novo %d '
                        'objeto(s) que ainda não chegaram…' % sent)

    def _update_resync(self):
        with self.lock:
            if not self.resync.get('active'):
                return
            started = self.resync.get('started_at', 0.0)
            pending = len(self.pending_getdata)
        elapsed = time.time() - started
        done = pending == 0 and elapsed > 5
        if done or elapsed > self.RESYNC_TIMEOUT:
            with self.lock:
                self.resync['active'] = False
                received = self.resync.get('received', 0)
            if done:
                self.on_log('network', 're-sync concluído: %d '
                            'objeto(s) recuperado(s)' % received)

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

    def on_getdata(self, connection, payload):  # noqa: C901
        self._bump_stats('getdatas')
        # A9: rate por peer + cap de hashes + cap de bytes (2-4MB).
        peer_key = self._peer_key(connection)
        if peer_key is not None and self._rate_limited(
                self._getdata_hits, peer_key,
                GETDATA_RATE_MAX, GETDATA_RATE_WINDOW):
            return
        # getdata recebido prova par vivo (não é mudo): holder que só recebe getdata
        try:
            connection.last_useful_at = time.time()
        except Exception:
            pass
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

    def _drop_connections_for_resync(self):
        with self.lock:
            conns = list(self.connections.values())
            dropped = [c.peer_key for c in conns]
            self.connections.clear()
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass
        return dropped

    def _reconnect_once(self, delay=0):
        if delay:
            time.sleep(delay)
        if not self.running:
            return
        try:
            with self.lock:
                active = bool(self.resync.get('active'))
            if delay and not active:
                return
            self._ensure_connections()
        except Exception as exc:
            try:
                self.on_log('network', 're-sync: %s' % exc)
            except Exception:
                pass

    def _kick_reconnect(self):
        if not self.running:
            return
        for index, delay in enumerate((0, 10)):
            try:
                threading.Thread(
                    target=self._reconnect_once, args=(delay,),
                    daemon=True, name='net-resync-%d' % index).start()
            except Exception:
                pass

    def wipe_objects(self):
        # Re-sync automático: o protocolo Bitmessage não tem mensagem
        # "me mande seu inventário". Os pares só anunciam (inv) no
        # handshake (_maybe_send_initial_data/send_inventory, e no
        # PyBitmessage real o sendBigInv com o inventário inteiro) e ao
        # receber objeto novo (announce_object). Por isso, após apagar,
        # pares já conectados nunca reenviariam os invs antigos e o nó
        # ficaria parado: derrubamos as conexões para cada handshake
        # novo trazer os invs de novo (on_inv->getdata->object, com
        # PoW/expiração validados em received_object, sem loop por
        # known_hashes/inventory dedup).
        # Detalhe que quebrou o re-download na prática contra pares
        # reais: o PyBitmessage ignora getdata por alguns segundos após
        # o handshake (antiIntersectionDelay/skipUntil) e nós pedíamos
        # uma única vez, sem repetir — todo o lote pós-wipe era
        # descartado em silêncio e nada voltava. Por isso todo hash
        # pedido fica em pending_getdata e _retry_pending_getdata
        # repete o getdata até o objeto chegar ou expirar (como o
        # DownloadThread de referência faz com missingObjects).
        # Não há o que re-anunciar localmente: inventory vazio envia
        # nada e on_getdata sem linhas no banco responde nada.
        # Limite honesto: só volta o que ainda não expirou e o que os
        # pares ainda guardam; o histórico completo leva minutos.
        try:
            rows = self.db.query('SELECT COUNT(*) AS n FROM objects')
            total = rows[0]['n'] if rows else 0
        except Exception:
            total = 0
        with self.lock:
            self.inventory.clear()
            self.known_hashes.clear()
            self.pending_getdata.clear()
        try:
            self.db.execute('DELETE FROM objects')
        except Exception as exc:
            self.on_log('network', 'limpeza: %s' % exc)
            return 0
        dropped = self._drop_connections_for_resync()
        now = time.time()
        with self.lock:
            self.resync['active'] = True
            self.resync['started_at'] = now
            self.resync['last_progress'] = now
            self.resync['removed'] = total
            self.resync['received'] = 0
            self.resync['dropped'] = list(dropped[:50])
        self.on_log(
            'network',
            '%d objetos apagados. Baixando tudo de novo… '
            'pode levar vários minutos (a rede reanuncia aos poucos).'
            % total)
        self._kick_reconnect()
        return total

    def _describe_net_state(self, established, total, inventory_size,
                            pending_size, stats):
        """Estado honesto da sincronização (sem prometer o impossível).

        Códigos estáveis para a GUI: parado | procurando-pares |
        negociando | aguardando-inv | sincronizando | conectado.
        """
        if not self.running:
            return 'parado'
        if established == 0 and total == 0:
            return 'procurando-pares'
        if established == 0:
            return 'negociando'
        try:
            invs = int(stats.get('invs', 0))
        except Exception:
            invs = 0
        if invs == 0 and not inventory_size:
            return 'aguardando-inv'
        if pending_size > 0:
            return 'sincronizando'
        return 'conectado'

    def _snapshot_backoff(self, now):
        try:
            return self.peers.in_backoff(now)
        except Exception:
            return 0

    def _snapshot_connect_timeout(self):
        try:
            return max(
                5, min(int(self.db.get_int('connect_timeout', 10)), 300))
        except Exception:
            return 10

    def snapshot(self):
        import struct as _struct
        now = time.time()
        with self.lock:
            connections = list(self.connections.values())
            peers_stored = len(self.peers.entries)
            inventory_size = len(self.inventory)
            known_size = len(self.known_hashes)
            pending_size = len(self.pending_getdata)
            resync_info = dict(self.resync)
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
            last_useful = getattr(connection, 'last_useful_at', None)
            if connection.established:
                silent_base = last_useful or base
                silent_for = max(0, int(now - silent_base))
                handshake_for = None
            else:
                silent_for = None
                try:
                    handshake_for = max(
                        0, int(now - float(connection.started_at)))
                except Exception:
                    handshake_for = None
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
                'silent_for': silent_for,
                'handshake_for': handshake_for,
                'has_useful': last_useful is not None,
            })
        proxy = self.proxy.describe() if self.proxy else 'Direto'
        try:
            stored = self.db.query('SELECT COUNT(*) AS n FROM objects')
            objects_stored = stored[0]['n'] if stored else 0
        except Exception:
            objects_stored = None
        uptime = int(now - self.started_at) if self.started_at else 0
        established = sum(1 for c in connections if c.established)
        peers_backoff = self._snapshot_backoff(now)
        connect_timeout = self._snapshot_connect_timeout()
        return {
            'proxy': proxy,
            'streams': list(self.streams),
            'running': self.running,
            'uptime': uptime,
            'stats': stats_copy,
            'net_state': self._describe_net_state(
                established, len(connections), inventory_size,
                pending_size, stats_copy),
            'connection_count': len(connections),
            'peers_stored': peers_stored,
            'peers_backoff': peers_backoff,
            'inventory': inventory_size,
            'known_hashes': known_size,
            'objects_stored': objects_stored,
            'pending_getdata': pending_size,
            'timeouts': {
                'handshake': self.HANDSHAKE_TIMEOUT,
                'silent': self.SILENT_TIMEOUT,
                'connect': connect_timeout,
            },
            'resync': {
                'active': bool(resync_info.get('active')),
                'elapsed': max(0, int(now - resync_info.get(
                    'started_at', now))),
                'pending': pending_size,
                'received': int(resync_info.get('received', 0)),
                'removed': int(resync_info.get('removed', 0)),
            },
            'connections': sorted(
                rows, key=lambda r: (r['host'], r['port'])),
        }
