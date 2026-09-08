"""Giro anti-travamento: handshake com timeout, eviccao de par mudo,
rotacao para o falante e sync andando do zero.

Cenario real do dono: 6 "negociando" com 0B + 1 estabelecida muda +
0 invs em 4min. Causa raiz (evidencia no codigo):
- bmchat/net/peer.py::_handshake: deadline unico (era 60s) e
  bmchat/net/manager.py::_prune_connections so removia thread morta ou
  excesso: negociando presa ocupava slot por minutos.
- bmchat/net/peer.py::_read_loop: socket.timeout engolido com `continue`
  para sempre: par mudo nunca caia.
- bmchat/net/manager.py::_ensure_connections: missing = max-len(current)
  contava negociando como slot cheio (1 tentativa/5s); DNS so no start().
- bmchat/net/peers.py::best: sem bonus de produtividade; falante sem
  precedencia sobre morto/novato.
Referencia (/home/artix/PyBitmessage/src/network/connectionpool.py,
reaper): nao-estabelecido sem TX ha 20s fecha com "Timeout".
"""
import shutil
import tempfile
import time

from bmchat.core.database import Database
from bmchat.net.manager import NetworkManager
import bmchat.net.manager as manager_mod
from bmchat.net.peers import Peer
from bmchat.protocol import packets
from bmchat.protocol.objects import (
    assemble_object_unsigned, complete_object,
)
from bmchat.util.hashing import double_sha512


def _fake_pow(*args, **kwargs):
    return True


def _make_raw(tag):
    expires = int(time.time()) + 3600
    unsigned = assemble_object_unsigned(expires, 0, 4, 1, tag)
    return complete_object(unsigned, 0)


class FakeConn:
    """Conexao fake com os campos que manager/snapshot consomem."""

    def __init__(self, host, port, established=False, started_ago=0.0,
                 connected_ago=None, useful_ago=None):
        now = time.time()
        self.peer = Peer(host, port)
        self.peer_key = (host, port)
        self.established = established
        self.started_at = now - started_ago
        if connected_ago is None:
            self.connected_at = now if established else None
        else:
            self.connected_at = now - connected_ago
        if useful_ago is None:
            self.last_useful_at = None
        else:
            self.last_useful_at = now - useful_ago
        self.their_version = None
        self.their_services = 0
        self.their_streams = []
        self.time_offset = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self.sent = []
        self.closed = False

    def is_alive(self):
        return not self.closed

    def close(self):
        self.closed = True

    def send_packet(self, command, payload=b''):
        self.sent.append((command, bytes(payload)))

    def send_packets(self, command, blobs):
        for blob in blobs:
            self.sent.append((command, bytes(blob)))

    def getdatas(self):
        return [p for c, p in self.sent if c == b'getdata']


def _make_manager(directory, logs=None):
    db = Database(directory)
    manager = NetworkManager(
        directory, db,
        on_log=(lambda *a: (logs.append(a) if logs is not None else None)))
    manager.running = True
    return db, manager


def _fresh_manager(prefix):
    directory = tempfile.mkdtemp(prefix=prefix)
    logs = []
    db, manager = _make_manager(directory, logs)
    manager.peers.entries.clear()
    return directory, logs, db, manager


def _close(directory, db):
    try:
        db.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_handshake_travado_timeout_fecha():
    directory, _logs, db, mgr = _fresh_manager('bmchat-hsto-')
    try:
        host, port = '10.9.0.1', 8444
        mgr.peers.add(host, port)
        conn = FakeConn(host, port, established=False, started_ago=60.0)
        mgr.connections[conn.peer_key] = conn
        evicted = mgr._prune_stalled(time.time())
        assert evicted == 1
        assert conn.closed
        assert conn.peer_key not in mgr.connections
        # Punicao leve (-1), sem banir: ainda elegivel fora do cooldown.
        assert mgr.peers.entries[(host, port)]['rating'] == -1
        assert mgr.peers.best(cooldown=0)
    finally:
        _close(directory, db)


def test_handshake_recente_nao_evictado():
    directory, _logs, db, mgr = _fresh_manager('bmchat-hsok-')
    try:
        conn = FakeConn('10.9.0.2', 8444, established=False, started_ago=2.0)
        mgr.connections[conn.peer_key] = conn
        assert mgr._prune_stalled(time.time()) == 0
        assert not conn.closed
        assert conn.peer_key in mgr.connections
    finally:
        _close(directory, db)


def test_par_mudo_evictado_apos_silencio():
    directory, _logs, db, mgr = _fresh_manager('bmchat-mute-')
    try:
        host, port = '10.9.0.3', 8444
        mgr.peers.add(host, port)
        conn = FakeConn(host, port, established=True, connected_ago=200.0,
                        useful_ago=None)
        mgr.connections[conn.peer_key] = conn
        evicted = mgr._prune_stalled(time.time())
        assert evicted == 1
        assert conn.closed
        assert conn.peer_key not in mgr.connections
        entry = mgr.peers.entries[(host, port)]
        assert entry['rating'] == -2
        assert entry['mute_count'] == 1
    finally:
        _close(directory, db)


def test_par_util_antigo_nao_evictado():
    """Entregou inv ha 400s e esta quieto: saudavel, nao sofre eviccao."""
    directory, _logs, db, mgr = _fresh_manager('bmchat-okq-')
    try:
        conn = FakeConn('10.9.0.4', 8444, established=True,
                        connected_ago=500.0, useful_ago=400.0)
        mgr.connections[conn.peer_key] = conn
        assert mgr._prune_stalled(time.time()) == 0
        assert not conn.closed
    finally:
        _close(directory, db)


def test_par_recem_estabelecido_nao_evictado():
    directory, _logs, db, mgr = _fresh_manager('bmchat-new-')
    try:
        conn = FakeConn('10.9.0.5', 8444, established=True,
                        connected_ago=10.0, useful_ago=None)
        mgr.connections[conn.peer_key] = conn
        assert mgr._prune_stalled(time.time()) == 0
        assert not conn.closed
    finally:
        _close(directory, db)


def test_mudo_nao_banido_para_sempre():
    directory, _logs, db, mgr = _fresh_manager('bmchat-noban-')
    try:
        host, port = '10.9.0.6', 8444
        mgr.peers.add(host, port)
        mgr.peers.record_mute(host, port)
        # Em cooldown some do giro…
        assert (host, port) not in [
            (p.host, p.port) for p, _i in mgr.peers.best()]
        # …mas passado o cooldown volta (nao e ban).
        assert (host, port) in [
            (p.host, p.port) for p, _i in mgr.peers.best(cooldown=0)]
    finally:
        _close(directory, db)


def test_best_prioriza_falante_e_pula_morto_em_cooldown():
    directory, _logs, db, mgr = _fresh_manager('bmchat-best-')
    try:
        now = int(time.time())
        mgr.peers.entries[('10.9.1.1', 8444)] = {
            'stream': 1, 'services': 1, 'last_seen': now, 'rating': -5,
            'last_try': now, 'inv_count': 0, 'last_inv': 0, 'mute_count': 0}
        mgr.peers.entries[('10.9.1.2', 8444)] = {
            'stream': 1, 'services': 1, 'last_seen': now, 'rating': 0,
            'last_try': 0, 'inv_count': 0, 'last_inv': 0, 'mute_count': 0}
        mgr.peers.entries[('10.9.1.3', 8444)] = {
            'stream': 1, 'services': 1, 'last_seen': now, 'rating': 0,
            'last_try': 0, 'inv_count': 4, 'last_inv': now, 'mute_count': 0}
        ordered = [(p.host, p.port) for p, _i in mgr.peers.best()]
        assert ordered[0] == ('10.9.1.3', 8444)
        assert ('10.9.1.1', 8444) not in ordered
    finally:
        _close(directory, db)


def test_record_inv_marca_produtivo():
    directory, _logs, db, mgr = _fresh_manager('bmchat-prod-')
    try:
        mgr.peers.add('10.9.2.1', 8444)
        mgr.peers.add('10.9.2.2', 8444)
        mgr.peers.record_inv('10.9.2.2', 8444)
        ordered = [(p.host, p.port) for p, _i in mgr.peers.best()]
        assert ordered[0] == ('10.9.2.2', 8444)
        assert mgr.peers.entries[('10.9.2.2', 8444)]['inv_count'] == 1
    finally:
        _close(directory, db)


def test_cold_start_gira_rapido_e_quente_nao():
    """6 negociando + boot vazio: 6 tentativas novas (era 1); com
    inventario, o teto volta ao normal (2)."""
    directory, _logs, db, mgr = _fresh_manager('bmchat-burst-')
    try:
        for i in range(10):
            mgr.peers.add('10.9.3.%d' % (10 + i), 8444)
        for i in range(6):
            conn = FakeConn('10.9.3.%d' % i, 8444, established=False)
            mgr.connections[conn.peer_key] = conn
        spawned = []
        mgr.spawn = lambda peer: spawned.append((peer.host, peer.port))
        mgr._ensure_connections()
        assert len(spawned) == 6
        # Quente: mesmo cenario, sem burst.
        mgr.inventory[b'Q' * 32] = b'raw'
        spawned.clear()
        mgr._ensure_connections()
        assert len(spawned) == 2
    finally:
        _close(directory, db)


def test_dns_reresolve_quando_lista_esgota():
    directory, logs, db, mgr = _fresh_manager('bmchat-dns-')
    try:
        now = int(time.time())
        for i in range(3):
            mgr.peers.entries[('10.9.4.%d' % i, 8444)] = {
                'stream': 1, 'services': 1, 'last_seen': now, 'rating': -5,
                'last_try': now, 'inv_count': 0, 'last_inv': 0,
                'mute_count': 0}
        spawned = []
        mgr.spawn = lambda peer: spawned.append((peer.host, peer.port))
        resolved = []
        mgr._resolve_seeds = lambda: resolved.append(True)
        mgr._last_dns_resolve = 0.0
        mgr._ensure_connections()
        assert spawned == []
        assert resolved == [True]
        assert any('sementes DNS' in str(m) for m in logs)
    finally:
        _close(directory, db)


def test_sync_anda_do_zero_com_falante():
    old = manager_mod.is_proof_of_work_sufficient
    manager_mod.is_proof_of_work_sufficient = _fake_pow
    directory, _logs, db, mgr = _fresh_manager('bmchat-synct-')
    try:
        assert mgr._is_cold_start()
        raws = [_make_raw(b'falante-%d' % i) for i in range(2)]
        hashes = [double_sha512(raw)[:32] for raw in raws]
        mgr.peers.add('10.9.5.1', 8444)
        talker = FakeConn('10.9.5.1', 8444, established=True)
        mgr.connections[talker.peer_key] = talker
        mgr.on_inv(talker, packets.assemble_inventory(hashes))
        assert len(talker.getdatas()) == 1
        assert packets.parse_inventory(talker.getdatas()[0]) == hashes
        for raw in raws:
            assert mgr.received_object(raw, talker) is not None
        assert len(mgr.inventory) == 2
        assert not mgr.pending_getdata
        assert talker.last_useful_at is not None
        assert mgr.peers.entries[('10.9.5.1', 8444)]['inv_count'] == 1
        assert not mgr._is_cold_start()
        assert mgr.snapshot()['net_state'] == 'conectado'
    finally:
        manager_mod.is_proof_of_work_sufficient = old
        _close(directory, db)


def _answer_getdatas(mgr, raws_by_hash):
    """Harness: responde getdata do falante com os objetos (via manager)."""
    for conn in list(mgr.connections.values()):
        if not conn.established or conn.closed:
            continue
        pending = conn.getdatas()[conn.__dict__.setdefault('_answered', 0):]
        for payload in pending:
            conn.__dict__['_answered'] = conn.__dict__.get('_answered', 0) + 1
            for obj_hash in packets.parse_inventory(payload):
                raw = raws_by_hash.get(bytes(obj_hash))
                if raw is not None:
                    mgr.received_object(bytes(raw), conn)


def _sim_spawn_factory(mgr, dead, mute_key, talk_key, talk_at, talker_conn):
    def fake_spawn(peer):
        key = (peer.host, peer.port)
        if key in dead:
            mgr.connections[key] = FakeConn(
                peer.host, peer.port, established=False)
        elif key == mute_key:
            mgr.connections[key] = FakeConn(
                peer.host, peer.port, established=True)
        elif key == talk_key and time.time() >= talk_at \
                and not talker_conn:
            conn = FakeConn(peer.host, peer.port, established=True)
            mgr.connections[key] = conn
            talker_conn.append(conn)
        # Falante ainda nao chegou: nao registra nada (sera tentado
        # de novo no proximo giro, sem punicao).
    return fake_spawn


def _sim_feed(mgr, talker_conn, inv_done, hashes, raws_by_hash):
    if talker_conn and not inv_done:
        inv_done.append(True)
        mgr.on_inv(talker_conn[0], packets.assemble_inventory(hashes))
    _answer_getdatas(mgr, raws_by_hash)


def _sim_track(mgr, dead, mute_key, marks, start):
    now = time.time()
    if marks['dead'] is None and all(k not in mgr.connections for k in dead):
        marks['dead'] = now - start
    if marks['mute'] is None and mute_key not in mgr.connections:
        marks['mute'] = now - start
    if len(mgr.inventory) >= 3:
        marks['synced'] = now - start
        return True
    return False


def test_simulacao_6_mortos_1_mudo_1_falante_tardio():
    """6 mortos + 1 mudo + 1 falante tardio: despeja e sincroniza.

    Tempos medidos (timeouts curtos de proposito): handshake 0.3s,
    silencio 0.5s, falante chega em t+0.8s.
    """
    old = manager_mod.is_proof_of_work_sufficient
    manager_mod.is_proof_of_work_sufficient = _fake_pow
    directory, logs, db, mgr = _fresh_manager('bmchat-sim-')
    try:
        mgr.HANDSHAKE_TIMEOUT = 0.3
        mgr.SILENT_TIMEOUT = 0.5
        mgr.BOOT_EXTRA_SLOTS = 4
        mgr.GETDATA_RETRY_DELAY = 0.2
        dead = [('10.10.0.%d' % i, 8444) for i in range(1, 7)]
        mute_key = ('10.10.0.7', 8444)
        talk_key = ('10.10.0.8', 8444)
        for key in dead + [mute_key, talk_key]:
            mgr.peers.add(*key)
        raws = [_make_raw(b'sim-%d' % i) for i in range(3)]
        hashes = [double_sha512(raw)[:32] for raw in raws]
        raws_by_hash = {bytes(h): bytes(r) for h, r in zip(hashes, raws)}

        start = time.time()
        talk_at = start + 0.8
        talker_conn = []
        inv_done = []
        mgr.spawn = _sim_spawn_factory(
            mgr, dead, mute_key, talk_key, talk_at, talker_conn)
        marks = {'dead': None, 'mute': None, 'synced': None}
        deadline = start + 8.0
        while time.time() < deadline:
            mgr._ensure_connections()
            mgr._prune_connections()
            mgr._retry_pending_getdata()
            _sim_feed(mgr, talker_conn, inv_done, hashes, raws_by_hash)
            if _sim_track(mgr, dead, mute_key, marks, start):
                break
            time.sleep(0.02)
        print('\nsim: mortos despejados em %.2fs, mudo em %.2fs, '
              'sync completo em %.2fs'
              % (marks['dead'] or -1, marks['mute'] or -1,
                 marks['synced'] or -1))
        assert marks['dead'] is not None and marks['dead'] < 2.0, \
            'mortos seguraram slot alem do handshake timeout'
        assert marks['mute'] is not None and marks['mute'] < 2.5, \
            'mudo nao foi evictado'
        assert talker_conn, 'falante nunca foi tentado'
        assert marks['synced'] is not None and marks['synced'] < 8.0, \
            'sync nao andou apos o falante chegar'
        assert not mgr.pending_getdata
        assert mgr.stats['invs'] >= 1
        assert mgr.snapshot()['net_state'] == 'conectado'
        assert any('handshake sem resposta' in str(m) for m in logs)
        assert any('silencioso' in str(m) for m in logs)
    finally:
        manager_mod.is_proof_of_work_sufficient = old
        _close(directory, db)


def test_diagnostico_mostra_procurando_e_silencio():
    from bmchat.gui.app import _diagnostics_report, _status_state_part
    directory, _logs, db, mgr = _fresh_manager('bmchat-diag-')
    try:
        report = _diagnostics_report(mgr.snapshot())
        assert 'procurando pares' in report
        snap = mgr.snapshot()
        assert snap['net_state'] == 'procurando-pares'
        assert 'procurando pares' in _status_state_part(snap, 0)
        mgr.connections[('h', 1)] = FakeConn(
            '10.9.6.1', 8444, established=False, started_ago=10.0)
        mgr.connections[('m', 2)] = FakeConn(
            '10.9.6.2', 8444, established=True, connected_ago=100.0,
            useful_ago=None)
        report = _diagnostics_report(mgr.snapshot())
        assert 'handshake há' in report
        assert 'silencioso há' in report
        assert 'aguardando inventário' in _status_state_part(
            mgr.snapshot(), 1)
    finally:
        _close(directory, db)
