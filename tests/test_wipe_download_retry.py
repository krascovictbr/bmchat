"""Re-download apos wipe contra pares REAIS (nao so fakes dos dois lados).

Causa raiz (evidencia no PyBitmessage de referencia em
/home/artix/PyBitmessage/src):
- tcp.py set_connection_fully_established: o par re-anuncia o inventario
  inteiro (sendBigInv) no handshake novo — reconectar e util;
- tcp.py antiIntersectionDelay + bmproto.py bm_command_getdata: o par
  real IGNORA getdata por alguns segundos apos o handshake (skipUntil);
- downloadthread.py: a referencia REPETE o getdata via missingObjects.

Nosso manager pedia uma unica vez em on_inv e nunca repetia: todo o
lote pos-wipe caia na janela de descarte do par real e nada voltava.
A simulacao antiga passou a toa porque usava nosso manager nos dois
lados (sem skipUntil) e injetava o re-inv a mao, sem handshake real.

Estes testes travam a correcao: pending_getdata + _retry_pending_getdata,
prioridade de re-sync furando o cooldown e o pop com identidade.
"""
import shutil
import socket
import tempfile
import threading
import time

from bmchat.core.database import Database
from bmchat.net.manager import NetworkManager
import bmchat.net.manager as manager_mod
from bmchat.net.peer import PeerConnection
from bmchat.net.peers import Peer
from bmchat.protocol import packets
from bmchat.protocol.objects import (
    assemble_object_unsigned, complete_object,
)
from bmchat.util.hashing import double_sha512


REAL_POW_CHECK = manager_mod.is_proof_of_work_sufficient


def _fake_pow(*args, **kwargs):
    return True


def _make_raw(tag):
    expires = int(time.time()) + 3600
    unsigned = assemble_object_unsigned(expires, 0, 4, 1, tag)
    return complete_object(unsigned, 0)


class FakeConn:
    established = True

    def __init__(self, host='127.0.0.1', port=8444):
        self.peer = type('Peer', (), {'host': host, 'port': port})()
        self.peer_key = (host, port)
        self.sent = []
        self.closed = False

    def send_packet(self, command, payload=b''):
        self.sent.append((command, bytes(payload)))

    def send_packets(self, command, blobs):
        for blob in blobs:
            self.sent.append((command, bytes(blob)))

    def close(self):
        self.closed = True


def _make_manager(directory, logs=None):
    db = Database(directory)
    manager = NetworkManager(
        directory, db,
        on_log=(lambda *a: (logs.append(a) if logs is not None else None)))
    return db, manager


def _getdatas(conn):
    return [p for c, p in conn.sent if c == b'getdata']


def test_getdata_repetido_enquanto_objeto_nao_chega():
    directory = tempfile.mkdtemp(prefix='bmchat-retry-')
    try:
        db, mgr = _make_manager(directory)
        mgr.GETDATA_RETRY_DELAY = 0.05
        target = b'R' * 32
        conn = FakeConn()
        mgr.connections[conn.peer_key] = conn
        mgr.on_inv(conn, packets.assemble_inventory([target]))
        assert len(_getdatas(conn)) == 1
        assert target in mgr.pending_getdata
        time.sleep(0.08)
        mgr._retry_pending_getdata()
        assert len(_getdatas(conn)) == 2
        assert packets.parse_inventory(_getdatas(conn)[1]) == [target]
        db.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_objeto_recebido_limpa_pendente_e_cala_retry():
    directory = tempfile.mkdtemp(prefix='bmchat-retry-done-')
    old = manager_mod.is_proof_of_work_sufficient
    manager_mod.is_proof_of_work_sufficient = _fake_pow
    try:
        db, mgr = _make_manager(directory)
        mgr.GETDATA_RETRY_DELAY = 0.05
        raw = _make_raw(b'chegou')
        obj_hash = double_sha512(raw)[:32]
        conn = FakeConn()
        mgr.connections[conn.peer_key] = conn
        mgr.on_inv(conn, packets.assemble_inventory([obj_hash]))
        assert len(_getdatas(conn)) == 1
        assert mgr.received_object(raw, conn) == obj_hash
        assert obj_hash not in mgr.pending_getdata
        conn.sent.clear()
        time.sleep(0.08)
        mgr._retry_pending_getdata()
        assert _getdatas(conn) == []
        db.close()
    finally:
        manager_mod.is_proof_of_work_sufficient = old
        shutil.rmtree(directory, ignore_errors=True)


def test_retry_recupera_getdata_descartado_como_par_real_faz():
    """Modelo fiel do skipUntil: o 1o getdata e descartado, o 2o serve."""
    directory = tempfile.mkdtemp(prefix='bmchat-skip-')
    old = manager_mod.is_proof_of_work_sufficient
    manager_mod.is_proof_of_work_sufficient = _fake_pow
    try:
        db_holder = Database(tempfile.mkdtemp(prefix='bmchat-skip-h-'))
        holder = NetworkManager(tempfile.mkdtemp(prefix='bmchat-skip-h2-'),
                                db_holder)
        db, mgr = _make_manager(directory)
        mgr.GETDATA_RETRY_DELAY = 0.05
        raw = _make_raw(b'skip-until-model')
        obj_hash = double_sha512(raw)[:32]
        holder.inventory[obj_hash] = raw

        class HolderConn(FakeConn):
            drops_left = 1

            def send_packets(self, command, blobs):
                # par real servindo o objeto (lado holder -> requester)
                for blob in blobs:
                    assert mgr.received_object(bytes(blob), conn) is not None

        conn = FakeConn()
        mgr.connections[conn.peer_key] = conn
        holder_conn = HolderConn()
        # 1o getdata: par real descarta (skipUntil) — holder nao responde.
        mgr.on_inv(conn, packets.assemble_inventory([obj_hash]))
        assert len(_getdatas(conn)) == 1
        assert obj_hash not in mgr.inventory
        # retry dispara o 2o getdata; desta vez o holder responde.
        time.sleep(0.08)
        mgr._retry_pending_getdata()
        assert len(_getdatas(conn)) == 2
        holder.on_getdata(holder_conn, _getdatas(conn)[1])
        assert obj_hash in mgr.inventory
        assert obj_hash not in mgr.pending_getdata
        db.close()
        db_holder.close()
    finally:
        manager_mod.is_proof_of_work_sufficient = old
        shutil.rmtree(directory, ignore_errors=True)


def test_resync_prioriza_par_derrubado_mesmo_em_cooldown():
    directory = tempfile.mkdtemp(prefix='bmchat-resync-prio-')
    try:
        db, mgr = _make_manager(directory)
        mgr.running = True
        key = ('127.0.0.1', 8444)
        now = int(time.time())
        mgr.peers.entries[key] = {
            'stream': 1, 'services': 1, 'last_seen': now,
            'rating': -5, 'last_try': now}
        with mgr.lock:
            mgr.resync['active'] = True
            mgr.resync['dropped'] = [key]
        spawned = []
        mgr.spawn = lambda peer: spawned.append((peer.host, peer.port))
        try:
            mgr._ensure_connections()
        finally:
            mgr.running = False
        assert (key[0], key[1]) in spawned
        db.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_conexao_velha_nao_orfana_conexao_nova_mesma_chave():
    directory = tempfile.mkdtemp(prefix='bmchat-poprace-')
    try:
        db, mgr = _make_manager(directory)
        peer = Peer('127.0.0.1', 1)  # porta fechada: connect falha rapido
        old_conn = PeerConnection(mgr, peer)
        new_conn = PeerConnection(mgr, peer)
        mgr.connections[new_conn.peer_key] = new_conn
        old_conn.run()  # falha (nao estabelecido) e sai pelo finally
        assert mgr.connections.get(new_conn.peer_key) is new_conn
        db.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _wait(condition, timeout=30, step=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(step)
    return False


def _seed_holder(db_b, mgr_b, object_count):
    for i in range(object_count):
        raw = _make_raw(b'loop-%d' % i)
        obj_hash = double_sha512(raw)[:32]
        db_b.store_object(obj_hash, raw, 0, 4, 1, int(time.time()) + 3600)
        mgr_b.inventory[obj_hash] = raw
        mgr_b.known_hashes.add(obj_hash)


def _arm_skipuntil_drop(mgr_b):
    original = mgr_b.on_getdata
    original_inv = mgr_b.send_inventory
    armed = {'drop_next': False}

    def send_inv_and_arm(conn):
        # Cada handshake novo re-anuncia o inventario; o par real
        # descarta o getdata imediato (skipUntil). Modela isso
        # descartando o 1o getdata apos cada inv de handshake.
        armed['drop_next'] = True
        return original_inv(conn)

    def flaky(conn, payload):
        if armed['drop_next']:
            armed['drop_next'] = False
            return
        return original(conn, payload)

    mgr_b.send_inventory = send_inv_and_arm
    mgr_b.on_getdata = flaky


def _run_helper_server(mgr_b, listener, port, stop):
    def server():
        listener.settimeout(0.5)
        while not stop.is_set():
            try:
                sock, _addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            sock.settimeout(60)
            incoming = PeerConnection(
                mgr_b, Peer('127.0.0.1', port), sock=sock)
            mgr_b.connections[incoming.peer_key] = incoming
            incoming.start()

    threading.Thread(target=server, daemon=True).start()


def _drive_maintenance(mgr_a, maint_stop):
    def maintenance():
        while not maint_stop.is_set():
            try:
                mgr_a._ensure_connections()
                mgr_a._prune_connections()
                mgr_a._retry_pending_getdata()
                mgr_a._update_resync()
            except Exception:
                pass
            maint_stop.wait(1.0)

    threading.Thread(target=maintenance, daemon=True).start()


def _loopback_pair(root, object_count, drop_first_getdata=False):
    import os
    old = manager_mod.is_proof_of_work_sufficient
    manager_mod.is_proof_of_work_sufficient = _fake_pow
    state = {}

    def restore():
        manager_mod.is_proof_of_work_sufficient = old

    try:
        os.makedirs(root + '/a')
        os.makedirs(root + '/b')
        db_a = Database(root + '/a')
        db_b = Database(root + '/b')
        mgr_a = NetworkManager(root + '/a', db_a,
                               on_log=lambda *a: None)
        mgr_b = NetworkManager(root + '/b', db_b,
                               on_log=lambda *a: None)
        for mgr in (mgr_a, mgr_b):
            mgr.streams = [1]
            mgr.running = True
            mgr.peers.entries.clear()
        _seed_holder(db_b, mgr_b, object_count)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        port = listener.getsockname()[1]
        stop = threading.Event()

        if drop_first_getdata:
            _arm_skipuntil_drop(mgr_b)
        _run_helper_server(mgr_b, listener, port, stop)
        mgr_a.peers.add('127.0.0.1', port, stream=1, services=1)
        mgr_a.GETDATA_RETRY_DELAY = 1
        mgr_a.spawn(Peer('127.0.0.1', port))
        # Aciona a manutencao como o app real faz via start(): sem isso
        # _retry_pending_getdata nunca rodaria neste harness manual.
        maint_stop = threading.Event()
        _drive_maintenance(mgr_a, maint_stop)
        state.update(db_a=db_a, db_b=db_b, mgr_a=mgr_a, mgr_b=mgr_b,
                     listener=listener, stop=stop, maint_stop=maint_stop)
        return state
    except Exception:
        restore()
        raise


def _loopback_close(state):
    try:
        state['stop'].set()
        state.get('maint_stop', threading.Event()).set()
        state['listener'].close()
        state['mgr_a'].running = False
        state['mgr_b'].running = False
        for conn in list(state['mgr_a'].connections.values()) + list(
                state['mgr_b'].connections.values()):
            try:
                conn.close()
            except Exception:
                pass
        state['db_a'].close()
        state['db_b'].close()
    finally:
        manager_mod.is_proof_of_work_sufficient = REAL_POW_CHECK


def test_loopback_wipe_recupera_com_tempo_medido():
    root = tempfile.mkdtemp(prefix='bmchat-loop-')
    state = _loopback_pair(root, 3)
    try:
        mgr_a = state['mgr_a']
        assert _wait(lambda: mgr_a.established_count >= 1, 20)
        assert _wait(lambda: len(mgr_a.inventory) >= 3, 30)
        pre_wipe = list(mgr_a.connections.values())
        start = time.time()
        assert mgr_a.wipe_objects() == 3
        assert all(getattr(c, '_closing', True) for c in pre_wipe), \
            'wipe deveria fechar as conexoes antigas'
        assert _wait(lambda: len(mgr_a.connections) >= 1, 60)
        reconnection = time.time() - start
        assert _wait(lambda: len(mgr_a.inventory) >= 3, 60)
        total = time.time() - start
        print('\nloopback: reconexao em %.2fs, re-download total em %.2fs'
              % (reconnection, total))
        assert reconnection < 60
        assert total < 60
    finally:
        _loopback_close(state)
        shutil.rmtree(root, ignore_errors=True)


def test_loopback_wipe_sobrevive_a_descarte_do_primeiro_getdata():
    """Par real descarta o getdata pos-handshake; o retry tem que salvar."""
    root = tempfile.mkdtemp(prefix='bmchat-loop-skip-')
    state = _loopback_pair(root, 3, drop_first_getdata=True)
    try:
        mgr_a = state['mgr_a']
        assert _wait(lambda: mgr_a.established_count >= 1, 20)
        # sync inicial perde o 1o lote de propósito; o retry recupera.
        assert _wait(lambda: len(mgr_a.inventory) >= 3, 60), \
            'sem retry, o descarte do 1o getdata seria permanente'
        start = time.time()
        assert mgr_a.wipe_objects() == 3
        assert _wait(lambda: len(mgr_a.inventory) >= 3, 90), \
            'pos-wipe com descarte: retry nao recuperou'
        total = time.time() - start
        print('\nloopback com descarte: re-download em %.2fs' % total)
    finally:
        _loopback_close(state)
        shutil.rmtree(root, ignore_errors=True)
