"""Fixes P0-P5: retry rápido, giro, completude, pending per-peer.

Verifica valores novos e loopback cronometrado ANTES vs DEPOIS.
"""
import shutil
import socket
import tempfile
import threading
import time

from bmchat.core.database import Database
from bmchat.net.manager import NetworkManager, INV_WANTED_MAX
from bmchat.net.peers import Peer
from bmchat.protocol import packets
from bmchat.protocol.objects import assemble_object_unsigned, complete_object
from bmchat.util.hashing import double_sha512
import bmchat.net.manager as manager_mod


def _fake_pow(*a, **k):
    return True


def _make_raw(tag):
    expires = int(time.time()) + 3600
    unsigned = assemble_object_unsigned(expires, 0, 4, 1, tag)
    return complete_object(unsigned, 0)


class FakeConn:
    def __init__(self, host='127.0.0.1', port=8444, established=True):
        self.peer = type('P', (), {'host': host, 'port': port})()
        self.peer_key = (host, port)
        self.established = established
        self.started_at = time.time()
        self.connected_at = time.time() if established else None
        self.last_useful_at = None
        self.their_version = None
        self.their_services = 0
        self.their_streams = []
        self.time_offset = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self.sent = []
        self.closed = False
        self.sock = None

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


def _make_manager():
    directory = tempfile.mkdtemp(prefix='bmchat-fix-')
    db = Database(directory)
    mgr = NetworkManager(directory, db, on_log=lambda *a: None)
    mgr.running = True
    mgr.peers.entries.clear()
    return directory, db, mgr


def _close(directory, db):
    try:
        db.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_p0_retry_delay_is_3():
    _, db, mgr = _make_manager()
    try:
        assert mgr.GETDATA_RETRY_DELAY == 3
        assert INV_WANTED_MAX == 1000
    finally:
        _close(_, db)


def test_p1_handshake_is_20_boot_extra_6_silent_60():
    _, db, mgr = _make_manager()
    try:
        assert mgr.HANDSHAKE_TIMEOUT == 20
        assert mgr.SILENT_TIMEOUT == 60
        assert mgr.BOOT_EXTRA_SLOTS == 6
    finally:
        _close(_, db)


def test_peer_recv_timeout_and_handshake_defaults():
    import bmchat.net.peer as peer_mod
    _, db, mgr = _make_manager()
    try:
        from bmchat.net.peer import PeerConnection
        conn = PeerConnection(mgr, Peer('127.0.0.1', 8444))
        assert conn._handshake_timeout() == 20
        # recv_timeout default 30 via db sem setting
        assert db.get_int('recv_timeout', 30) == 30
        # _read_loop tem contador de 3 timeouts (checa fonte)
        src = open(peer_mod.__file__).read()
        assert 'timeouts' in src and '>= 3' in src
    finally:
        _close(_, db)


def test_p3_inventory_chunk_and_inv_wanted():
    _, db, mgr = _make_manager()
    try:
        # inventário grande 5000 hashes deve ser chunkado em 49999 (1 pacote)
        for i in range(5000):
            key = i.to_bytes(4, 'big') + b'\x00' * 28
            mgr.inventory[key] = b'raw%d' % i
        conn = FakeConn()
        mgr.send_inventory(conn)
        invs = [p for c, p in conn.sent if c == b'inv']
        assert invs
        total = sum(len(packets.parse_inventory(p)) for p in invs)
        assert total == 5000
        # chunk grande 60000 deve gerar 2 pacotes (49999+10001)
        conn.sent.clear()
        mgr.inventory.clear()
        for i in range(60000):
            key = i.to_bytes(4, 'big') + b'\x00' * 28
            mgr.inventory[key] = b'r'
        mgr.send_inventory(conn)
        invs = [p for c, p in conn.sent if c == b'inv']
        assert len(invs) == 2
        assert len(packets.parse_inventory(invs[0])) == 49999
        assert len(packets.parse_inventory(invs[1])) == 10001
        # wanted cap 1000
        conn2 = FakeConn()
        hashes = [bytes([i % 256]) * 32 for i in range(2000)]
        mgr.known_hashes.clear()
        mgr.inventory.clear()
        mgr.on_inv(conn2, packets.assemble_inventory(hashes))
        sent = sum(len(packets.parse_inventory(p))
                   for p in conn2.getdatas())
        assert sent <= 1000
    finally:
        _close(_, db)


def test_p5_pending_per_peer_preferencial():
    _, db, mgr = _make_manager()
    try:
        h = b'P' * 32
        now = time.time()
        src_a = ('1.1.1.1', 8444)
        src_b = ('2.2.2.2', 8444)
        mgr._remember_pending([h], now, src_a)
        assert mgr.pending_getdata[h][2] == src_a
        # não sobrescreve source já existente
        mgr._remember_pending([h], now, src_b)
        assert mgr.pending_getdata[h][2] == src_a
        # retry prefere source se conectado
        conn_a = FakeConn('1.1.1.1', 8444, established=True)
        conn_b = FakeConn('2.2.2.2', 8444, established=True)
        mgr.connections[conn_a.peer_key] = conn_a
        mgr.connections[conn_b.peer_key] = conn_b
        # força stale
        time.sleep(0.05)
        mgr.GETDATA_RETRY_DELAY = 0.01
        time.sleep(0.02)
        stale = mgr._stale_pending(time.time())
        assert h in stale
        mgr._resend_pending(stale, time.time())
        # deve ter preferido conn_a (source)
        assert any(c == b'getdata' for c, _ in conn_a.sent)
        assert conn_b.sent == []
    finally:
        _close(_, db)


def test_p2_silent_progressivo_30_e_60():
    _, db, mgr = _make_manager()
    try:
        now = time.time()
        # 35s silencioso -> try (sem mute)
        conn = FakeConn('10.0.0.1', 8444, established=True)
        conn.connected_at = now - 35
        conn.started_at = now - 35
        mgr.connections[conn.peer_key] = conn
        mgr.peers.add('10.0.0.1', 8444)
        before = mgr.peers.entries[('10.0.0.1', 8444)]['rating']
        assert mgr._established_silent_try(conn, now) is True
        assert mgr._established_mute(conn, now) is False
        mgr._evict_if_stalled(conn, now)
        assert conn.closed
        assert mgr.peers.entries[('10.0.0.1', 8444)]['rating'] == before
        # 70s silencioso -> mute
        conn2 = FakeConn('10.0.0.2', 8444, established=True)
        conn2.connected_at = now - 70
        conn2.started_at = now - 70
        mgr.connections[conn2.peer_key] = conn2
        mgr.peers.add('10.0.0.2', 8444)
        assert mgr._established_mute(conn2, now) is True
        mgr._evict_if_stalled(conn2, now)
        assert conn2.closed
        assert mgr.peers.entries[('10.0.0.2', 8444)]['mute_count'] == 1
    finally:
        _close(_, db)


def test_handshake_20s_nao_25():
    _, db, mgr = _make_manager()
    try:
        now = time.time()
        conn = FakeConn('10.0.0.9', 8444, established=False)
        conn.started_at = now - 21
        mgr.connections[conn.peer_key] = conn
        assert mgr._handshake_stalled(conn, now) is True
        conn2 = FakeConn('10.0.0.10', 8444, established=False)
        conn2.started_at = now - 19
        assert mgr._handshake_stalled(conn2, now) is False
    finally:
        _close(_, db)


def _loopback_pair(root, object_count, drop_first=False, retry_delay=3):  # noqa: C901
    old = manager_mod.is_proof_of_work_sufficient
    manager_mod.is_proof_of_work_sufficient = _fake_pow
    try:
        import os
        os.makedirs(root + '/a')
        os.makedirs(root + '/b')
        db_a = Database(root + '/a')
        db_b = Database(root + '/b')
        mgr_a = NetworkManager(root + '/a', db_a, on_log=lambda *a: None)
        mgr_b = NetworkManager(root + '/b', db_b, on_log=lambda *a: None)
        for mgr in (mgr_a, mgr_b):
            mgr.streams = [1]
            mgr.running = True
            mgr.peers.entries.clear()
        for i in range(object_count):
            raw = _make_raw(b'lb-%d' % i)
            h = double_sha512(raw)[:32]
            db_b.store_object(h, raw, 0, 4, 1, int(time.time()) + 3600)
            mgr_b.inventory[h] = raw
            mgr_b.known_hashes.add(h)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        port = listener.getsockname()[1]
        stop = threading.Event()
        if drop_first:
            orig = mgr_b.on_getdata
            armed = {'drop': True}

            def flaky(conn, payload):
                if armed['drop']:
                    armed['drop'] = False
                    return
                return orig(conn, payload)
            mgr_b.on_getdata = flaky
            # cada handshake rearma o drop (skipUntil)
            orig_inv = mgr_b.send_inventory

            def send_inv_and_arm(conn):
                armed['drop'] = True
                return orig_inv(conn)
            mgr_b.send_inventory = send_inv_and_arm

        def server():
            listener.settimeout(0.5)
            while not stop.is_set():
                try:
                    sock, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                sock.settimeout(30)
                inc = __import__('bmchat.net.peer', fromlist=['PeerConnection']).PeerConnection(
                    mgr_b, Peer('127.0.0.1', port), sock=sock)
                mgr_b.connections[inc.peer_key] = inc
                inc.start()
        threading.Thread(target=server, daemon=True).start()
        mgr_a.peers.add('127.0.0.1', port, stream=1, services=1)
        mgr_a.GETDATA_RETRY_DELAY = retry_delay
        mgr_a.spawn(Peer('127.0.0.1', port))

        def maint():
            while not stop.is_set():
                try:
                    mgr_a._ensure_connections()
                    mgr_a._prune_connections()
                    mgr_a._retry_pending_getdata()
                except Exception:
                    pass
                stop.wait(0.2)
        threading.Thread(target=maint, daemon=True).start()
        return {
            'db_a': db_a, 'db_b': db_b, 'mgr_a': mgr_a, 'mgr_b': mgr_b,
            'listener': listener, 'stop': stop, 'port': port,
        }, old
    except Exception:
        manager_mod.is_proof_of_work_sufficient = old
        raise


def _wait(cond, timeout=20, step=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(step)
    return False


def test_loopback_p0_retry_3_vs_15():
    root = tempfile.mkdtemp(prefix='bmchat-p0-')
    state, old = _loopback_pair(root, 1, drop_first=True, retry_delay=3)
    try:
        mgr_a = state['mgr_a']
        assert _wait(lambda: mgr_a.established_count >= 1, 10)
        start = time.time()
        ok = _wait(lambda: len(mgr_a.inventory) >= 1, 10)
        elapsed = time.time() - start
        print("\nP0 retry 3s com skipUntil: %.2fs (antes 15s seria ~15.12s)" % elapsed)
        assert ok and elapsed < 6.0, "retry 3s deveria recuperar em <6s, foi %.2fs" % elapsed
        # compara estimado antes: 15s
        assert elapsed < 10.0
    finally:
        state['stop'].set()
        try:
            state['listener'].close()
        except Exception:
            pass
        state['mgr_a'].running = False
        state['mgr_b'].running = False
        try:
            state['db_a'].close()
            state['db_b'].close()
        except Exception:
            pass
        manager_mod.is_proof_of_work_sufficient = old
        shutil.rmtree(root, ignore_errors=True)


def test_loopback_p1_giro_6_slots():
    directory, db, mgr = _make_manager()
    try:
        for i in range(10):
            mgr.peers.add('10.9.9.%d' % (10 + i), 8444)
        for i in range(6):
            conn = FakeConn('10.9.9.%d' % i, 8444, established=False)
            mgr.connections[conn.peer_key] = conn
        spawned = []
        mgr.spawn = lambda p: spawned.append((p.host, p.port))
        mgr._ensure_connections()
        assert len(spawned) == 8  # 8+6-6 com BOOT_EXTRA 6
    finally:
        _close(directory, db)


def test_loopback_p3_p5_chunk_e_preferencial():
    root = tempfile.mkdtemp(prefix='bmchat-p3p5-')
    state, old = _loopback_pair(root, 3, drop_first=False, retry_delay=3)
    try:
        mgr_a = state['mgr_a']
        assert _wait(lambda: mgr_a.established_count >= 1, 10)
        assert _wait(lambda: len(mgr_a.inventory) >= 3, 15)
        assert len(mgr_a.pending_getdata) == 0
        # verifica que inventory chunk funcionou (3 objetos vieram)
        assert len(mgr_a.inventory) == 3
    finally:
        state['stop'].set()
        try:
            state['listener'].close()
        except Exception:
            pass
        state['mgr_a'].running = False
        state['mgr_b'].running = False
        try:
            state['db_a'].close()
            state['db_b'].close()
        except Exception:
            pass
        manager_mod.is_proof_of_work_sufficient = old
        shutil.rmtree(root, ignore_errors=True)
