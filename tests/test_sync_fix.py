"""Regressão para header 1.6M e sync após wipe."""
import os
import shutil
import socket
import tempfile
import threading
import time

from bmchat.core.database import Database
from bmchat.net.manager import NetworkManager
from bmchat.net.peer import PeerConnection
from bmchat.net.peers import Peer
from bmchat.protocol import packets
from bmchat.protocol.const import MAX_MESSAGE_SIZE
from bmchat.protocol.objects import assemble_object_unsigned, complete_object
from bmchat.util.hashing import double_sha512
import bmchat.net.manager as manager_mod
import bmchat.net.peer as peer_mod


def _fake_pow(*a, **k):
    return True


def _make_raw(tag):
    expires = int(time.time()) + 3600
    unsigned = assemble_object_unsigned(expires, 0, 4, 1, tag)
    return complete_object(unsigned, 0)


def _wait(cond, timeout=20, step=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(step)
    return False


def test_header_aceita_inv_grande():
    """Header deve aceitar até MAX_MESSAGE_SIZE (1.6M), não 262k."""
    assert MAX_MESSAGE_SIZE == 1600100
    src = open(peer_mod.__file__).read()
    assert "MAX_MESSAGE_SIZE" in src
    assert "MAX_OBJECT_LENGTH + 64 + HEADER_SIZE" not in src
    # payload 10000 hashes = 320k deve passar no novo limite
    hashes = [os.urandom(32) for _ in range(10000)]
    payload = packets.assemble_inventory(hashes)
    assert len(payload) == 10000 * 32 + 3  # varint 10000 = 3 bytes
    assert len(payload) > 262232  # old limit rejeitaria
    assert len(payload) <= MAX_MESSAGE_SIZE  # novo aceita


def test_loopback_50_objetos_sync():  # noqa: C901
    old = manager_mod.is_proof_of_work_sufficient
    manager_mod.is_proof_of_work_sufficient = _fake_pow
    root = tempfile.mkdtemp(prefix="bmchat-fix50-")
    try:
        os.makedirs(root + "/a")
        os.makedirs(root + "/b")
        db_a = Database(root + "/a")
        db_b = Database(root + "/b")
        mgr_a = NetworkManager(root + "/a", db_a, on_log=lambda *a: None)
        mgr_b = NetworkManager(root + "/b", db_b, on_log=lambda *a: None)
        for mgr in (mgr_a, mgr_b):
            mgr.streams = [1]
            mgr.running = True
            mgr.peers.entries.clear()
            mgr.HANDSHAKE_TIMEOUT = 5
            mgr.SILENT_TIMEOUT = 60
            mgr.GETDATA_RETRY_DELAY = 1

        for i in range(50):
            raw = _make_raw(b"fix-%d" % i)
            h = double_sha512(raw)[:32]
            db_a.store_object(h, raw, 0, 4, 1, int(time.time()) + 3600)
            mgr_a.inventory[h] = raw
            mgr_a.known_hashes.add(h)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        port = listener.getsockname()[1]
        stop = threading.Event()

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
                inc = PeerConnection(mgr_a, Peer("127.0.0.1", port), sock=sock)
                mgr_a.connections[inc.peer_key] = inc
                inc.start()

        threading.Thread(target=server, daemon=True).start()

        def maint():
            while not stop.is_set():
                try:
                    mgr_b._ensure_connections()
                    mgr_b._prune_connections()
                    mgr_b._retry_pending_getdata()
                except Exception:
                    pass
                stop.wait(0.2)

        threading.Thread(target=maint, daemon=True).start()
        mgr_b.peers.add("127.0.0.1", port, stream=1, services=1)
        mgr_b.spawn(Peer("127.0.0.1", port))
        start = time.time()
        ok = _wait(lambda: len(mgr_b.inventory) >= 50, timeout=30)
        elapsed = time.time() - start
        assert ok, "sync 50 falhou em %.2fs" % elapsed
        assert elapsed < 30, "sync 50 lento %.2fs" % elapsed

        # wipe e re-sync
        mgr_b.wipe_objects()
        assert len(mgr_b.inventory) == 0
        start2 = time.time()
        ok2 = _wait(lambda: len(mgr_b.inventory) >= 50, timeout=40)
        elapsed2 = time.time() - start2
        assert ok2, "re-sync após wipe falhou"
        assert elapsed2 < 40
        stop.set()
        listener.close()
        mgr_a.running = False
        mgr_b.running = False
        for c in list(mgr_a.connections.values()) + list(mgr_b.connections.values()):
            try:
                c.close()
            except Exception:
                pass
        db_a.close()
        db_b.close()
    finally:
        manager_mod.is_proof_of_work_sufficient = old
        shutil.rmtree(root, ignore_errors=True)
