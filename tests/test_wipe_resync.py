"""Re-sync após "Apagar objetos": wipe derruba conexões e rebaixa tudo.

Causa raiz (ver NetworkManager.wipe_objects): o protocolo não tem
mensagem "me mande seu inventário"; pares só enviam inv no handshake
e ao receber objeto novo. Sem derrubar as conexões, pares já
conectados nunca reenviariam os invs antigos e o nó ficava parado.
"""
import shutil
import tempfile
import time

from bmchat.core.database import Database
from bmchat.net.manager import NetworkManager
from bmchat.protocol import packets


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


def test_wipe_forca_resync_e_redownload_via_reinv():
    directory = tempfile.mkdtemp(prefix='bmchat-wipe-resync-')
    logs = []
    try:
        db, mgr = _make_manager(directory, logs)
        hash_a, hash_b = b'A' * 32, b'B' * 32
        db.store_object(
            hash_a, b'RAW-A', 2, 1, 1, int(time.time()) + 3600)
        db.store_object(
            hash_b, b'RAW-B', 2, 1, 1, int(time.time()) + 3600)
        mgr._load_known_hashes()
        mgr.inventory[hash_a] = b'RAW-A'
        mgr.inventory[hash_b] = b'RAW-B'
        conn = FakeConn()
        mgr.connections[conn.peer_key] = conn
        # Sem re-inv nada chega: prova do stall original.
        assert conn.sent == []

        removed = mgr.wipe_objects()

        assert removed == 2
        assert len(mgr.inventory) == 0
        assert len(mgr.known_hashes) == 0
        rows = db.query('SELECT COUNT(*) AS n FROM objects')
        assert rows[0]['n'] == 0
        # Re-sync: derruba conexões para o maintenance reconectar e
        # os pares re-anunciarem no handshake novo.
        assert len(mgr.connections) == 0
        assert conn.closed is True
        assert any('Baixando tudo de novo' in str(m) for _, m in logs)
        # Peer reconectado re-anuncia os invs antigos -> baixa de novo.
        fresh = FakeConn(port=8445)
        mgr.on_inv(
            fresh, packets.assemble_inventory([hash_a, hash_b]))
        getdatas = [p for c, p in fresh.sent if c == b'getdata']
        assert getdatas, 'após wipe, re-inv deveria disparar getdata'
        wanted = packets.parse_inventory(getdatas[0])
        assert set(wanted) == {hash_a, hash_b}
        # Nada local para re-anunciar: getdata após wipe responde vazio.
        fresh.sent.clear()
        mgr.on_getdata(fresh, packets.assemble_getdata([hash_a]))
        assert [c for c, _ in fresh.sent if c == b'object'] == []
        db.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_wipe_derruba_conexoes_e_agenda_reconexao():
    directory = tempfile.mkdtemp(prefix='bmchat-wipe-kick-')
    logs = []
    try:
        db, mgr = _make_manager(directory, logs)
        conn = FakeConn()
        mgr.connections[conn.peer_key] = conn
        mgr.running = True
        called = []
        mgr._ensure_connections = lambda: called.append(True)
        try:
            assert mgr.wipe_objects() == 0
        finally:
            mgr.running = False
        assert conn.closed is True
        assert len(mgr.connections) == 0
        deadline = time.time() + 5
        while time.time() < deadline and not called:
            time.sleep(0.05)
        assert called, 'wipe deveria agendar _ensure_connections'
        db.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_wipe_restart_sincroniza_tudo_do_zero():
    directory = tempfile.mkdtemp(prefix='bmchat-wipe-restart-')
    try:
        db, mgr = _make_manager(directory)
        hash_a = b'C' * 32
        db.store_object(
            hash_a, b'RAW-C', 2, 1, 1, int(time.time()) + 3600)
        mgr._load_known_hashes()
        assert hash_a in mgr.known_hashes
        assert mgr.wipe_objects() == 1
        db.close()
        # "Fecha e reabre": boot com inventário vazio.
        db2 = Database(directory)
        try:
            mgr2 = NetworkManager(directory, db2)
            mgr2._prune_expired_objects()
            mgr2._load_known_hashes()
            assert len(mgr2.known_hashes) == 0
            assert len(mgr2.inventory) == 0
            conn = FakeConn()
            # Handshake novo: par anuncia tudo e o nó pede tudo.
            mgr2.on_inv(
                conn, packets.assemble_inventory([hash_a, b'D' * 32]))
            getdatas = [p for c, p in conn.sent if c == b'getdata']
            assert getdatas, 'boot vazio deveria pedir invs do par'
            wanted = packets.parse_inventory(getdatas[0])
            assert set(wanted) == {hash_a, b'D' * 32}
        finally:
            db2.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_wipe_nao_toca_mensagens_contatos_identidades_chaves():
    directory = tempfile.mkdtemp(prefix='bmchat-wipe-keep-')
    try:
        db, mgr = _make_manager(directory)
        db.add_identity(
            'BM-teste-identidade', 'Eu', 1, b's' * 32, b'e' * 32)
        db.add_contact('BM-teste-contato', 'Amigo', 1)
        db.add_subscription('BM-teste-canal', 'Canal')
        db.add_message(
            None, 'BM-teste-identidade', 'BM-teste-contato', 'oi',
            'corpo', 2, int(time.time()), 'out', 'sent')
        db.store_pubkey('BM-teste-contato', b's' * 65, b'e' * 65)
        db.store_object(
            b'E' * 32, b'RAW-E', 2, 1, 1, int(time.time()) + 3600)
        mgr._load_known_hashes()
        mgr.inventory[b'E' * 32] = b'RAW-E'

        assert mgr.wipe_objects() == 1

        assert db.query('SELECT COUNT(*) AS n FROM objects')[0]['n'] == 0
        assert len(mgr.inventory) == 0
        assert len(mgr.known_hashes) == 0
        assert db.all_identities() != []
        assert db.all_contacts() != []
        assert db.all_subscriptions() != []
        assert db.recent_messages() != []
        assert db.get_pubkey('BM-teste-contato') is not None
        db.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
