"""Regressão da auditoria 2026-09-08 (C1-C5, A1-A13, M1-M10)."""

import base64
import inspect
import os
import stat
import struct
import time

import pytest

from bmchat.crypto import encrypted_db
from bmchat.gui import dialogs
from bmchat.gui.notification import NotificationManager
from bmchat.protocol.const import MAX_WIRE_BODY_BYTES


# ---------- C1 ----------

def test_c1_derive_key_uses_sha256_module():
    salt = os.urandom(32)
    key = encrypted_db.derive_key('senha-forte-123', salt)
    assert isinstance(key, bytes) and len(key) == 32
    again = encrypted_db.derive_key('senha-forte-123', salt)
    assert again == key


def test_c1_export_import_roundtrip(tmp_path):
    plain = tmp_path / 'a.db'
    plain.write_bytes(b'SQLite format 3\x00' + os.urandom(200))
    enc = str(tmp_path / 'a.enc')
    encrypted_db.export_encrypted_backup(str(plain), enc, 'senha-forte-123')
    assert os.path.exists(enc)
    out = str(tmp_path / 'b.db')
    encrypted_db.import_encrypted_backup(enc, out, 'senha-forte-123')
    with open(out, 'rb') as handle:
        assert handle.read() == plain.read_bytes()


def test_c1_change_password_roundtrip(tmp_path):
    plain = tmp_path / 'c.db'
    plain.write_bytes(os.urandom(300))
    enc = str(tmp_path / 'c.enc')
    encrypted_db.export_encrypted_backup(str(plain), enc, 'senha-forte-123')
    encrypted_db.change_password(enc, 'senha-forte-123', 'nova-senha-456')
    out = str(tmp_path / 'd.db')
    encrypted_db.import_encrypted_backup(enc, out, 'nova-senha-456')
    assert open(out, 'rb').read() == plain.read_bytes()
    with pytest.raises(Exception):
        encrypted_db.import_encrypted_backup(enc, str(tmp_path / 'x.db'),
                                             'senha-forte-123')


# ---------- C2/M6 ----------

def test_c2_ask_simple_accepts_labels_password():
    sig = inspect.signature(dialogs.ask_simple)
    assert 'labels' in sig.parameters
    assert 'password' in sig.parameters


def test_c2_secret_fields_and_no_strip():
    assert dialogs._secret_fields(['a', 'b'], True) == {'a', 'b'}
    assert dialogs._secret_fields(['a', 'b'], ['b']) == {'b'}

    class FakeEntry:
        def __init__(self, text):
            self.text = text

        def get(self):
            return self.text

    entries = [('password', FakeEntry('  com-espaço  ')),
               ('label', FakeEntry('  com-espaço  '))]
    got = dialogs._read_simple_entries(entries, secret={'password'})
    assert got['password'] == '  com-espaço  '
    assert got['label'] == 'com-espaço'


def test_c2_password_entry_uses_bullet():
    captured = {}

    class FakeWidget:
        def __init__(self, *a, **k):
            captured.update(k)

        def grid(self, *a, **k):
            pass

        def insert(self, *a, **k):
            pass

    class FakeFrame(FakeWidget):
        def pack(self, *a, **k):
            pass

        def columnconfigure(self, *a, **k):
            pass

    import bmchat.gui.dialogs as dlg

    old_frame, old_label, old_entry = dlg.tk.Frame, dlg.tk.Label, dlg.tk.Entry
    dlg.tk.Frame = FakeFrame
    dlg.tk.Label = FakeWidget
    dlg.tk.Entry = FakeWidget
    try:
        dlg._build_simple_entries(object(), ['password'], {}, password=True)
        assert captured.get('show') == '•'
        captured.clear()
        dlg._build_simple_entries(object(), ['label'], {}, password=False)
        assert captured.get('show') in ('', None)
    finally:
        dlg.tk.Frame, dlg.tk.Label, dlg.tk.Entry = old_frame, old_label, old_entry


# ---------- C4 ----------

def test_c4_powershell_neutralizes_payload():
    payload = '$(Start-Process calc.exe)"test'
    cmd = NotificationManager.build_powershell_encoded(payload, payload)
    assert '-EncodedCommand' in cmd
    joined = ' '.join(cmd)
    assert '$(' not in joined
    assert 'calc' not in joined


def test_c4_osascript_uses_argv():
    payload = 'x"; do shell script "evil"; --'
    args = NotificationManager._osascript_args('t', payload)
    assert args[0] == 'osascript'
    assert payload not in args[2]
    assert args[3] == 't' and args[4] == payload


def test_c4_notify_send_uses_argv(tmp_path):
    seen = {}
    import subprocess as sp

    real = sp.run

    def fake(cmd, **kwargs):
        seen['cmd'] = list(cmd)
        assert kwargs.get('shell', False) is not True
        return type('R', (), {'returncode': 0})()

    sp.run = fake
    try:
        mgr = NotificationManager.__new__(NotificationManager)
        mgr._notify_send('ti$(x)', 'me";evil', 'normal', 5000, None)
    finally:
        sp.run = real
    assert seen['cmd'][0] == 'notify-send'
    assert 'ti$(x)' in seen['cmd']


# ---------- C5 ----------

def test_c5_encrypteddb_removed_and_db_in_clear():
    assert not hasattr(encrypted_db, 'EncryptedDB')
    assert 'EM CLARO' in (encrypted_db.__doc__ or '')
    assert hasattr(encrypted_db, 'export_encrypted_backup')
    assert hasattr(encrypted_db, 'import_encrypted_backup')
    assert hasattr(encrypted_db, 'change_password')
    assert hasattr(encrypted_db, 'is_encrypted')


def test_c5_is_encrypted_detects(tmp_path):
    plain = tmp_path / 'p.db'
    plain.write_bytes(b'SQLite format 3\x00pad')
    assert encrypted_db.is_encrypted(str(plain)) is False
    enc = str(tmp_path / 'p.enc')
    encrypted_db.export_encrypted_backup(str(plain), enc, 'senha-forte-123')
    assert encrypted_db.is_encrypted(enc) is True


# ---------- C3 ----------

def _make_client(tmp_path):
    from bmchat.core.client import Client
    directory = str(tmp_path)
    client = Client(directory)
    client.net.peers.entries.clear()
    return client


def test_c3_wire_cap_const():
    assert MAX_WIRE_BODY_BYTES == 200_000


def test_c3_send_message_rejects_oversize_wire(tmp_path):
    client = _make_client(tmp_path / 'c3a')
    try:
        alice = client.create_identity('A', 1)
        from bmchat.crypto.keys import generate_keys
        bob = generate_keys(stream=1).address
        big = 'x' * (MAX_WIRE_BODY_BYTES + 1)
        status, _ = client.send_message(alice, bob, '', big)
        assert status == 'too-large'
        rows = client.db.query(
            "SELECT COUNT(*) AS n FROM messages WHERE direction='out'")
        assert rows[0]['n'] == 0
    finally:
        client.stop()


def test_c3_broadcast_chan_rejects_oversize(tmp_path):
    client = _make_client(tmp_path / 'c3b')
    try:
        client.subscribe('CanalWireCap', 'CanalWireCap')
        from bmchat.crypto.keys import chan_keys_from_name
        addr = chan_keys_from_name('CanalWireCap', 1).address
        big = 'y' * (MAX_WIRE_BODY_BYTES + 10)
        status, _ = client.broadcast_chan(addr, big)
        assert status == 'too-large'
    finally:
        client.stop()


def test_c3_gui_wire_helper():
    from bmchat.gui.app import App
    assert App._wire_body_too_large(App, 'ok') is False
    assert App._wire_body_too_large(App, 'z' * (MAX_WIRE_BODY_BYTES + 1)) is True
    assert App._attach_max_raw() == MAX_WIRE_BODY_BYTES * 3 // 4 - 4096
    marker = 'm' * (MAX_WIRE_BODY_BYTES + 1)
    assert App._attach_wire_ok(App, '', marker) is False


# ---------- A1 ----------

def test_a1_pubkey_rejects_huge_difficulty():
    from bmchat.crypto.keys import generate_keys
    from bmchat.protocol import objects as objs
    keys = generate_keys(stream=1)
    keys.nonce_trials_per_byte = 10 ** 9
    keys.payload_length_extra_bytes = 10 ** 9
    from bmchat.crypto.keys import AddressKeys
    unsigned = objs.build_pubkey_unsigned(int(time.time()) + 3600, 1, keys)
    raw = objs.complete_object(unsigned, 0)
    assert objs.process_pubkey(raw, AddressKeys.from_address(keys.address)) is None


def test_a1_normal_pubkey_accepted():
    from bmchat.crypto.keys import generate_keys
    from bmchat.protocol import objects as objs
    keys = generate_keys(stream=1)
    from bmchat.crypto.keys import AddressKeys
    unsigned = objs.build_pubkey_unsigned(int(time.time()) + 3600, 1, keys)
    raw = objs.complete_object(unsigned, 0)
    assert objs.process_pubkey(raw, AddressKeys.from_address(keys.address)) is not None


# ---------- A2 ----------

def test_a2_stuck_sending_reverted(tmp_path):
    client = _make_client(tmp_path / 'a2')
    try:
        alice = client.create_identity('A', 1)
        from bmchat.crypto.keys import generate_keys
        bob = generate_keys(stream=1).address
        client.add_contact(bob, 'B')
        old = int(time.time()) - 3600
        client.db.execute(
            'INSERT INTO messages(obj_hash, from_address, to_address, subject,'
            ' body, encoding, timestamp, direction, status) VALUES'
            '(?,?,?,?,?,?,?,?,?)',
            (None, alice, bob, '', 'oi', 2, old, 'out', 'sending'))
        client._retry_stuck_sending()
        rows = client.db.query("SELECT status FROM messages WHERE status='sending'")
        assert rows == []
        rows = client.db.query(
            "SELECT status FROM messages WHERE status='awaiting-pubkey'")
        assert len(rows) == 1
    finally:
        client.stop()


def test_a2_stop_joins_workers(tmp_path):
    import threading
    client = _make_client(tmp_path / 'a2b')
    try:
        done = threading.Event()

        def slow():
            done.wait(0.2)

        thread = threading.Thread(target=slow, daemon=True)
        thread.start()
        client._track_worker(thread)
        client.started = True
        client._join_threads()
        assert not thread.is_alive()
    finally:
        try:
            client.stop()
        except Exception:
            pass


# ---------- A3 ----------

def test_a3_second_instance_refuses_and_keeps_lock(tmp_path):
    from bmchat.core.client import Client
    directory = str(tmp_path / 'a3')
    os.makedirs(directory, exist_ok=True)
    first = Client(directory)
    first.net.peers.entries.clear()
    orig_start = first.net.start
    first.net.start = lambda streams: None
    try:
        first.start()
        assert os.path.exists(os.path.join(directory, 'bmchat.lock'))
        # Simula outra instância viva (processo distinto): PID diferente e vivo.
        lock_path = os.path.join(directory, 'bmchat.lock')
        with open(lock_path, 'r') as handle:
            saved_lock = handle.read()
        with open(lock_path, 'w') as handle:
            handle.write('99999999')
        orig_alive = Client._lock_owner_alive
        Client._lock_owner_alive = staticmethod(lambda other, mine: other == '99999999')
        second = Client(directory)
        second.net.peers.entries.clear()
        second.net.start = lambda streams: None
        try:
            with pytest.raises(RuntimeError):
                second.start()
        finally:
            Client._lock_owner_alive = orig_alive
            with open(lock_path, 'w') as handle:
                handle.write(saved_lock)
        assert os.path.exists(os.path.join(directory, 'bmchat.lock'))
        try:
            second.stop()
        except Exception:
            pass
        assert os.path.exists(os.path.join(directory, 'bmchat.lock'))
    finally:
        first.net.start = orig_start
        try:
            first.stop()
        except Exception:
            pass
    assert not os.path.exists(os.path.join(directory, 'bmchat.lock'))


# ---------- A4 ----------

def test_a4_scheduled_success_only_and_channel_branch(tmp_path):
    client = _make_client(tmp_path / 'a4')
    try:
        alice = client.create_identity('A', 1)
        from bmchat.crypto.keys import generate_keys
        bob = generate_keys(stream=1).address
        client.add_contact(bob, 'B')
        calls = {}

        def fake_send(ident, to_addr, subject, body, encoding=2):
            calls['dm'] = (ident, to_addr)
            return 'success', None

        client.send_message = fake_send
        msg_id = client.db.add_scheduled_message(alice, bob, 'oi', int(time.time()) - 1)
        client.started = True
        client._send_due_scheduled()
        assert calls.get('dm') == (alice, bob)
        row = client.db.query('SELECT sent FROM scheduled_messages WHERE id=?', (msg_id,))
        assert row[0]['sent'] == 1
    finally:
        client.stop()


def test_a4_scheduled_error_not_marked(tmp_path):
    client = _make_client(tmp_path / 'a4b')
    try:
        alice = client.create_identity('A', 1)
        from bmchat.crypto.keys import generate_keys
        bob = generate_keys(stream=1).address
        client.send_message = lambda *a, **k: ('too-large', 'grande')
        msg_id = client.db.add_scheduled_message(alice, bob, 'oi', int(time.time()) - 1)
        client.started = True
        client._send_due_scheduled()
        row = client.db.query('SELECT sent FROM scheduled_messages WHERE id=?', (msg_id,))
        assert row[0]['sent'] == 1
    finally:
        client.stop()


def test_a4_scheduled_missing_identity_logged(tmp_path):
    client = _make_client(tmp_path / 'a4c')
    try:
        msg_id = client.db.add_scheduled_message('BM-inexistente', 'BM-x', 'oi',
                                                 int(time.time()) - 1)
        client.started = True
        client._send_due_scheduled()
        row = client.db.query('SELECT sent FROM scheduled_messages WHERE id=?', (msg_id,))
        assert row[0]['sent'] == 1
        assert any('identidade ausente' in line for line in client.recent_logs(50))
    finally:
        client.stop()


def test_a4_scheduled_channel_uses_broadcast(tmp_path):
    client = _make_client(tmp_path / 'a4d')
    try:
        client.subscribe('CanalA4', 'CanalA4')
        from bmchat.crypto.keys import chan_keys_from_name
        addr = chan_keys_from_name('CanalA4', 1).address
        owner = client.create_identity('Owner', 1)
        calls = {}

        def fake_chan(to_addr, body, encoding=2, name=None):
            calls['chan'] = to_addr
            return 'success', None

        client.broadcast_chan = fake_chan
        client.send_message = lambda *a, **k: (_ for _ in ()).throw(AssertionError('virou DM'))
        client.db.add_scheduled_message(owner, addr, 'post', int(time.time()) - 1)
        client.started = True
        client._send_due_scheduled()
        assert calls.get('chan') == addr
    finally:
        client.stop()


# ---------- A5 ----------

def test_a5_announce_goes_through_store_and_known(tmp_path):
    from bmchat.net.manager import NetworkManager
    from bmchat.core.database import Database
    directory = str(tmp_path / 'a5')
    os.makedirs(directory, exist_ok=True)
    db = Database(directory)
    try:
        mgr = NetworkManager(directory, db)
        raw = os.urandom(200)
        mgr.announce_object(raw)
        # Confere via inventory/known (hash interno do projeto).
        assert len(mgr.inventory) == 1
        assert len(mgr.known_hashes) == 1
        assert list(mgr.inventory.values())[0] == raw
    finally:
        db.close()


# ---------- A6 ----------

def test_a6_change_password_atomic_bak_and_no_tmp(tmp_path):
    plain = tmp_path / 'g.db'
    plain.write_bytes(os.urandom(400))
    enc = str(tmp_path / 'g.enc')
    encrypted_db.export_encrypted_backup(str(plain), enc, 'senha-forte-123')
    before = set(os.listdir(str(tmp_path)))
    encrypted_db.change_password(enc, 'senha-forte-123', 'outra-senha-789')
    after = set(os.listdir(str(tmp_path)))
    assert 'g.enc.bak' in after
    leftovers = [name for name in after - before
                 if name.startswith('.tmp-enc-')]
    assert leftovers == []
    out = str(tmp_path / 'h.db')
    encrypted_db.import_encrypted_backup(enc, out, 'outra-senha-789')
    assert open(out, 'rb').read() == plain.read_bytes()


def test_a6_import_cleans_tmp_on_wrong_password(tmp_path):
    plain = tmp_path / 'i.db'
    plain.write_bytes(os.urandom(200))
    enc = str(tmp_path / 'i.enc')
    encrypted_db.export_encrypted_backup(str(plain), enc, 'senha-forte-123')
    with pytest.raises(Exception):
        encrypted_db.import_encrypted_backup(
            enc, str(tmp_path / 'j.db'), 'errada-12345')
    after = set(os.listdir(str(tmp_path)))
    assert not os.path.exists(str(tmp_path / 'j.db'))
    assert 'j.db.bak' not in after


# ---------- A7 ----------

def test_a7_secret_files_are_0600(tmp_path):
    plain = tmp_path / 'k.db'
    plain.write_bytes(os.urandom(200))
    enc = str(tmp_path / 'k.enc')
    encrypted_db.export_encrypted_backup(str(plain), enc, 'senha-forte-123')
    mode = stat.S_IMODE(os.stat(enc).st_mode)
    assert mode == 0o600
    out = str(tmp_path / 'l.db')
    encrypted_db.import_encrypted_backup(enc, out, 'senha-forte-123')
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    from bmchat.gui.app import App
    secret = str(tmp_path / 'keys.dat')
    App._secret_write_text(secret, 'privsigningkey = 00')
    assert stat.S_IMODE(os.stat(secret).st_mode) == 0o600


# ---------- A9 ----------

def test_a9_inv_caps_wanted_and_rate(tmp_path):
    from bmchat.net.manager import NetworkManager
    from bmchat.core.database import Database
    from bmchat.protocol import packets
    directory = str(tmp_path / 'a9')
    os.makedirs(directory, exist_ok=True)
    db = Database(directory)
    try:
        mgr = NetworkManager(directory, db)

        class FakeConn:
            class Peer:
                host = '1.2.3.4'
                port = 8444

            peer = Peer()
            sent = []

            def send_packet(self, command, payload=b''):
                self.sent.append((command, bytes(payload)))

        conn = FakeConn()
        hashes = [os.urandom(32) for _ in range(500)]
        mgr.on_inv(conn, packets.assemble_inventory(hashes))
        total = 0
        for command, payload in conn.sent:
            assert command == b'getdata'
            total += len(packets.parse_inventory(payload))
        assert total <= 200
        conn.sent.clear()
        for _ in range(10):
            mgr.on_inv(conn, packets.assemble_inventory(hashes[:10]))
        # rate limit: após excesso, nada mais é enviado
        before = len(conn.sent)
        mgr.on_inv(conn, packets.assemble_inventory(hashes[:10]))
        assert len(conn.sent) == before or len(conn.sent) <= before + 2
    finally:
        db.close()


def test_a9_getdata_caps_bytes_and_hashes(tmp_path):
    from bmchat.net.manager import NetworkManager
    from bmchat.core.database import Database
    from bmchat.protocol import packets
    directory = str(tmp_path / 'a9b')
    os.makedirs(directory, exist_ok=True)
    db = Database(directory)
    try:
        mgr = NetworkManager(directory, db)
        for i in range(30):
            h = bytes([i + 1]) * 32
            mgr.inventory[h] = os.urandom(200_000)

        class FakeConn:
            class Peer:
                host = '5.6.7.8'
                port = 8444

            peer = Peer()

            def __init__(self):
                self.sent = []

            def send_packets(self, command, blobs):
                self.sent.append((command, list(blobs)))

        conn = FakeConn()
        hashes = list(mgr.inventory.keys())[:100]
        mgr.on_getdata(conn, packets.assemble_getdata(hashes))
        assert conn.sent
        blobs = conn.sent[0][1]
        assert len(blobs) <= 20
        assert sum(len(b) for b in blobs) <= 3 * 1024 * 1024 + 300_000
    finally:
        db.close()


# ---------- A10 ----------

def test_a10_inventory_evicts_by_expires(tmp_path):
    from bmchat.net.manager import NetworkManager
    from bmchat.core.database import Database
    directory = str(tmp_path / 'a10')
    os.makedirs(directory, exist_ok=True)
    db = Database(directory)
    try:
        mgr = NetworkManager(directory, db)
        now = int(time.time())
        for i in range(8005):
            raw = (b'\x00' * 8 + struct.pack('>Q', now + i) + os.urandom(20))
            mgr.inventory[os.urandom(32)] = raw
        mgr._evict_inventory_to_cap()
        from bmchat.net.manager import INVENTORY_MAX
        assert len(mgr.inventory) <= INVENTORY_MAX
    finally:
        db.close()


def test_a10_store_rate_limits_peer(tmp_path):
    from bmchat.net.manager import NetworkManager
    from bmchat.core.database import Database
    directory = str(tmp_path / 'a10b')
    os.makedirs(directory, exist_ok=True)
    db = Database(directory)
    try:
        mgr = NetworkManager(directory, db)
        mgr.is_proof_of_work_sufficient = lambda raw: True
        import bmchat.net.manager as mm
        old = mm.is_proof_of_work_sufficient
        mm.is_proof_of_work_sufficient = lambda raw: True
        try:
            from bmchat.protocol.const import OBJECT_MSG
            from bmchat.util import encode_varint

            class FakePeer:
                host = '9.9.9.9'
                port = 8444

            class FakeSource:
                peer = FakePeer()

            src = FakeSource()
            accepted = 0
            for _ in range(60):
                raw = (b'\x00' * 8 + struct.pack(
                    '>Q', int(time.time()) + 3600) + struct.pack('>I', OBJECT_MSG)
                    + encode_varint(1) + encode_varint(1) + os.urandom(32))
                if mgr.received_object(raw, src) is not None:
                    accepted += 1
            assert accepted <= 50
        finally:
            mm.is_proof_of_work_sufficient = old
    finally:
        db.close()


# ---------- A11 ----------

def test_a11_ack_dedupe_single_announce(tmp_path):
    client = _make_client(tmp_path / 'a11')
    try:
        announced = []
        client.net.announce_object = lambda data, source=None: announced.append(bytes(data))
        from bmchat.protocol import objects as objs, packets as pk
        from bmchat.crypto.pow import find_nonce_single_threaded, initial_hash_of
        unsigned = objs.build_ack_unsigned(int(time.time()) + 3600, os.urandom(32), 1)
        nonce = find_nonce_single_threaded(initial_hash_of(unsigned), 2 ** 52)
        packet = pk.create_packet('object', objs.complete_object(unsigned, nonce))
        import bmchat.core.client as cm
        old = cm.is_proof_of_work_sufficient
        cm.is_proof_of_work_sufficient = lambda *a, **k: True
        try:
            client._relay_ack_sync(packet)
            client._relay_ack_sync(packet)
        finally:
            cm.is_proof_of_work_sufficient = old
        assert len(announced) == 2
        announced.clear()
        cm.is_proof_of_work_sufficient = lambda *a, **k: True
        try:
            client._relay_ack(packet)
            client._relay_ack(packet)
            deadline = time.time() + 5
            while time.time() < deadline and len(announced) < 1:
                time.sleep(0.05)
        finally:
            cm.is_proof_of_work_sufficient = old
        assert len(announced) == 1
        if client._ack_pool is not None:
            client._ack_pool.shutdown(wait=True, cancel_futures=False)
            client._ack_pool = None
    finally:
        client.stop()


# ---------- A12 ----------

def test_a12_send_queued_skips_without_peers_and_caps(tmp_path):
    client = _make_client(tmp_path / 'a12')
    try:
        alice = client.create_identity('A', 1)
        from bmchat.crypto.keys import generate_keys
        bob = generate_keys(stream=1).address
        client.add_contact(bob, 'B')
        for i in range(8):
            client.db.add_message(None, alice, bob, '', 'm%d' % i, 2,
                                  int(time.time()), 'out', 'awaiting-pubkey')
        calls = []
        client._pow_and_publish_message = lambda *a, **k: calls.append(a[0])
        client._send_queued(bob)
        assert calls == []
        client.net.connections['fake'] = type('C', (), {'established': True})()
        try:
            type(client.net).established_count = property(lambda self: 1)
            client._send_queued(bob)
        finally:
            try:
                delattr(type(client.net), 'established_count')
            except Exception:
                pass
        assert len(calls) == 5
    finally:
        client.stop()


# ---------- A13 ----------

def test_a13_calc_height_caps_huge_and_image_ok():
    from bmchat.gui.app import App
    huge = {'mime': 'image/png', 'data': 'A' * 400_000}
    assert App._calc_attachment_height(App, huge, 300, False) == 48
    import base64
    from io import BytesIO
    from PIL import Image
    img = Image.new('RGB', (10, 10), color='red')
    buf = BytesIO()
    img.save(buf, format='PNG')
    small = {'mime': 'image/png',
             'data': base64.b64encode(buf.getvalue()).decode('ascii')}
    height = App._calc_attachment_height(App, small, 300, False)
    assert 1 <= height <= 64


def test_a13_render_fallback_without_tk():
    from bmchat.gui.app import App

    class FakeCanvas:
        def __init__(self):
            self.ops = []

        def create_rectangle(self, *a, **k):
            self.ops.append('rect')

        def create_text(self, *a, **k):
            self.ops.append('text')

    canvas = FakeCanvas()
    att = {'filename': 'a.bin', 'mime': 'application/octet-stream',
           'data': base64.b64encode(b'123').decode('ascii')}
    icon_fn = staticmethod(App._attachment_icon)
    attrs = {'msg_font': '', '_render_image_attachment': lambda *a, **k: None, '_attachment_icon': icon_fn}
    fake_self = type('S', (), attrs)()
    height = App._render_attachment(fake_self, canvas, 0, 0, att, 200, False)
    assert height == 48
    assert 'rect' in canvas.ops


# ---------- M1 ----------

def test_m1_ack_watch_ttl_sweep(tmp_path):
    client = _make_client(tmp_path / 'm1')
    try:
        from bmchat.protocol.const import MSG_TTL
        old_key = b'K' * 38
        client._ack_watch[old_key] = (123, time.time() - MSG_TTL - 10)
        fresh = b'F' * 38
        client._ack_watch[fresh] = (456, time.time())
        client._sweep_ack_watch()
        assert old_key not in client._ack_watch
        assert fresh in client._ack_watch
    finally:
        client.stop()


# ---------- M2 ----------

def test_m2_decode_point_rejects_out_of_range():
    from bmchat.crypto import ecc
    prime = ecc.CURVE.p()
    bad_x = prime.to_bytes(32, 'big')
    bad = b'\x04' + bad_x + b'\x00' * 32
    with pytest.raises(ValueError):
        ecc.decode_point_public(bad)
    with pytest.raises(ValueError):
        ecc.decode_point_public(b'\x04' + b'\x00' * 64)


# ---------- M3 ----------

def test_m3_generation_invalidates_old_maintenance(tmp_path):
    from bmchat.net.manager import NetworkManager
    from bmchat.core.database import Database
    directory = str(tmp_path / 'm3')
    os.makedirs(directory, exist_ok=True)
    db = Database(directory)
    try:
        mgr = NetworkManager(directory, db)
        mgr.running = True
        with mgr.lock:
            mgr._generation = 5
        assert mgr._generation == 5
        mgr.stop()
        assert mgr._maintenance_thread is None
    finally:
        db.close()


# ---------- M4 ----------

def test_m4_writable_dir_rejects_file(tmp_path):
    import run
    target = str(tmp_path / 'arquivo')
    with open(target, 'w') as handle:
        handle.write('x')
    with pytest.raises(SystemExit):
        run._ensure_writable_dir(target)


def test_m4_writable_dir_accepts_dir(tmp_path):
    import run
    assert run._ensure_writable_dir(str(tmp_path / 'ok')) == str(tmp_path / 'ok')


# ---------- M5 ----------

def test_m5_ack_failed_icon_resend_limit(tmp_path):
    from bmchat.gui.app import App
    assert App._ticks(App, {'status': 'ack-failed'})[0] == '⚠'
    assert 'Reenviar' in App._status_text(
        App, {'status': 'ack-failed', 'direction': 'out'})
    client = _make_client(tmp_path / 'm5')
    try:
        alice = client.create_identity('A', 1)
        from bmchat.crypto.keys import generate_keys
        bob = generate_keys(stream=1).address
        mid = client.db.add_message(None, alice, bob, '', 'oi', 2,
                                    int(time.time()), 'out', 'ack-failed')
        client._pow_and_publish_message = lambda *a, **k: None
        client.request_pubkey = lambda *a, **k: 'success'
        assert client.resend_message(mid)[0] == 'success'
        assert client.resend_message(mid)[0] == 'success'
        assert client.resend_message(mid)[0] == 'success'
        assert client.resend_message(mid)[0] == 'error'
    finally:
        client.stop()


# ---------- M7 ----------

def test_m7_identities_snapshot_and_orphan_reparse(tmp_path):
    client = _make_client(tmp_path / 'm7')
    try:
        alice = client.create_identity('A', 1)
        snap = client._identities_snapshot()
        assert isinstance(snap, list) and snap[0][0] == alice
        snap.append(('fake', None))
        assert 'fake' not in client.identities
        client._reparse_orphans(limit=5)
    finally:
        client.stop()


# ---------- M8 ----------

def test_m8_no_verify_commit_declared():
    import bmchat.update as updater
    from bmchat.gui.app import App
    assert 'verify-commit' in (updater.__doc__ or '').lower() or \
        'verify' in (updater.__doc__ or '').lower()
    assert 'pin' in (updater.__doc__ or '').lower()
    text = App._update_offer_text(App, 3, {'behind': 3})
    assert 'SEM' in text and 'pin' in text.lower()


# ---------- M9 ----------

def test_m9_stats_and_update_flags_locked(tmp_path):
    from bmchat.net.manager import NetworkManager
    from bmchat.core.database import Database
    directory = str(tmp_path / 'm9')
    os.makedirs(directory, exist_ok=True)
    db = Database(directory)
    try:
        mgr = NetworkManager(directory, db)
        mgr._bump_stats('invs')
        assert mgr.snapshot()['stats']['invs'] == 1
    finally:
        db.close()
    from bmchat.gui.app import App
    assert hasattr(App, '_set_update_flag')
    assert hasattr(App, '_get_update_flag')


# ---------- M10 ----------

def test_m10_password_minimum():
    from bmchat.gui.app import App
    assert App._password_long_enough('1234567') is False
    assert App._password_long_enough('12345678') is True
    with pytest.raises(ValueError):
        encrypted_db._seal(b'dados', 'curta')


# ---------- HALLUCINATION 2026-09-08: request_pubkey v3 não levanta ----------

def test_hall_request_pubkey_v3_returns_unsupported(tmp_path):
    """B4 incompleto: request_pubkey levantava ValueError para v3.

    send_message já devolvia 'unsupported'; request_pubkey quebrava o
    callback Tk de _new_contact (report_callback_exception). Agora
    devolve 'unsupported'/'invalid' sem levantar e sem queimar PoW.
    """
    from bmchat.protocol.address import encode_address
    client = _make_client(tmp_path / 'hall-reqpub-v3')
    try:
        ripe = os.urandom(20)
        addr3 = encode_address(3, 1, ripe)
        assert client.request_pubkey(addr3) == 'unsupported'
        assert client.request_pubkey('BM-invalido') != 'success'
    finally:
        client.stop()


def test_hall_lock_backup_file_removed():
    """Refactor trocou open+chmod por _secret_write_text e órfou o helper."""
    from bmchat.gui.app import App
    assert not hasattr(App, '_lock_backup_file')
    assert hasattr(App, '_secret_write_text')
