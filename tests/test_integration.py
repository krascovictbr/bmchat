import os
import shutil
import struct
import sys
import tempfile
import time

import pytest

from bmchat.core.client import Client
from bmchat.crypto.keys import AddressKeys, generate_keys
from bmchat.protocol import address as addr_module
from bmchat.protocol import objects
from bmchat.protocol import packets
from bmchat.protocol.const import OBJECT_MSG
from bmchat.util import encode_varint

REF_SRC = os.environ.get(
    'BMCHAT_REF_SRC', '/home/artix/PyBitmessage/src')


def _ref_crypto():
    if not os.path.exists(os.path.join(REF_SRC, 'highlevelcrypto.py')):
        pytest.skip('PyBitmessage de referência indisponível')
    if REF_SRC not in sys.path:
        sys.path.insert(0, REF_SRC)
    import highlevelcrypto
    return highlevelcrypto
from bmchat.crypto.pow import (
    find_nonce_single_threaded, initial_hash_of,
)
import bmchat.core.client as client_mod

TARGET = 2 ** 52


@pytest.fixture
def client():
    directory = tempfile.mkdtemp(prefix='bmchat-test-')
    instance = Client(directory)

    def fake_run(self, unsigned, target, message_id=None, done_cb=None,
                 token=None, stop_event=None):
        nonce = find_nonce_single_threaded(initial_hash_of(unsigned), target)
        result = objects.complete_object(unsigned, nonce)
        if done_cb is not None:
            done_cb(result, nonce)

    def fake_quick(self, unsigned, target):
        return find_nonce_single_threaded(initial_hash_of(unsigned), target)

    instance._run_pow_and_done = fake_run.__get__(instance, Client)
    instance._quick_pow = fake_quick.__get__(instance, Client)
    original_target = client_mod.calculate_target
    client_mod.calculate_target = lambda *a, **k: TARGET
    instance._testing_target = TARGET
    instance._testing_original_target = original_target
    yield instance
    client_mod.calculate_target = original_target
    instance.stop()
    shutil.rmtree(directory, ignore_errors=True)


def test_pubkey_lifecycle(client):
    client.create_identity('Alice', 1)
    bob = client.create_identity('Bob', 1)
    client._load_identities()
    client.add_contact(bob, 'Bob')

    bob_keys = client.identities[bob]
    unsigned = objects.build_pubkey_unsigned(
        int(time.time()) + 28 * 24 * 3600, 1, bob_keys)
    complete = objects.complete_object(unsigned, 0)
    client._on_pubkey(objects.ParsedObject(complete), complete)
    assert client.has_pubkey(bob)
    assert client.pubkeys[bob]['nonce_trials_per_byte'] == 1000


def test_send_then_ack(client):
    alice = client.create_identity('Alice', 1)
    bob = client.create_identity('Bob', 1)
    client._load_identities()
    client.add_contact(bob, 'Bob')

    bob_keys = client.identities[bob]
    unsigned = objects.build_pubkey_unsigned(
        int(time.time()) + 28 * 24 * 3600, 1, bob_keys)
    client._on_pubkey(objects.ParsedObject(
        objects.complete_object(unsigned, 0)), objects.complete_object(
            unsigned, 0))

    status, error = client.send_message(alice, bob, '', 'Olá Bob')
    assert status == 'success'

    deadline = time.time() + 5
    while time.time() < deadline:
        rows = client.db.messages_for_conversation(bob)
        outbound = [r for r in rows if r['direction'] == 'out']
        if outbound and outbound[0]['status'] == 'sent':
            break
        time.sleep(0.05)
    assert outbound and outbound[0]['status'] == 'sent'

    watch_keys = list(client._ack_watch.keys())
    assert len(watch_keys) == 1
    watch = watch_keys[0]

    rows = client.db.messages_for_conversation(bob)
    outbound = [r for r in rows if r['direction'] == 'out']
    assert len(outbound) == 1
    assert outbound[0]['status'] == 'sent'

    # Bob recebe a mensagem (via pipeline normal)
    built = objects.build_msg_unsigned(
        int(time.time()) + 3600, 1, bob_keys_producer(client, bob),
        client.identities[alice].encryption_public,
        client.identities[alice].ripe,
        'Mensagem de retorno'.encode(), 2, b'')
    client._on_object(objects.ParsedObject(objects.complete_object(built, 0)),
                      objects.complete_object(built, 0), None)
    inbound = [r for r in client.db.messages_for_conversation(alice)
               if r['direction'] == 'in']
    assert len(inbound) == 1

    # O ack que Alice gerou chega de volta: deve marcar como ackreceived
    ack_unsigned = objects.build_ack_unsigned(int(time.time()) + 3600,
                                              watch[6:], 1)
    ack_nonce = find_nonce_single_threaded(
        initial_hash_of(ack_unsigned), TARGET)
    ack_object = objects.complete_object(ack_unsigned, ack_nonce)
    client._maybe_mark_ack(objects.ParsedObject(ack_object))

    outbound = [r for r in client.db.messages_for_conversation(bob)
                if r['direction'] == 'out']
    assert outbound[0]['status'] == 'ackreceived'


def test_msg_with_ack_packet_is_valid(client):
    client.create_identity('Alice', 1)
    client.create_identity('Bob', 1)
    client._load_identities()
    packet, watch = client._build_ack_packet(1)
    assert len(watch) == 38
    magic, command, length, checksum = packets.parse_header(packet[:24])
    assert magic == packets.MAGIC
    assert command == 'object'
    obj = packet[24:]
    assert len(obj) == length
    assert client_mod.sha512(obj)[:4] == checksum
    parsed = objects.ParsedObject(obj)
    assert parsed.object_type == OBJECT_MSG
    assert parsed.version == 1


def test_backup_roundtrip(client):
    alice = client.create_identity('Alice', 1)
    data = client.export_identity(alice)
    assert data is not None
    assert data['address'] == alice
    assert data['signing_wif'] and data['encryption_wif']
    assert data['signing_wif'] != data['encryption_wif']
    assert client.export_identity('BM-inexistente') is None

    other_dir = tempfile.mkdtemp(prefix='bmchat-restore-')
    other = Client(other_dir)
    try:
        status, info = other.import_identity(
            data['signing_wif'], data['encryption_wif'],
            'Alice restaurada', data['stream'])
        assert status == 'success'
        assert info == alice
        assert alice in other.identities
        assert other.identities[alice].signing_private == \
            client.identities[alice].signing_private
        assert other.identities[alice].encryption_private == \
            client.identities[alice].encryption_private
        status, _ = other.import_identity(
            data['signing_wif'], data['encryption_wif'], 'x', 1)
        assert status == 'exists'
        status, _ = other.import_identity('inválida', 'inválida', 'x', 1)
        assert status == 'invalid'
    finally:
        other.stop()
        shutil.rmtree(other_dir, ignore_errors=True)


def test_keys_dat_roundtrip(client):
    alice = client.create_identity('Alice', 1)
    blob = client.export_keys_dat()
    assert '[%s]' % alice in blob
    assert 'privsigningkey = ' in blob
    assert 'privencryptionkey = ' in blob

    other_dir = tempfile.mkdtemp(prefix='bmchat-keysdat-')
    other = Client(other_dir)
    try:
        result = other.import_keys_dat(blob)
        assert result['imported'] == 1
        assert result['errors'] == 0
        assert alice in other.identities
        assert other.identities[alice].signing_private == \
            client.identities[alice].signing_private
        again = other.import_keys_dat(blob)
        assert again['imported'] == 0
        assert again['skipped'] == 1
        tampered = blob.replace('[%s]' % alice, '[BM-2cADULTERADO]', 1)
        bad = other.import_keys_dat(tampered)
        assert bad['errors'] == 1
        assert bad['imported'] == 0
    finally:
        other.stop()
        shutil.rmtree(other_dir, ignore_errors=True)


def test_receive_foreign_message(client):
    ref = _ref_crypto()
    alice = client.create_identity('Alice', 1)
    alice_keys = client.identities[alice]
    sender_keys = generate_keys(stream=1)
    sender_addr = sender_keys.address
    hexenc_pub = alice_keys.encryption_public.hex().encode('ascii')
    hexsign_priv = sender_keys.signing_private.hex().encode('ascii')

    expires = int(time.time()) + 3600
    plain = encode_varint(4) + encode_varint(1) + struct.pack('>I', 1)
    plain += sender_keys.signing_public[1:]
    plain += sender_keys.encryption_public[1:]
    plain += encode_varint(1000) + encode_varint(1000)
    plain += alice_keys.ripe
    plain += encode_varint(2) + encode_varint(8) + b'Oi Alice'
    ack_unsigned = objects.build_ack_unsigned(expires, os.urandom(32), 1)
    ack_nonce = find_nonce_single_threaded(
        initial_hash_of(ack_unsigned), TARGET)
    ack_packet = packets.create_packet(
        'object', objects.complete_object(ack_unsigned, ack_nonce))
    plain += encode_varint(len(ack_packet)) + ack_packet
    signed = struct.pack('>Q', expires) + struct.pack('>I', 2) + \
        encode_varint(1) + encode_varint(1) + plain
    sig = bytes(ref.sign(signed, hexsign_priv))
    plain += encode_varint(len(sig)) + sig
    ciphertext = bytes(ref.encrypt(plain, hexenc_pub))
    raw = struct.pack('>Q', 0) + struct.pack('>Q', expires) + \
        struct.pack('>I', 2) + encode_varint(1) + encode_varint(1) + \
        ciphertext

    announced = []
    original = client.net.announce_object
    original_check = client_mod.is_proof_of_work_sufficient
    client_mod.is_proof_of_work_sufficient = lambda *a, **k: True
    client.net.announce_object = lambda data, source=None: \
        announced.append(bytes(data))
    try:
        client._on_object(objects.ParsedObject(raw), raw, None)
        deadline = time.time() + 10
        while time.time() < deadline and not announced:
            time.sleep(0.05)
    finally:
        client.net.announce_object = original
        client_mod.is_proof_of_work_sufficient = original_check

    rows = client.db.messages_for_conversation(alice)
    inbound = [r for r in rows if r['direction'] == 'in']
    assert len(inbound) == 1
    assert inbound[0]['body'] == 'Oi Alice'
    assert inbound[0]['from_address'] == sender_addr
    assert abs(inbound[0]['timestamp'] - int(time.time())) < 300
    events = []
    while True:
        try:
            events.append(client.ui_queue.get_nowait())
        except Exception:
            break
    kinds = [e[0] for e in events]
    assert 'message' in kinds
    assert announced, 'ACK do destinatário não foi retransmitido'
    acked = objects.ParsedObject(announced[0])
    assert acked.object_type == OBJECT_MSG
    assert acked.version == 1


def test_foreign_getpubkey_triggers_pubkey(client):
    alice = client.create_identity('Alice', 1)
    tag = client.identities[alice].tag
    expires = int(time.time()) + 3600
    raw = struct.pack('>Q', 0) + struct.pack('>Q', expires) + \
        struct.pack('>I', 0) + encode_varint(4) + encode_varint(1) + tag

    announced = []
    original = client.net.announce_object
    client.net.announce_object = lambda data, source=None: \
        announced.append(bytes(data))
    try:
        client._on_object(objects.ParsedObject(raw), raw, None)
        deadline = time.time() + 15
        while time.time() < deadline and not announced:
            time.sleep(0.05)
    finally:
        client.net.announce_object = original

    assert announced, 'pubkey não foi publicada em resposta'
    parsed = objects.ParsedObject(announced[0])
    assert parsed.object_type == 1
    assert parsed.version == 4
    incoming = objects.process_pubkey(
        announced[0], AddressKeys.from_address(alice))
    assert incoming is not None
    assert incoming.address == alice


def test_retry_republishes_getpubkey(client):
    alice = client.create_identity('Alice', 1)
    bob = generate_keys(stream=1).address
    client.add_contact(bob, 'Bob')
    client.db.add_message(None, alice, bob, '', 'oi', 2, int(time.time()),
                          'out', 'awaiting-pubkey')
    assert client._awaiting_addresses() == [bob]
    announced = []
    original = client.net.announce_object
    client.net.announce_object = lambda data, source=None: \
        announced.append(bytes(data))
    client.started = True
    try:
        client._retry_awaiting()
        deadline = time.time() + 15
        while time.time() < deadline and not announced:
            time.sleep(0.05)
    finally:
        client.started = False
        client.net.announce_object = original
    assert announced, 'retry não republicou o getpubkey'
    assert objects.ParsedObject(announced[0]).object_type == 0


def test_inventory_persists_across_restarts():
    from bmchat.core.database import Database
    from bmchat.net.manager import NetworkManager
    directory = tempfile.mkdtemp(prefix='bmchat-persist-')
    try:
        fake_hash = b'H' * 32
        fake_raw = b'R' * 100
        fresh = b'N' * 32
        db1 = Database(directory)
        db1.store_object(fake_hash, fake_raw, 2, 1, 1,
                         int(time.time()) + 3600)
        db1.store_object(b'E' * 32, b'X', 2, 1, 1,
                         int(time.time()) - 90000)
        mgr1 = NetworkManager(directory, db1)
        mgr1._prune_expired_objects()
        mgr1._load_known_hashes()
        assert fake_hash in mgr1.known_hashes
        assert b'E' * 32 not in mgr1.known_hashes
        db1.close()

        events = []

        class FakeConn:
            established = True

            def send_packet(self, command, payload=b''):
                events.append((command, bytes(payload)))

            def send_packets(self, command, blobs):
                for blob in blobs:
                    events.append((command, bytes(blob)))

        db2 = Database(directory)
        mgr2 = NetworkManager(directory, db2)
        mgr2._load_known_hashes()
        conn = FakeConn()
        mgr2.on_inv(conn, packets.assemble_inventory([fake_hash, fresh]))
        getdatas = [e for e in events if e[0] == b'getdata']
        assert getdatas, 'deveria pedir o hash novo'
        assert packets.parse_inventory(getdatas[0][1]) == [fresh]
        events.clear()
        mgr2.inventory.clear()
        mgr2.on_getdata(conn, packets.assemble_getdata([fake_hash]))
        served = [e for e in events if e[0] == b'object']
        assert served and served[0][1] == fake_raw
        db2.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_wipe_objects_and_stats():
    from bmchat.core.database import Database
    from bmchat.net.manager import NetworkManager
    directory = tempfile.mkdtemp(prefix='bmchat-wipe-')
    try:
        db = Database(directory)
        mgr = NetworkManager(directory, db)
        for i in range(3):
            db.store_object(bytes([i + 1]) * 32, b'X' * 40, 2, 1, 1,
                            int(time.time()) + 3600)
        mgr._load_known_hashes()
        assert len(mgr.known_hashes) == 3

        class FakeConn:
            established = True

            def __init__(self):
                self.sent = []

            def send_packet(self, command, payload=b''):
                self.sent.append((command, bytes(payload)))

            def send_packets(self, command, blobs):
                for blob in blobs:
                    self.sent.append((command, bytes(blob)))

        conn = FakeConn()
        mgr.on_inv(conn, packets.assemble_inventory([b'Z' * 32]))
        assert mgr.stats['invs'] == 1
        assert any(c == b'getdata' for c, _ in conn.sent)
        mgr.on_getdata(conn, packets.assemble_getdata([b'\x01' * 32]))
        assert mgr.stats['getdatas'] == 1
        mgr.announce_object(b'Y' * 50)
        assert mgr.stats['objects_announced'] == 1

        snap = mgr.snapshot()
        assert snap['objects_stored'] == 3
        assert snap['stats']['objects_announced'] == 1
        assert 'uptime' in snap

        assert mgr.wipe_objects() == 3
        assert mgr.snapshot()['objects_stored'] == 0
        assert len(mgr.inventory) == 0
        assert len(mgr.known_hashes) == 0
        db.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_chan_matches_reference():
    if not os.path.exists(os.path.join(REF_SRC, 'addresses.py')):
        pytest.skip('PyBitmessage de referência indisponível')
    if REF_SRC not in sys.path:
        sys.path.insert(0, REF_SRC)
    from addresses import encodeAddress, encodeVarint
    import highlevelcrypto as ref
    from bmchat.crypto.keys import chan_keys_from_name
    for name in ['AIED', 'teste', 'Canal São Paulo']:
        passphrase = name.encode('utf-8')
        signing_nonce, encryption_nonce = 0, 1
        while True:
            priv_s, pub_s = ref.deterministic_keys(
                passphrase, encodeVarint(signing_nonce))
            priv_e, pub_e = ref.deterministic_keys(
                passphrase, encodeVarint(encryption_nonce))
            ripe = ref.to_ripe(bytes(pub_s), bytes(pub_e))
            if ripe[:1] == b'\x00':
                break
            signing_nonce += 2
            encryption_nonce += 2
        ref_address = encodeAddress(4, 1, bytes(ripe))
        ours = chan_keys_from_name(name, stream=1)
        assert ours.address == ref_address
        assert ours.signing_private == bytes(priv_s)
        assert ours.encryption_private == bytes(priv_e)


def test_chan_subscribe_and_post(client):
    from bmchat.crypto.keys import chan_keys_from_name
    status, _ = client.subscribe('AIED', 'AIED')
    assert status == 'success'
    expected = chan_keys_from_name('AIED', 1).address
    row = client.db.get_subscription(expected)
    assert row is not None
    assert row.get('name') == 'AIED'

    announced = []
    original = client.net.announce_object
    client.net.announce_object = lambda data, source=None: \
        announced.append(bytes(data))
    try:
        status, info = client.broadcast_chan(expected, 'Ola, canal!')
        assert status == 'success', info
        deadline = time.time() + 15
        while time.time() < deadline and not announced:
            time.sleep(0.05)
    finally:
        client.net.announce_object = original
    assert announced, 'broadcast do chan não foi anunciado'
    parsed = objects.ParsedObject(announced[0])
    assert parsed.object_type == 3
    assert parsed.version == 5
    assert parsed.data[:32] == chan_keys_from_name('AIED', 1).tag
    subs = {parsed.data[:32]: AddressKeys.from_address(expected)}
    incoming = objects.process_broadcast(announced[0], subs)
    assert incoming is not None
    assert incoming.message == 'Ola, canal!'.encode('utf-8')

    other = generate_keys(stream=1).address
    client.db.add_subscription(other, 'só-leitura')
    status, info = client.broadcast_chan(other, 'x')
    assert status == 'noname'
    status, info = client.broadcast_chan(expected, 'x', name='NomeErrado')
    assert status == 'mismatch'


def test_delete_conversation_and_entries(client):
    alice = client.create_identity('Alice', 1)
    bob = generate_keys(stream=1).address
    client.add_contact(bob, 'Bob')
    client.db.add_message(None, alice, bob, '', 'a', 2, 1000, 'out', 'sent')
    client.db.add_message(None, bob, alice, '', 'b', 2, 2000, 'in',
                          'received')
    assert len(client.db.messages_for_conversation(bob)) == 2
    client.db.delete_conversation(bob)
    assert client.db.messages_for_conversation(bob) == []
    assert client.db.get_contact(bob) is not None
    client.remove_contact(bob)
    assert client.db.get_contact(bob) is None
    other = generate_keys(stream=1).address
    client.db.add_subscription(other, 'x')
    client.db.add_message(None, other, other, '', 'c', 2, 3000, 'in',
                          'received')
    client.unsubscribe(other)
    assert client.db.get_subscription(other) is None
    assert client.db.messages_for_conversation(other) == []


def test_migrate_future_message_timestamps():
    from bmchat.core.database import Database
    directory = tempfile.mkdtemp(prefix='bmchat-migrate-')
    try:
        now = int(time.time())
        db = Database(directory)
        db.store_object(b'M' * 32, b'Z' * 40, 2, 1, 1, now + 3600)
        received_at = now - 7200
        db.execute('UPDATE objects SET received=? WHERE hash=?',
                   (received_at, b'M' * 32))
        db.add_message(b'M' * 32, 'BM-de', 'BM-para', '', 'legada', 2,
                       now + 345600, 'in', 'received')
        db.add_message(None, 'BM-de', 'BM-para', '', 'sem-objeto', 2,
                       now + 345600, 'in', 'received')
        db.add_message(None, 'BM-de', 'BM-para', '', 'normal', 2,
                       now - 100, 'out', 'sent')
        db.close()
        db2 = Database(directory)
        try:
            rows = {r['body']: r for r in db2.query(
                'SELECT body, timestamp FROM messages')}
            assert rows['legada']['timestamp'] == received_at
            assert rows['sem-objeto']['timestamp'] <= now + 3600
            assert rows['sem-objeto']['timestamp'] >= now - 60
            assert rows['normal']['timestamp'] == now - 100
        finally:
            db2.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_support_address_is_valid():
    from bmchat import SUPPORT_ADDRESS, SUPPORT_LABEL
    assert SUPPORT_LABEL
    status, version, stream, _ripe = addr_module.decode_address(
        SUPPORT_ADDRESS)
    assert status == 'success'
    assert version == 4
    assert stream == 1
    AddressKeys.from_address(SUPPORT_ADDRESS)


def test_support_report_excludes_secrets(client):
    pytest.importorskip('tkinter')
    from bmchat.gui.app import _build_support_report
    alice = client.create_identity('Alice', 1)
    bob = generate_keys(stream=1).address
    client.add_contact(bob, 'Bob')
    client.db.add_message(None, alice, bob, '', 'SEGREDO-XYZ-123', 2,
                          int(time.time()), 'out', 'sent')
    report = _build_support_report(client)
    assert 'DIAGNOSTICO BMCHAT' in report
    assert 'SEGREDO-XYZ-123' not in report
    assert client.identities[alice].signing_private.hex() not in report
    assert client.identities[alice].encryption_private.hex() not in report
    assert 'NAO incluido' in report
    assert '== Rede ==' in report
    assert 'pendentes' in report


def bob_keys_producer(client, bob):
    return client.identities[bob]


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
