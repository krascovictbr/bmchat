"""TTL global das mensagens (msg_ttl_seconds) + gestão útil de mensagens.

Cobre: default/faixa/clamp do setting, expires=now+ttl no objeto montado
(PoW mockado), target recalculado com o TTL, ACK expirando junto, broadcast/
chan/agendadas respeitando o TTL, retry com TTL guardado, sweep do watch,
exclusão individual e janela de aceitação da rede (interop).
"""
import shutil
import tempfile
import time

import pytest

from bmchat.core.client import Client
import bmchat.core.client as client_mod
from bmchat.crypto.keys import generate_keys
from bmchat.crypto.pow import (
    calculate_target, find_nonce_single_threaded, initial_hash_of,
)
from bmchat.net.manager import MAX_FUTURE_SKEW, MAX_PAST_SKEW
from bmchat.protocol import objects
from bmchat.protocol.const import (
    MSG_TTL_DEFAULT, MSG_TTL_MAX, MSG_TTL_MIN, MSG_TTL_PRESETS,
    OBJECT_BROADCAST, OBJECT_MSG, format_ttl_pt,
)

INSTANT_TARGET = 2 ** 64 - 1


@pytest.fixture
def client(monkeypatch):
    directory = tempfile.mkdtemp(prefix='bmchat-msgttl-')
    instance = Client(directory)
    seen = []

    def spy(nonce_trials, extra_bytes, object_len, ttl):
        seen.append((nonce_trials, extra_bytes, object_len, ttl))
        return INSTANT_TARGET

    def fake_run(self, unsigned, target, message_id=None, done_cb=None,
                 token=None, stop_event=None):
        nonce = find_nonce_single_threaded(initial_hash_of(unsigned), target)
        result = objects.complete_object(unsigned, nonce)
        if done_cb is not None:
            done_cb(result, nonce)

    def fake_quick(self, unsigned, target):
        return find_nonce_single_threaded(initial_hash_of(unsigned), target)

    monkeypatch.setattr(client_mod, 'calculate_target', spy)
    instance._run_pow_and_done = fake_run.__get__(instance, Client)
    instance._quick_pow = fake_quick.__get__(instance, Client)
    instance._ttl_targets = seen
    announced = []
    instance.net.announce_object = \
        lambda data, source=None: announced.append(bytes(data))
    instance._announced = announced
    yield instance
    instance.started = False
    instance.stop()
    shutil.rmtree(directory, ignore_errors=True)


def _wait_for(condition, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


def _drain(client):
    events = []
    while True:
        try:
            events.append(client.ui_queue.get_nowait())
        except Exception:
            break
    return events


def _inject_pubkey(client, address):
    keys = client.identities[address]
    unsigned = objects.build_pubkey_unsigned(
        int(time.time()) + 28 * 24 * 3600, 1, keys)
    complete = objects.complete_object(unsigned, 0)
    client._on_pubkey(objects.ParsedObject(complete), complete)
    assert client.has_pubkey(address)


def _make_pair(client):
    alice = client.create_identity('Alice', 1)
    bob = client.create_identity('Bob', 1)
    client.add_contact(bob, 'Bob')
    _inject_pubkey(client, bob)
    return alice, bob


def _sent_row(client, bob):
    rows = client.db.messages_for_conversation(bob)
    outbound = [row for row in rows if row['direction'] == 'out']
    return outbound[0] if outbound else None


def test_ttl_default_e_faixa(client):
    assert MSG_TTL_DEFAULT == 86400
    assert MSG_TTL_MIN == 3600
    assert MSG_TTL_MAX == 1814400
    assert client.get_msg_ttl() == 86400
    assert [value for value, _label in MSG_TTL_PRESETS] == [
        3600, 86400, 604800, 1814400]
    assert format_ttl_pt(3600) == '1 hora'
    assert format_ttl_pt(86400) == '1 dia'


def test_set_ttl_clampa_e_avisa(client):
    _drain(client)
    effective, clamped = client.set_msg_ttl(60)
    assert (effective, clamped) == (3600, True)
    assert client.get_msg_ttl() == 3600
    events = _drain(client)
    assert any(event[0] == 'log' and 'TTL' in event[2] for event in events)

    _drain(client)
    effective, clamped = client.set_msg_ttl(10 ** 9)
    assert (effective, clamped) == (MSG_TTL_MAX, True)
    assert any(event[0] == 'log' for event in _drain(client))

    _drain(client)
    effective, clamped = client.set_msg_ttl('lixo')
    assert effective == MSG_TTL_DEFAULT and clamped is True
    assert any(event[0] == 'log' for event in _drain(client))

    _drain(client)
    for valid in (3600, 86400, 604800, 1814400):
        effective, clamped = client.set_msg_ttl(valid)
        assert (effective, clamped) == (valid, False)
    assert not any(event[0] == 'log' and 'TTL' in event[2]
                   for event in _drain(client))


def test_get_ttl_defensivo_com_sujeira_no_banco(client):
    client.db.set_setting('msg_ttl_seconds', 'abc')
    assert client.get_msg_ttl() == MSG_TTL_DEFAULT
    client.db.set_setting('msg_ttl_seconds', '10')
    assert client.get_msg_ttl() == MSG_TTL_MIN
    client.db.set_setting('msg_ttl_seconds', str(10 ** 9))
    assert client.get_msg_ttl() == MSG_TTL_MAX


def test_send_message_expires_now_mais_ttl(client):
    alice, bob = _make_pair(client)
    client.set_msg_ttl(7200)
    before = int(time.time())
    status, error = client.send_message(alice, bob, '', 'oi com ttl')
    assert (status, error) == ('success', None)
    assert _wait_for(
        lambda: _sent_row(client, bob) is not None and
        _sent_row(client, bob)['status'] == 'sent')
    assert _wait_for(lambda: len(client._announced) >= 1)
    parsed = objects.ParsedObject(client._announced[-1])
    assert parsed.object_type == OBJECT_MSG
    assert parsed.version == 1
    assert before + 7200 - 10 <= parsed.expires <= int(time.time()) + 7200 + 10
    row = _sent_row(client, bob)
    assert row['ttl'] == 7200
    assert row['expires'] == parsed.expires
    ttls = [ttl for _n, _e, _ln, ttl in client._ttl_targets]
    assert 7200 in ttls


def test_target_endurece_com_ttl_maior():
    pequeno = calculate_target(1000, 1000, 2000, 3600)
    grande = calculate_target(1000, 1000, 2000, 1814400)
    assert grande < pequeno


def test_ack_expira_junto(client):
    client.set_msg_ttl(86400)
    before = int(time.time())
    packet, watch = client._build_ack_packet(1)
    assert len(watch) == 38
    parsed = objects.ParsedObject(packet[24:])
    assert parsed.object_type == OBJECT_MSG
    assert parsed.version == 1
    assert before + 86400 - 10 <= parsed.expires <= \
        int(time.time()) + 86400 + 10

    client.set_msg_ttl(3600)
    packet, _watch = client._build_ack_packet(1)
    parsed = objects.ParsedObject(packet[24:])
    assert int(time.time()) + 3600 - 10 <= parsed.expires <= \
        int(time.time()) + 3600 + 10

    fixed = int(time.time()) + 5000
    packet, _watch = client._build_ack_packet(1, expires=fixed)
    assert objects.ParsedObject(packet[24:]).expires == fixed


def test_watch_tem_deadline_e_sweep_marca_ack_failed(client):
    alice, bob = _make_pair(client)
    client.set_msg_ttl(3600)
    status, _error = client.send_message(alice, bob, '', 'oi')
    assert status == 'success'
    assert _wait_for(
        lambda: _sent_row(client, bob) is not None and
        _sent_row(client, bob)['status'] == 'sent')
    assert len(client._ack_watch) == 1
    key, entry = next(iter(client._ack_watch.items()))
    assert isinstance(entry, tuple) and len(entry) == 2
    _message_id, deadline = entry
    assert abs(deadline - (int(time.time()) + 3600)) < 30
    assert client._retry_ack_failed() == 0
    assert len(client._ack_watch) == 1
    assert client._prune_ack_watch(now=deadline + 10) == 1
    assert key not in client._ack_watch
    assert _sent_row(client, bob)['status'] == 'ack-failed'


def test_broadcast_e_chan_respeitam_ttl(client):
    from bmchat.crypto.keys import chan_keys_from_name
    alice = client.create_identity('Alice', 1)
    client.set_msg_ttl(604800)
    before = int(time.time())
    assert client.broadcast(alice, 'oi rede') == 'success'
    assert _wait_for(lambda: len(client._announced) >= 1)
    parsed = objects.ParsedObject(client._announced[-1])
    assert parsed.object_type == OBJECT_BROADCAST
    assert parsed.version == 5
    assert before + 604800 - 10 <= parsed.expires <= \
        int(time.time()) + 604800 + 10
    rows = client.db.messages_for_conversation(alice)
    assert rows and rows[-1]['ttl'] == 604800

    status, _info = client.subscribe('CANALTTL', 'CANALTTL')
    assert status == 'success'
    expected = chan_keys_from_name('CANALTTL', 1).address
    status, info = client.broadcast_chan(expected, 'oi canal')
    assert (status, info) == ('success', None)
    assert _wait_for(lambda: len(client._announced) >= 2)
    parsed = objects.ParsedObject(client._announced[-1])
    assert parsed.object_type == OBJECT_BROADCAST
    assert before + 604800 - 10 <= parsed.expires <= \
        int(time.time()) + 604800 + 10


def test_agendada_usa_ttl_do_envio(client):
    alice, bob = _make_pair(client)
    client.set_msg_ttl(3600)
    client.db.add_scheduled_message(alice, bob, 'agendada',
                                    int(time.time()) - 1)
    client.set_msg_ttl(7200)
    before = int(time.time())
    client.started = True
    try:
        client._send_due_scheduled()
    finally:
        client.started = False
    assert _wait_for(
        lambda: _sent_row(client, bob) is not None and
        _sent_row(client, bob)['status'] == 'sent')
    assert _wait_for(lambda: len(client._announced) >= 1)
    parsed = objects.ParsedObject(client._announced[-1])
    assert before + 7200 - 10 <= parsed.expires <= \
        int(time.time()) + 7200 + 10
    assert _sent_row(client, bob)['ttl'] == 7200


def test_retry_usa_ttl_guardado(client):
    alice = client.create_identity('Alice', 1)
    bob_keys = generate_keys(stream=1)
    bob = bob_keys.address
    client.add_contact(bob, 'Bob')
    client.set_msg_ttl(3600)
    status, _error = client.send_message(alice, bob, '', 'sem chave')
    assert status == 'success'
    row = _sent_row(client, bob)
    assert row['status'] == 'awaiting-pubkey'
    assert row['ttl'] == 3600
    # TTL global muda antes da chave chegar; o retry mantém o guardado.
    client.set_msg_ttl(7200)
    client.db.store_pubkey(bob, bob_keys.signing_public,
                           bob_keys.encryption_public)
    client.pubkeys[bob] = {
        'signing_public': bob_keys.signing_public,
        'encryption_public': bob_keys.encryption_public,
        'nonce_trials_per_byte': 1000,
        'payload_length_extra_bytes': 1000,
    }
    before = int(time.time())
    client._send_queued(bob)
    assert _wait_for(
        lambda: _sent_row(client, bob) is not None and
        _sent_row(client, bob)['status'] == 'sent')
    assert _wait_for(lambda: len(client._announced) >= 1)
    parsed = objects.ParsedObject(client._announced[-1])
    assert before + 3600 - 10 <= parsed.expires <= \
        int(time.time()) + 3600 + 10


def test_excluir_mensagem_preserva_conversa(client):
    alice = client.create_identity('Alice', 1)
    bob = generate_keys(stream=1).address
    now = int(time.time())
    first = client.db.add_message(None, alice, bob, '', 'uma', 2, now,
                                  'out', 'sent')
    second = client.db.add_message(None, alice, bob, '', 'duas', 2, now,
                                   'out', 'sent')
    client.db.delete_message(first)
    assert client.db.get_message(first) is None
    assert client.db.get_message(second) is not None
    assert [row['body'] for row in
            client.db.messages_for_conversation(bob)] == ['duas']


def test_ttl_dentro_da_janela_da_rede():
    sender = generate_keys(stream=1)
    recipient = generate_keys(stream=1)
    now = int(time.time())
    for ttl, _label in MSG_TTL_PRESETS:
        unsigned = objects.build_msg_unsigned(
            now + ttl, 1, sender, recipient.encryption_public,
            recipient.ripe, 'interop'.encode('utf-8'), 2, b'')
        raw = objects.complete_object(unsigned, 0)
        parsed = objects.ParsedObject(raw)
        assert parsed.object_type == OBJECT_MSG
        assert parsed.version == 1
        assert abs(parsed.expires - (now + ttl)) <= 2
        assert now - MAX_PAST_SKEW <= parsed.expires <= \
            now + MAX_FUTURE_SKEW
