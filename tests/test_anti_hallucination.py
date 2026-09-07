"""Regressão anti-alucinação: recepção de broadcast (chan).

Cobre os dois defeitos reais encontrados na auditoria 2026-09-07:
1. `Client._on_broadcast` acessava `incoming.stream`, atributo inexistente
   em `IncomingBroadcast` (só existem `sender_version`/`sender_stream`),
   derrubando 100% dos broadcasts com AttributeError.
2. Identidade chan (dono) sem inscrição separada registrava em
   `subscriptions` um `AddressKeys` sem `encryption_private_from_address`
   (None), fazendo `process_broadcast` falhar o decrypt e descartar o post.

Ambos passavam nos testes antigos porque `test_chan_subscribe_and_post`
exercitava só `objects.process_broadcast` direto com `from_address`.
"""
import tempfile
import time

from bmchat.core.client import Client
from bmchat.crypto.keys import chan_keys_from_name
from bmchat.protocol import objects


def _make_raw(chan_name, msg):
    keys = chan_keys_from_name(chan_name, 1)
    unsigned = objects.build_broadcast_unsigned(
        int(time.time()) + 3600, 1, keys, msg.encode('utf-8'), 2)
    return objects.complete_object(unsigned, 0), keys


def _drain(client):
    while not client.ui_queue.empty():
        client.ui_queue.get()


def test_broadcast_via_subscription_recebido():
    tmp = tempfile.mkdtemp(prefix='bmchat-audit-sub-')
    c = Client(tmp)
    raw, keys = _make_raw('AUDITFIXSUB123', 'ola via sub')
    c.db.add_subscription(keys.address, 'AUDITFIXSUB123')
    _drain(c)
    c._on_broadcast(objects.ParsedObject(raw), raw)
    rows = c.db.messages_for_conversation(keys.address)
    assert len(rows) == 1
    assert rows[0]['body'] == 'ola via sub'
    evs = []
    while not c.ui_queue.empty():
        evs.append(c.ui_queue.get())
    assert any(e[0] == 'broadcast' and e[1] == keys.address for e in evs)


def test_broadcast_owner_chan_sem_sub_recebido():
    tmp = tempfile.mkdtemp(prefix='bmchat-audit-owner-')
    c = Client(tmp)
    raw, keys = _make_raw('AUDITFIXOWNER9', 'msg do dono')
    c.db.add_identity(
        keys.address, 'meuchan', 1,
        keys.signing_private, keys.encryption_private,
        1000, 1000, chan=1, chan_label='AUDITFIXOWNER9')
    c.identities[keys.address] = keys
    assert c.db.all_subscriptions() == []
    _drain(c)
    c._on_broadcast(objects.ParsedObject(raw), raw)
    rows = c.db.messages_for_conversation(keys.address)
    assert len(rows) == 1
    assert rows[0]['body'] == 'msg do dono'
