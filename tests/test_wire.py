import shutil
import socket
import threading
import time

import pytest

from bmchat.core.client import Client
from bmchat.protocol import objects
from bmchat.crypto.pow import (
    find_nonce_single_threaded, initial_hash_of,
)
from bmchat.net.peer import PeerConnection
from bmchat.net.peers import Peer
import bmchat.core.client as client_mod
import bmchat.net.manager as manager_mod

TARGET = 2 ** 52


def _fake_check(*a, **k):
    return True


FAKE_CHECK = _fake_check


@pytest.fixture(scope='module')
def powered_clients(tmp_path_factory):
    root = tmp_path_factory.mktemp('wire')
    directory_a = str(root / 'a')
    directory_b = str(root / 'b')

    def fake_run(self, unsigned, target, message_id=None, done_cb=None,
                 token=None, stop_event=None):
        nonce = find_nonce_single_threaded(initial_hash_of(unsigned), target)
        result = objects.complete_object(unsigned, nonce)
        if done_cb is not None:
            done_cb(result, nonce)

    def fake_quick(self, unsigned, target):
        return find_nonce_single_threaded(initial_hash_of(unsigned), target)

    client_a = Client(directory_a)
    client_b = Client(directory_b)
    client_a.net.peers.entries.clear()
    client_b.net.peers.entries.clear()
    client_a.db.set_setting('max_connections', 4)
    client_b.db.set_setting('max_connections', 4)
    client_a._run_pow_and_done = fake_run.__get__(client_a, Client)
    client_a._quick_pow = fake_quick.__get__(client_a, Client)
    client_b._run_pow_and_done = fake_run.__get__(client_b, Client)
    client_b._quick_pow = fake_quick.__get__(client_b, Client)
    original = client_mod.calculate_target
    original_check = manager_mod.is_proof_of_work_sufficient
    original_client_check = client_mod.is_proof_of_work_sufficient
    client_mod.calculate_target = lambda *a, **k: TARGET
    manager_mod.is_proof_of_work_sufficient = FAKE_CHECK
    client_mod.is_proof_of_work_sufficient = FAKE_CHECK

    yield client_a, client_b

    client_mod.calculate_target = original
    manager_mod.is_proof_of_work_sufficient = original_check
    client_mod.is_proof_of_work_sufficient = original_client_check
    client_a.stop()
    client_b.stop()
    shutil.rmtree(root, ignore_errors=True)


def _wait(condition, timeout=30, step=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(step)
    return False


def test_wire_message_roundtrip(powered_clients):
    client_a, client_b = powered_clients
    alice = client_a.create_identity('Alice', 1)
    bob = client_b.create_identity('Bob', 1)
    client_a.add_contact(bob, 'Bob')
    client_b.add_contact(alice, 'Alice')

    client_a.start()
    client_b.start()

    # servidor de entrada para B (handshake do lado do servidor)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(4)
    port = listener.getsockname()[1]

    accepted = []
    stop = threading.Event()

    def server():
        listener.settimeout(0.5)
        while not stop.is_set():
            try:
                sock, addr = listener.accept()
            except socket.timeout:
                continue
            sock.settimeout(60)
            incoming = PeerConnection(
                client_b.net, Peer('127.0.0.1', port), sock=sock)
            client_b.net.connections[incoming.peer_key] = incoming
            incoming.start()
            accepted.append(incoming)
    threading.Thread(target=server, daemon=True).start()

    client_a.net.add_peer('127.0.0.1', port)
    assert _wait(lambda: client_a.net.connection_count >= 1 or not accepted,
                 timeout=15)

    # A pede a chave pública do B e B responde publicando; A recebe via rede
    client_a.request_pubkey(bob)
    assert _wait(
        lambda: client_a.pubkeys.get(bob),
        timeout=40), 'pubkey do Bob não chegou a Alice pela rede'

    # Alice envia mensagem; Bob deve recebê-la via rede
    status, error = client_a.send_message(alice, bob, '', 'Olá via rede!')
    assert status == 'success'
    assert _wait(
        lambda: any(
            r['direction'] == 'in' and r['body'] == 'Olá via rede!'
            for r in client_b.db.messages_for_conversation(bob)),
        timeout=40), 'mensagem não chegou ao Bob pela rede'

    # Bob deve receber e o ack retorna para Alice
    assert _wait(
        lambda: any(
            r['direction'] == 'out' and r['status'] == 'ackreceived'
            for r in client_a.db.messages_for_conversation(bob)),
        timeout=40), 'ack do Bob não chegou à Alice'

    stop.set()
    listener.close()
