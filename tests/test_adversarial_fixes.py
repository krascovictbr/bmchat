"""Regressão das correções adversariais 2026-09-08 (furos deixados)."""

import os
import stat
import time
from io import BytesIO

import pytest

from bmchat.crypto import encrypted_db
from bmchat.gui.app import App


def _make_client(tmp_path, name='c'):
    from bmchat.core.client import Client
    directory = str(tmp_path / name)
    client = Client(directory)
    client.net.peers.entries.clear()
    return client


# ADV-F1: calc com guard + altura igual ao render (imagem alta/corrompida)
def test_adv_calc_matches_render_tall_and_corrupt():
    import base64 as b64
    from PIL import Image
    img = Image.new('RGB', (200, 1000), color='green')
    buf = BytesIO()
    img.save(buf, format='PNG')
    tall = {'mime': 'image/png',
            'data': b64.b64encode(buf.getvalue()).decode('ascii')}
    h_calc = App._calc_attachment_height(App, tall, 300, False)
    # render sem Tk: usa fake que captura altura via thumbnail manual?
    # Comportamento esperado: mesma razão do render (min com 300px altura).
    # 200x1000 -> ratio=min(300/200,300/1000)=0.3 -> h=308
    assert h_calc == int(1000 * 0.3) + 8 == 308

    trunc = {'mime': 'image/png',
             'data': b64.b64encode(buf.getvalue()[:100]).decode('ascii')}
    assert App._calc_attachment_height(App, trunc, 300, False) == 48

    huge = {'mime': 'image/png', 'data': 'A' * 400_000}
    assert App._calc_attachment_height(App, huge, 300, False) == 48


# ADV-F1b: parse aceita ':' no nome, sanitiza ']' no envio
def test_adv_attachment_filename_colon_roundtrip():
    from bmchat.gui.app import App as A
    body = 'texto\n\n[attachment:meu:arquivo.txt:text/plain:SGk=]'
    clean, atts = A._parse_attachments(A, body)
    assert len(atts) == 1
    assert atts[0]['filename'] == 'meu:arquivo.txt'
    assert atts[0]['mime'] == 'text/plain'
    assert A._sanitize_attachment_filename('a]b[c:d') == 'a_b_c:d'


# ADV-F2: lock dir 0700 + stale race verifica vencedor
def test_adv_lock_dir_mode_and_stale_verify(tmp_path):
    from bmchat.core.client import Client
    directory = str(tmp_path / 'lockmode')
    client = Client(directory)
    client.net.peers.entries.clear()
    orig_start = client.net.start
    client.net.start = lambda streams: None
    try:
        client.start()
        mode = stat.S_IMODE(os.stat(directory).st_mode)
        assert mode == 0o700
        # stale claim com vencedor concorrente deve barrar
        lock_path = os.path.join(directory, 'bmchat.lock')
        saved = open(lock_path).read()
        # simula outro reclamante vencendo: escreve PID distinto após claim
        orig_replace = None
        import os as _os
        orig_replace = _os.replace

        def fake_replace(src, dst):
            orig_replace(src, dst)
            # sobrescreve com outro PID (vencedor)
            with open(dst, 'w') as handle:
                handle.write('12345678')

        _os.replace = fake_replace
        # força stale: lock com PID morto
        with open(lock_path, 'w') as handle:
            handle.write('99999998')
        orig_alive = Client._lock_owner_alive
        Client._lock_owner_alive = staticmethod(lambda o, m: False)
        second = Client(directory)
        second.net.peers.entries.clear()
        second.net.start = lambda streams: None
        try:
            with pytest.raises(RuntimeError):
                second.start()
        finally:
            Client._lock_owner_alive = orig_alive
            _os.replace = orig_replace
            with open(lock_path, 'w') as handle:
                handle.write(saved)
            try:
                second.stop()
            except Exception:
                pass
    finally:
        client.net.start = orig_start
        try:
            client.stop()
        except Exception:
            pass


# ADV-F3: retry offline não queima PoW
def test_adv_retry_offline_skips_pow(tmp_path):
    client = _make_client(tmp_path, 'off')
    try:
        alice = client.create_identity('A', 1)
        from bmchat.crypto.keys import generate_keys
        bob = generate_keys(stream=1).address
        client.add_contact(bob, 'B')
        client.db.add_message(None, alice, bob, '', 'oi', 2,
                              int(time.time()), 'out', 'awaiting-pubkey')
        burned = []
        client.request_pubkey = lambda *a, **k: burned.append(1)
        client._pow_and_publish_message = lambda *a, **k: burned.append(1)
        client.started = True
        # sem peers -> offline
        assert client.net.established_count == 0
        client._retry_awaiting()
        assert burned == []
        # online -> queima
        type(client.net).established_count = property(lambda self: 1)
        try:
            client._retry_awaiting()
        finally:
            try:
                delattr(type(client.net), 'established_count')
            except Exception:
                pass
            # restaura property original (delattr removeu; recoloca)
            from bmchat.net.manager import NetworkManager
            # garante que a property existe para próximos testes
            if not isinstance(
                    getattr(NetworkManager, 'established_count', None),
                    property):
                NetworkManager.established_count = property(  # noqa: B010
                    lambda self: sum(
                        1 for c in self.connections.values()
                        if c.established))
        assert burned != []
    finally:
        client.stop()


# ADV-F4: store não passa de 8000
def test_adv_store_caps_at_max(tmp_path):
    from bmchat.net.manager import NetworkManager, INVENTORY_MAX
    from bmchat.core.database import Database
    directory = str(tmp_path / 'cap')
    os.makedirs(directory, exist_ok=True)
    db = Database(directory)
    try:
        mgr = NetworkManager(directory, db)
        for i in range(INVENTORY_MAX):
            mgr.inventory[bytes([i % 256]) * 16 + bytes(
                [i // 256 % 256]) * 16] = b'x' * 10
        mgr.store_object(b'novo' + os.urandom(100))
        assert len(mgr.inventory) <= INVENTORY_MAX
    finally:
        db.close()


# ADV-F5: restore sucesso não deixa .bak órfão do temp
def test_adv_restore_no_orphan_bak(tmp_path):
    plain = tmp_path / 'p.db'
    plain.write_bytes(b'data' + os.urandom(50))
    enc = str(tmp_path / 'p.enc')
    encrypted_db.export_encrypted_backup(str(plain), enc, 'senha-forte-123')
    # simula fluxo do App: unlink antes do import (sem .bak órfão)
    import tempfile as _tf
    fd, tmp = _tf.mkstemp(dir=str(tmp_path), suffix='.db')
    os.close(fd)
    os.unlink(tmp)
    assert not os.path.exists(tmp)
    encrypted_db.import_encrypted_backup(enc, tmp, 'senha-forte-123')
    assert os.path.exists(tmp)
    assert not os.path.exists(tmp + '.bak')
    # cleanup do App também remove .bak se existir
    open(tmp + '.bak', 'w').write('x')
    App._cleanup_temp(App, tmp)
    assert not os.path.exists(tmp)
    assert not os.path.exists(tmp + '.bak')


# ADV-F6: ack retry não consome slot sem PoW (identidade sumida)
def test_adv_ack_retry_no_slot_without_identity(tmp_path):
    client = _make_client(tmp_path, 'ackslot')
    try:
        alice = client.create_identity('A', 1)
        from bmchat.crypto.keys import generate_keys
        bob_keys = generate_keys(stream=1)
        bob = bob_keys.address
        # pubkey conhecida mas identidade de origem apagada do dict
        client.pubkeys[bob] = {
            'signing_public': b'\x04' + b'\x01' * 64,
            'encryption_public': b'\x04' + b'\x02' * 64,
            'nonce_trials_per_byte': 1000,
            'payload_length_extra_bytes': 1000,
        }
        mid = client.db.add_message(None, alice, bob, '', 'oi', 2,
                                    int(time.time()), 'out', 'ack-failed')
        # remove identidade (simula apagada)
        del client.identities[alice]
        launched = []
        client._pow_and_publish_message = lambda *a, **k: launched.append(1)
        row = {'id': mid, 'to_address': bob}
        client._retry_one_ack_failed(row)
        assert launched == []
        assert client._ack_retry_counts.get(mid, 0) == 0
        # resend manual com identidade ausente não consome e avisa
        status, _ = client.resend_message(mid)
        assert status == 'error'
        assert client._ack_retry_counts.get(mid, 0) == 0
    finally:
        client.stop()


# ADV-F8: senha unicode funciona
def test_adv_unicode_password_roundtrip(tmp_path):
    plain = tmp_path / 'u.db'
    plain.write_bytes(os.urandom(200))
    enc = str(tmp_path / 'u.enc')
    pwd = 'senha-\U0001f496-123forte'
    encrypted_db.export_encrypted_backup(str(plain), enc, pwd)
    out = str(tmp_path / 'v.db')
    encrypted_db.import_encrypted_backup(enc, out, pwd)
    assert open(out, 'rb').read() == plain.read_bytes()
