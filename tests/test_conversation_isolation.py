"""Isolamento de conversas DM (regressão: vazamento teste vs SUPORTE).

Cobre o bug reportado: contato "teste" com mesmo endereço da própria
identidade fazia diagnósticos ao SUPORTE aparecerem no chat do teste,
pois messages_for_conversation usava OR (to==addr OR from==addr).

Garante:
- DM normal (contato != identidade) só mostra o par exato.
- Self-chat (contato == identidade) mostra tudo PARA si, nunca outbound
  para outros (ex.: diagnóstico ao SUPORTE).
- Diagnóstico ao SUPORTE aparece SÓ na conversa do SUPORTE.
- send_message_with_id retorna id sem race (Command usa, sem SELECT).
"""
import shutil
import tempfile
import time

from bmchat.core.database import Database
from bmchat.core.client import Client
from bmchat.gui.commands import SendMessageCommand


def _mkdb():
    d = tempfile.mkdtemp(prefix='bmchat-isol-')
    db = Database(d)
    return d, db


def test_dm_isolado_nao_vaza_diagnostico():
    d, db = _mkdb()
    try:
        SELF = 'BM-SELF-ISOL'
        SUP = 'BM-SUP-ISOL'
        OTHER = 'BM-OTHER-ISOL'
        now = int(time.time())
        db.add_message(None, SELF, SELF, '', 'ok self', 1, now, 'out', 'sent')
        db.add_message(None, SELF, SUP, '', 'DIAGNOSTICO...', 1, now + 1, 'out', 'awaiting-pubkey')
        db.add_message(None, OTHER, SELF, '', 'hello teste', 1, now + 2, 'in', 'received')
        db.add_message(None, SELF, OTHER, '', 'reply', 1, now + 3, 'out', 'sent')

        # OR antigo vazava (4); DM isolado não
        assert len(db.messages_for_conversation(SELF)) == 4
        dm_self = db.messages_for_dm(SELF, SELF)
        assert all(r['to_address'] == SELF for r in dm_self), dm_self
        assert not any('DIAG' in (r['body'] or '') for r in dm_self)

        dm_other = db.messages_for_dm(OTHER, SELF)
        assert len(dm_other) == 2  # OTHER<->SELF nas duas direções

        dm_sup = db.messages_for_dm(SUP, SELF)
        assert len(dm_sup) == 1
        assert 'DIAG' in (dm_sup[0]['body'] or '')

        # last/count/mark/delete isolados
        assert 'DIAG' not in (db.last_message_for_dm(SELF, SELF)['body'] or '')
        assert db.count_for_dm(SELF, SELF) == 2
        db.mark_dm_read(SELF, SELF)
        # Não deve marcar nada como read aqui além do inbound? Verifica sem erro
        db.delete_dm_conversation(SUP, SELF)
        assert db.count_for_dm(SUP, SELF) == 0
        # Self-chat ainda intacto (só self-to-self deletado em delete_dm self?)
        # delete_dm self apaga só self-to-self por segurança
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_send_message_with_id_sem_race():
    d = tempfile.mkdtemp(prefix='bmchat-isol-send-')
    try:
        c = Client(d)
        alice = c.create_identity('Alice', 1)
        # Usa endereço válido gerado para bob
        from bmchat.crypto.keys import generate_keys
        bob = generate_keys(stream=1).address
        c.add_contact(bob, 'Bob')
        # Força target gigante para PoW rápido via mock de calculate_target
        import bmchat.core.client as mod
        orig = mod.calculate_target
        mod.calculate_target = lambda *a, **k: 2 ** 52
        from bmchat.crypto.pow import find_nonce_single_threaded, initial_hash_of
        from bmchat.protocol import objects

        def fake_run(self, unsigned, target, message_id=None, done_cb=None,
                     token=None, stop_event=None):
            nonce = find_nonce_single_threaded(initial_hash_of(unsigned), target)
            res = objects.complete_object(unsigned, nonce)
            if done_cb:
                done_cb(res, nonce)

        c._run_pow_and_done = fake_run.__get__(c, Client)
        c._quick_pow = lambda u, t: find_nonce_single_threaded(initial_hash_of(u), t)
        # Injeta pubkey do bob para envio direto
        bob_keys = c.identities[alice]  # usa mesma estrutura? Não, precisa pubkey real
        # Cria segunda identidade para simular bob com chave conhecida
        bob_addr = c.create_identity('BobLocal', 1)
        # Publica pubkey fake via _on_pubkey? Simplifica: injeta direto
        keys = c.identities[bob_addr]
        c.pubkeys[bob_addr] = {
            'signing_public': keys.signing_public,
            'encryption_public': keys.encryption_public,
            'nonce_trials_per_byte': 1000,
            'payload_length_extra_bytes': 1000,
        }
        status, mid = c.send_message_with_id(alice, bob_addr, '', 'oi sem race')
        assert status == 'success'
        assert isinstance(mid, int)
        row = c.db.get_message(mid)
        assert row is not None
        assert row['body'] == 'oi sem race'

        # Command usa o id sem SELECT (sem race)
        cmd = SendMessageCommand(c, alice, bob_addr, 'oi via command')
        st, err = cmd.execute()
        assert st == 'success', err
        assert cmd._message_id is not None
        assert c.db.get_message(cmd._message_id)['body'] == 'oi via command'
        mod.calculate_target = orig
        c.stop()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_self_send_loopback_sem_rede():
    """Self-chat (contato == identidade) entrega local, sem PoW/rede."""
    d = tempfile.mkdtemp(prefix='bmchat-isol-self-')
    try:
        c = Client(d)
        alice = c.create_identity('Alice', 1)
        assert c.has_pubkey(alice)
        st, mid = c.send_message_with_id(alice, alice, '', 'teste self')
        assert st == 'success'
        out = c.db.get_message(mid)
        assert out['status'] == 'ackreceived'
        rows = c.db.messages_for_dm(alice, alice)
        # outbound + inbound
        assert len(rows) == 2
        assert not any('DIAG' in (r['body'] or '') for r in rows)
        # Reenvio de travada antiga converte sem PoW
        stuck = c.db.add_message(
            None, alice, alice, '', 'travada', 1, int(time.time()),
            'out', 'awaiting-pubkey')
        st2, _ = c.resend_message(stuck)
        assert st2 == 'success'
        assert c.db.get_message(stuck)['status'] == 'ackreceived'
        c.stop()
    finally:
        shutil.rmtree(d, ignore_errors=True)
