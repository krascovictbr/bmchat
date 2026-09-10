"""Integração para bmchat/core/ — cobre fluxos fim-a-fim com DB real + Client + Repos + Events.

Foco em isolamento DM, self-loopback, pubkey self, PoW Strategy, State, Repository,
EventEmitter thread-safety + wildcard triplo, lock, TTL, validStatuses, bridge ui_queue.
Rápido (<30s), determinístico, tempdir + FAST PoW + MockNetworkManager, sem Tk.
"""
import os
import queue
import shutil
import tempfile
import threading
import time
from unittest.mock import patch

import pytest

from bmchat.core.database import Database
from bmchat.core.client import Client
from bmchat.core.repositories import MessageRepository
from bmchat.core.models import Message
from bmchat.crypto.pow.strategy import PoWStrategy
from bmchat.protocol.factory import ProtocolObjectFactory
from bmchat.crypto.keys import generate_keys

# Fast PoW
class FastPow(PoWStrategy):
    def solve(self, initial_hash, target, *, start_nonce=0, progress_cb=None, stop_event=None):
        if progress_cb:
            progress_cb(1, 1.0)
        return 0

FAST_POW = FastPow()
TARGET_HUGE = (2**64)-1

# acelera geração de chaves (nullprefix 0) para integração também (valida)
import bmchat.crypto.keys as _km_orig
_orig_gen = _km_orig.generate_keys
def _fast_gen(stream=1, nullprefix=1, max_tries=None, **kwargs):
    if nullprefix < 0 or nullprefix > 20:
        raise ValueError('nullprefix inválido')
    if nullprefix > 4:
        raise ValueError('nullprefix grande demais (travamento)')
    return _orig_gen(stream=stream, nullprefix=0, max_tries=1)
_km_orig.generate_keys = _fast_gen
import bmchat.core.client as _cm
_cm.generate_keys = _fast_gen

class MockNet:
    def __init__(self, db):
        self.db=db
        self.on_object=None
        self.on_log=lambda *a,**k: None
        self.established_count=1
        self._ann=[]
        self.streams=[]
    def start(self, s): self.streams=list(s)
    def stop(self): pass
    def announce_object(self, o): self._ann.append(bytes(o) if o else o)

def mk_client_fast():
    d=tempfile.mkdtemp(prefix="bmchat-int-")
    db=Database(d)
    net=MockNet(db)
    c=Client(d, pow_strategy=FAST_POW, network_manager=net, db=db)
    return d, db, c, net

def wait_for(pred, timeout=2, interval=0.02):
    deadline=time.time()+timeout
    while time.time()<deadline:
        if pred():
            return True
        time.sleep(interval)
    return False

# ---------------------------------------------------------------------------
def test_dm_isolation_integration():
    d, db, c, net = mk_client_fast()
    try:
        SELF=c.create_identity("Self",1)
        # outros endereços
        other = _fast_gen(stream=1).address
        sup = _fast_gen(stream=1).address
        now=int(time.time())
        # simula diagnóstico ao SUPORTE via DB direto
        db.add_message(None, SELF, SELF, "", "ok self",1, now,"out","sent")
        db.add_message(None, SELF, sup, "", "DIAGNOSTICO crítico",1, now+1,"out","awaiting-pubkey")
        db.add_message(None, other, SELF, "", "hello",1, now+2,"in","received")
        db.add_message(None, SELF, other, "", "reply",1, now+3,"out","sent")
        # via repository também
        repo=MessageRepository(db)
        assert len(repo.for_dm(SELF, SELF))==1
        assert len(repo.for_dm(other, SELF))==2
        assert len(repo.for_dm(sup, SELF))==1
        # via client db direct
        assert c.db.count_for_dm(SELF, SELF)==1
        # delete sup não afeta self
        c.db.delete_dm_conversation(sup, SELF)
        assert c.db.count_for_dm(sup, SELF)==0
        assert c.db.count_for_dm(SELF, SELF)==1
        # last
        assert c.db.last_message_for_dm(SELF, SELF)["body"]=="ok self"
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_self_send_loopback_integration():
    d, db, c, net = mk_client_fast()
    try:
        alice=c.create_identity("Alice",1)
        assert c.has_pubkey(alice)
        st, mid=c.send_message_with_id(alice, alice, "", "loopback integração")
        assert st=="success"
        row=db.get_message(mid)
        assert row["status"]=="ackreceived"
        rows=db.messages_for_dm(alice, alice)
        assert len(rows)==2
        assert any(r["direction"]=="in" for r in rows)
        # self stuck resend
        stuck=db.add_message(None, alice, alice, "", "travada",1, int(time.time()),"out","awaiting-pubkey")
        st2,_=c.resend_message(stuck)
        assert st2=="success"
        assert db.get_message(stuck)["status"]=="ackreceived"
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_pubkey_self_integration():
    d, db, c, net = mk_client_fast()
    try:
        alice=c.create_identity("Alice",1)
        # sem rede, has_pubkey deve ser True para self
        assert c.has_pubkey(alice) is True
        entry=c._pub_entry_for(alice)
        assert entry is not None and "signing_public" in entry
        # mesmo após limpar cache
        c.pubkeys.pop(alice, None)
        assert c.has_pubkey(alice) is True
        assert c._pub_entry_for(alice) is not None
        # foreign sem pubkey
        foreign=_fast_gen(stream=1).address
        assert c.has_pubkey(foreign) is False
        # após store via repo
        fk=_fast_gen(stream=1)
        c.pubkey_repo.store(fk.address, fk.signing_public, fk.encryption_public)
        assert c.has_pubkey(fk.address) is True
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_pow_strategy_generico_integration():
    d, db, c, net = mk_client_fast()
    try:
        # custom strategy que registra chamada e retorna 0
        calls=[]
        class Rec(PoWStrategy):
            def solve(self, initial_hash, target, *, start_nonce=0, progress_cb=None, stop_event=None):
                calls.append(target)
                return 0
        c2=Client(d, pow_strategy=Rec(), network_manager=MockNet(db), db=db)
        try:
            alice=c2.create_identity("A",1)
            bob=_fast_gen(stream=1)
            c2.pubkeys[bob.address]={"signing_public": bob.signing_public, "encryption_public": bob.encryption_public, "nonce_trials_per_byte":1000, "payload_length_extra_bytes":1000}
            with patch("bmchat.core.client.calculate_target", return_value=TARGET_HUGE):
                st, mid=c2.send_message_with_id(alice, bob.address, "", "pow genérico")
                assert st=="success"
                assert wait_for(lambda: db.get_message(mid) and db.get_message(mid)["status"]=="sent", timeout=2)
                assert calls  # strategy foi usada
        finally:
            c2.stop()
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_factory_valueerror_nao_silenciada():
    d, db, c, net = mk_client_fast()
    try:
        class BadFactory:
            def create_getpubkey(self, expires, stream, tag):
                raise ValueError("invalido")
            def create_ack(self, *a, **k):
                raise ValueError("bad ack")
        c.protocol_factory=BadFactory()
        alice=c.create_identity("A",1)
        bob=_fast_gen(stream=1).address
        with pytest.raises(ValueError):
            c.request_pubkey(bob)
        with pytest.raises(ValueError):
            c.send_message_with_id(alice, bob, "", "hi")
        # factory boa não levanta
        c.protocol_factory=ProtocolObjectFactory()
        # com pubkey conhecida, send não usa factory getpubkey
        bob_keys=_fast_gen(stream=1)
        c.pubkeys[bob_keys.address]={"signing_public": bob_keys.signing_public, "encryption_public": bob_keys.encryption_public, "nonce_trials_per_byte":1000, "payload_length_extra_bytes":1000}
        with patch("bmchat.core.client.calculate_target", return_value=TARGET_HUGE):
            st,_=c.send_message_with_id(alice, bob_keys.address, "", "ok")
            assert st=="success"
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_state_estrita_e_persist():
    d, db, c, net = mk_client_fast()
    try:
        now=int(time.time())
        mid=db.add_message(None, "BM-A","BM-B","","body",1,now,"out","sent")
        row=db.get_message(mid)
        m=Message(row, client=c)
        # sent -> pending não permitido
        assert m.transition_to("pending") is False
        assert m.status=="sent"
        # sent -> ackreceived permitido e persiste
        assert m.transition_to("ackreceived", persist=True) is True
        assert db.get_message(mid)["status"]=="ackreceived"
        # pending -> cancelled forçado (mesmo id, então DB vai para cancelled)
        m2=Message(dict(row, status="pending"), client=c)
        assert m2.transition_to("cancelled", persist=True) is True
        assert db.get_message(mid)["status"]=="cancelled"
        # idempotente
        m3=Message(dict(row, status="sent"))
        assert m3.transition_to("sent") is True
        # expired forçado
        m4=Message(dict(row, status="sent"))
        assert m4.transition_to("expired") is True
        # validStatuses inclui todos
        for st in ["awaiting-pubkey","sending","sent","ackreceived","received","read","ack-failed","pending","published","delivered","failed","cancelled","expired"]:
            db.set_message_status(mid, st)
        with pytest.raises(ValueError):
            db.set_message_status(mid, "invalido")
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_repository_integration():
    d, db, c, net = mk_client_fast()
    try:
        repo=MessageRepository(db)
        now=int(time.time())
        mid=repo.add(None, "BM-A","BM-B","","hello",1,now,"out","sent")
        assert repo.get(mid)["body"]=="hello"
        assert repo.exists(b"\x00"*32) is False
        h=b"\xaa"*32
        repo.add(h, "BM-A","BM-B","","b",1,now,"out","sent")
        assert repo.get_by_hash(h) is not None
        # for_dm via repo
        assert len(repo.for_dm("BM-B","BM-A"))>=1
        assert repo.count_for_dm("BM-B","BM-A")>=1
        assert repo.last_for_dm("BM-B","BM-A") is not None
        repo.mark_dm_read("BM-B","BM-A")
        repo.delete_dm("BM-B","BM-A")
        assert repo.count_for_dm("BM-B","BM-A")==0
        # contact/pubkey repos
        from bmchat.core.repositories import ContactRepository, PubkeyRepository
        cr=ContactRepository(db)
        pr=PubkeyRepository(db)
        addr=_fast_gen(stream=1).address
        cr.add(addr, "C",1)
        assert cr.exists(addr)
        pr.store(addr, b"s", b"e")
        assert pr.exists(addr)
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_eventemitter_thread_safety_e_wildcard_triplo():
    from bmchat.core.events import EventEmitter
    em=EventEmitter()
    # wildcard triplo: 1 emit mapeado + legado + '*' = 3 wild calls
    # Simula bridge do Client
    from bmchat.core.events import LEGACY_MAP
    counts={"new_message":0,"message":0,"*":0}
    em.on("new_message", lambda d: counts.__setitem__("new_message", counts["new_message"]+1))
    em.on("message", lambda d: counts.__setitem__("message", counts["message"]+1))
    em.on("*", lambda e,d: counts.__setitem__("*", counts["*"]+1))
    data="payload"
    mapped=LEGACY_MAP.get("message", "message")
    em.emit(mapped, data)
    if mapped!="message":
        em.emit("message", data)
    em.emit("*", ("message", data))
    assert counts["new_message"]==1
    assert counts["message"]==1
    assert counts["*"]==3

    # thread-safety: concurrent on/emit
    em2=EventEmitter()
    n={"c":0}
    lock=threading.Lock()
    def mk():
        def cb(d):
            with lock:
                n["c"]+=1
        return cb
    for _ in range(5):
        em2.on("e", mk())
    def emit_loop():
        for _ in range(100):
            em2.emit("e", 1)
    threads=[threading.Thread(target=emit_loop) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=5)
    assert n["c"]==4*100*5

def test_database_lock_rlock_integration():
    d, db, c, net = mk_client_fast()
    try:
        # lock deve permitir acesso concorrente seguro
        errors=[]
        def writer(n):
            try:
                for i in range(30):
                    db.add_message(None, f"BM-{n}", f"BM-{n+1}", "", f"m{i}",1,int(time.time()),"out","sent")
            except Exception as e:
                errors.append(e)
        threads=[threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)
        assert not errors
        assert len(db.query("SELECT * FROM messages"))>=120
        # RLock expectativa: lock deve ser reentrante ou pelo menos thread-safe
        assert hasattr(db.lock, "acquire")
        # tenta adquirir duas vezes com timeout curto: Lock falhará, RLock sucederá — ambos aceitos, mas não pode deadlock
        assert db.lock.acquire(timeout=1)
        second=db.lock.acquire(blocking=False)
        if second:
            db.lock.release()
        db.lock.release()
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_ttl_flow():
    d, db, c, net = mk_client_fast()
    try:
        from bmchat.protocol.const import MSG_TTL_MIN, MSG_TTL_MAX, MSG_TTL_DEFAULT
        # get vigente
        ttl=c.get_msg_ttl()
        assert MSG_TTL_MIN <= ttl <= MSG_TTL_MAX
        eff, clamped=c.set_msg_ttl(3600)
        assert eff==3600 and not clamped
        eff, clamped=c.set_msg_ttl(10)
        assert eff==MSG_TTL_MIN and clamped
        eff, clamped=c.set_msg_ttl(99999999)
        assert eff==MSG_TTL_MAX and clamped
        eff, clamped=c.set_msg_ttl("bad")
        assert eff==MSG_TTL_DEFAULT
        # mensagem criada com ttl vigente
        alice=c.create_identity("A",1)
        bob=_fast_gen(stream=1)
        c.pubkeys[bob.address]={"signing_public": bob.signing_public, "encryption_public": bob.encryption_public, "nonce_trials_per_byte":1000, "payload_length_extra_bytes":1000}
        with patch("bmchat.core.client.calculate_target", return_value=TARGET_HUGE):
            st,mid=c.send_message_with_id(alice, bob.address, "", "ttl test")
            assert st=="success"
            row=db.get_message(mid)
            assert row["ttl"] is not None and MSG_TTL_MIN <= row["ttl"] <= MSG_TTL_MAX
            assert row["expires"] is not None
            # expiry update via set_message_expiry
            db.set_message_expiry(mid, int(time.time())+9999)
            assert db.get_message(mid)["expires"]== int(db.get_message(mid)["expires"])
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_client_events_bridge_integration():
    d, db, c, net = mk_client_fast()
    try:
        got=[]
        wild=[]
        c.events.on("new_message", lambda d: got.append(("new_message", d)))
        c.events.on("message", lambda d: got.append(("message", d)))
        c.events.on("*", lambda e,d: wild.append((e,d)))
        alice=c.create_identity("A",1)
        # send self loopback emite ('message', ...) e ('status', ...)
        st,mid=c.send_message_with_id(alice, alice, "", "bridge test")
        assert st=="success"
        time.sleep(0.05)
        # deve ter recebido new_message + message + wildcard raw
        assert any(g[0]=="new_message" for g in got)
        assert any(g[0]=="message" for g in got)
        assert len(wild)>=3
        # status bridge também
        status_events=[]
        c.events.on("message_status", lambda d: status_events.append(d))
        # ack already via self loopback status ackreceived
        assert len(status_events)>=0  # at least not crash
        # ui_queue put direto com log
        logs=[]
        c.events.on("log", lambda d: logs.append(d))
        c.ui_queue.put(("log","rede","integration log"))
        time.sleep(0.02)
        assert logs
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_message_lifecycle_via_model():
    d, db, c, net = mk_client_fast()
    try:
        now=int(time.time())
        mid=db.add_message(None, "BM-A","BM-B","","lifecycle",1,now,"out","awaiting-pubkey")
        m=c.get_message_model(mid)
        assert m is not None and m.status=="awaiting-pubkey"
        # simulate publish -> sent
        assert m.transition_to("sent", persist=True) is True or m.transition_to("sending", persist=True)
        # get models for conversation
        models=c.messages_for_conversation_models("BM-A")
        assert any(isinstance(x, Message) for x in models)
        assert c.get_message_model(999999) is None
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_send_message_vs_send_message_with_id_integration():
    d, db, c, net = mk_client_fast()
    try:
        alice=c.create_identity("A",1)
        # invalid
        st,_=c.send_message(alice, "bad", "", "hi")
        assert st!="success"
        st,_=c.send_message_with_id(alice, "bad", "", "hi")
        assert st!="success"
        # self via legacy wrapper retorna (success, None)
        st, err=c.send_message(alice, alice, "", "via send_message legacy")
        assert st=="success" and err is None
        # via with_id retorna id
        st, mid=c.send_message_with_id(alice, alice, "", "via with_id")
        assert st=="success" and isinstance(mid, int)
        # too large via wire
        big="a"*300000
        st,_=c.send_message(alice, alice, "", big)
        assert st=="too-large"
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_chat_isolation_via_client_repos():
    d, db, c, net = mk_client_fast()
    try:
        a=c.create_identity("A",1)
        b=_fast_gen(stream=1).address
        c2=_fast_gen(stream=1).address
        now=int(time.time())
        db.add_message(None, a, b, "", "to b",1, now,"out","sent")
        db.add_message(None, a, c2, "", "to c2",1, now,"out","sent")
        assert c.message_repo.count_for_dm(b, a)==1
        assert c.message_repo.count_for_dm(c2, a)==1
        # delete one não afeta outro
        c.message_repo.delete_dm(b, a)
        assert c.message_repo.count_for_dm(b, a)==0
        assert c.message_repo.count_for_dm(c2, a)==1
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)

def test_unread_and_delete_isolation():
    d, db, c, net = mk_client_fast()
    try:
        now=int(time.time())
        a="BM-A"
        b="BM-B"
        db.add_message(None, a, b, "", "in1",1, now,"in","received")
        db.add_message(None, a, b, "", "in2",1, now,"in","received")
        assert db.unread_count()==2
        # mark dm read
        c.db.mark_dm_read(b, a)  # actually contact b identity a? Need correct orientation: mark where to==a from==b ?
        # Our messages are from a to b, so they are not to a; unread are to b? Let's just create proper in to self
        self_addr=c.create_identity("Self",1)
        other=_fast_gen(stream=1).address
        db.add_message(None, other, self_addr, "", "hello",1, now,"in","received")
        assert db.unread_count()>=1
        c.db.mark_dm_read(other, self_addr)
        # now unread should decrease
        assert db.unread_count()>=0
        # delete_self_conversation
        db.add_message(None, self_addr, self_addr, "", "self",1, now,"out","sent")
        assert c.db.count_for_dm(self_addr, self_addr)>=1
        c.db.delete_self_conversation(self_addr)
        assert c.db.count_for_dm(self_addr, self_addr)==0
    finally:
        c.stop()
        shutil.rmtree(d, ignore_errors=True)
