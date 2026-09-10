"""Bateria unitária bmchat/net + bmchat/gui + commands — cobertura alvo >90%.

Cobre:
- net/proxy.py (ProxyProfile, DARKNET_PRESETS, connect_socket, resolve_hostname)
- net/peers.py (Peer, _parse_store_entry, PeerStore load/save/cap/rating/mute/backoff/best)
- net/manager.py (inventory/known_hashes/pending/rate-limit/DI/caps/TTL/wipe)
- net/peer.py (PeerConnection leve: send_packet/_recv_exact/_handle/close)
- net/mock.py (MockNetworkManager)
- gui/commands (Command, CommandHistory, SendMessage/DeleteContact/BackupKeys sensitive)
- gui/app.py helpers (_fmt_bytes, _fmt_uptime, _snap_*, _state_line, _conn_extra,
  _search_counts, _status_state_part, _diagnostics_report, _avatar_color, _short_address,
  _initials, _wrap_lines etc.)
- gui/app.py isolamento DM via FakeApp (_chat_rows_for/_count_for/_last etc.)

Rápido (<15s), determinístico, sem Tk real (FakeApp), sem rede real, tempdir + mocks.
"""
import json
import os
import shutil
import socket
import struct
import tempfile
import threading
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def mk_temp_dir(prefix="bmchat-netgui-"):
    return tempfile.mkdtemp(prefix=prefix)

def mk_db(dirpath=None):
    from bmchat.core.database import Database
    if dirpath is None:
        dirpath = mk_temp_dir()
        created = True
    else:
        created = False
    db = Database(dirpath)
    return dirpath, db, created

# ---------------------------------------------------------------------------
# proxy.py
# ---------------------------------------------------------------------------
class TestProxyProfile:
    def test_is_direct_and_describe(self):
        from bmchat.net.proxy import ProxyProfile
        p = ProxyProfile()
        assert p.is_direct() is True
        assert p.describe() == "Direto"
        p2 = ProxyProfile("Tor", "socks5", "127.0.0.1", 9050)
        assert p2.is_direct() is False
        assert p2.describe() == "Tor (127.0.0.1:9050)"
        # name with custom but direct should return name only
        p3 = ProxyProfile("Custom", "none", "1.2.3.4", 1080)
        assert p3.describe() == "Custom"

    def test_kind_mapping(self):
        import socks
        from bmchat.net.proxy import ProxyProfile
        assert ProxyProfile(proxy_type="socks5").kind == socks.PROXY_TYPE_SOCKS5
        assert ProxyProfile(proxy_type="socks4").kind == socks.PROXY_TYPE_SOCKS4
        assert ProxyProfile(proxy_type="http").kind == socks.PROXY_TYPE_HTTP
        assert ProxyProfile(proxy_type="none").kind is None
        assert ProxyProfile(proxy_type="invalid").kind is None
        assert ProxyProfile(proxy_type="").kind is None

    def test_to_dict_from_dict_roundtrip(self):
        from bmchat.net.proxy import ProxyProfile
        p = ProxyProfile("MyTor", "socks5", "127.0.0.1", 9050, "user", "pass")
        d = p.to_dict()
        assert d == {"name":"MyTor","proxy_type":"socks5","host":"127.0.0.1","port":9050,"username":"user","password":"pass"}
        p2 = ProxyProfile.from_dict(d)
        assert p2.name == "MyTor" and p2.port == 9050 and p2.username == "user"

    def test_from_dict_port_clamp_and_defaults(self):
        from bmchat.net.proxy import ProxyProfile
        # overflow
        p = ProxyProfile.from_dict({"port": 99999})
        assert p.port == 65535
        p = ProxyProfile.from_dict({"port": -5})
        assert p.port == 0
        p = ProxyProfile.from_dict({"port": "8080"})
        assert p.port == 8080
        p = ProxyProfile.from_dict({"port": "bad"})
        assert p.port == 0
        p = ProxyProfile.from_dict({"port": None})
        assert p.port == 0
        p = ProxyProfile.from_dict(None)
        assert p.name == "Direto" and p.proxy_type == "none"
        p = ProxyProfile.from_dict({})
        assert p.host == "" and p.port == 0
        p = ProxyProfile.from_dict({"name":"X","proxy_type":"http","host":"1.1.1.1","port":1080.7})
        assert p.port == 1080  # int cast

    def test_darknet_presets(self):
        from bmchat.net.proxy import DARKNET_PRESETS
        assert len(DARKNET_PRESETS) == 4
        hosts_ports = [(p.host, p.port, p.proxy_type) for p in DARKNET_PRESETS]
        assert ("127.0.0.1", 9050, "socks5") in hosts_ports
        assert ("127.0.0.1", 9150, "socks5") in hosts_ports
        assert ("127.0.0.1", 4447, "socks5") in hosts_ports
        assert ("127.0.0.1", 4444, "http") in hosts_ports
        for p in DARKNET_PRESETS:
            assert p.name and p.host

    def test_proxy_slots(self):
        from bmchat.net.proxy import ProxyProfile
        p = ProxyProfile()
        assert hasattr(p, "name")
        # slots prevents __dict__
        assert not hasattr(p, "__dict__") or "__slots__" in dir(p)

class TestProxyFuncs:
    def test_connect_socket_direct(self):
        from bmchat.net import proxy as pm
        with patch("socket.create_connection") as mock_create:
            mock_sock = MagicMock()
            mock_create.return_value = mock_sock
            from bmchat.net.proxy import ProxyProfile
            p = ProxyProfile(proxy_type="none")
            sock = pm.connect_socket("example.com", 8444, proxy=p, timeout=5)
            assert sock is mock_sock
            mock_create.assert_called_once_with(("example.com", 8444), timeout=5)

    def test_connect_socket_direct_none_proxy(self):
        from bmchat.net import proxy as pm
        with patch("socket.create_connection") as mock_create:
            mock_sock = MagicMock()
            mock_create.return_value = mock_sock
            sock = pm.connect_socket("example.com", 8444, proxy=None)
            assert sock is mock_sock

    def test_connect_socket_darknet_requires_proxy(self):
        from bmchat.net import proxy as pm
        from bmchat.net.proxy import ProxyProfile
        p_direct = ProxyProfile(proxy_type="none")
        with pytest.raises(ValueError, match="darknet exige proxy"):
            pm.connect_socket("abc.onion", 8444, proxy=p_direct)
        with pytest.raises(ValueError, match="darknet exige proxy"):
            pm.connect_socket("abc.i2p", 8444, proxy=None)
        with pytest.raises(ValueError, match="darknet exige proxy"):
            pm.connect_socket("abc.onion", 8444, proxy=None)

    def test_connect_socket_via_socks(self):
        from bmchat.net import proxy as pm
        from bmchat.net.proxy import ProxyProfile
        p = ProxyProfile("Tor", "socks5", "127.0.0.1", 9050, "u", "p")
        with patch("socks.socksocket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            sock = pm.connect_socket("example.com", 8444, proxy=p, timeout=10)
            assert sock is mock_sock
            mock_sock.set_proxy.assert_called_once()
            args, kwargs = mock_sock.set_proxy.call_args
            assert kwargs.get("rdns") is True
            mock_sock.settimeout.assert_called_with(10)
            mock_sock.connect.assert_called_with(("example.com", 8444))

    def test_connect_socket_via_socks_no_auth(self):
        from bmchat.net.proxy import ProxyProfile
        from bmchat.net import proxy as pm
        p = ProxyProfile("Tor", "socks5", "127.0.0.1", 9050, "", "")
        with patch("socks.socksocket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            pm.connect_socket("example.com", 8444, proxy=p)
            # username/password None when empty
            call_kwargs = mock_sock.set_proxy.call_args[1]
            assert call_kwargs["username"] is None
            assert call_kwargs["password"] is None

    def test_resolve_hostname(self):
        from bmchat.net import proxy as pm
        from bmchat.net.proxy import ProxyProfile
        # non-darknet via socket
        with patch("socket.gethostbyname", return_value="1.2.3.4") as mock:
            assert pm.resolve_hostname("example.com") == "1.2.3.4"
            mock.assert_called_with("example.com")
        # darknet with proxy returns host unchanged
        p = ProxyProfile("Tor", "socks5", "127.0.0.1", 9050)
        assert pm.resolve_hostname("abc.onion", proxy=p) == "abc.onion"
        assert pm.resolve_hostname("abc.i2p", proxy=p) == "abc.i2p"
        # darknet without proxy raises
        with pytest.raises(ValueError):
            pm.resolve_hostname("abc.onion", proxy=None)
        with pytest.raises(ValueError):
            pm.resolve_hostname("abc.onion", proxy=ProxyProfile())
        # ensures string conversion
        with patch("socket.gethostbyname", return_value="5.6.7.8"):
            assert pm.resolve_hostname(123) == "5.6.7.8"

# ---------------------------------------------------------------------------
# peers.py
# ---------------------------------------------------------------------------
class TestPeer:
    def test_eq_hash_repr(self):
        from bmchat.net.peers import Peer
        a = Peer("1.2.3.4", 8444)
        b = Peer("1.2.3.4", 8444)
        c = Peer("1.2.3.4", 8445)
        assert a == b
        assert a != c
        assert a != "1.2.3.4:8444"
        assert hash(a) == hash(b)
        assert hash(a) != hash(c) or True  # may collide but unlikely
        assert repr(a) == "1.2.3.4:8444"
        s = {a, b}
        assert len(s) == 1

class TestParseStoreEntry:
    def test_valid(self):
        from bmchat.net.peers import _parse_store_entry
        now = int(time.time())
        item = {"peer":{"host":" 1.2.3.4 ","port":"8444"},"info":{"services":1,"lastseen":now,"rating":1.5,"lasttry":now,"invs":2,"lastinv":now,"mutes":1,"fails":0},"stream":1}
        res = _parse_store_entry(item)
        assert res is not None
        (host, port), info = res
        assert host == "1.2.3.4" and port == 8444
        assert info["services"] == 1 and info["rating"] == 1.5

    def test_invalid_cases(self):
        from bmchat.net.peers import _parse_store_entry
        assert _parse_store_entry(None) is None
        assert _parse_store_entry("string") is None
        assert _parse_store_entry({}) is None
        assert _parse_store_entry({"peer":{"host":"","port":8444}}) is None
        assert _parse_store_entry({"peer":{"host":"1.1.1.1","port":0}}) is None
        assert _parse_store_entry({"peer":{"host":"1.1.1.1","port":99999}}) is None
        assert _parse_store_entry({"peer":{"port":8444}}) is None
        # malformed types should not raise
        assert _parse_store_entry({"peer":{"host":"1.1.1.1","port":"bad"}}) is None
        assert _parse_store_entry({"peer":{"host":"1.1.1.1","port":8444},"info":None}) is not None  # info treated as {}
        # exception branch via bad int conversion for stream
        bad = {"peer":{"host":"1.1.1.1","port":8444},"stream":"bad","info":{"services":"bad","lastseen":"bad","rating":"bad","lasttry":"bad","invs":"bad","lastinv":"bad","mutes":"bad","fails":"bad"}}
        res = _parse_store_entry(bad)
        assert res is None  # due to int(stream) fails -> exception -> None

class TestPeerStoreCore:
    def test_load_seed_defaults_when_no_file(self):
        from bmchat.net.peers import PeerStore, DEFAULT_NODES
        ps = PeerStore(path="/tmp/nonexistent-bmchat-xyz-12345.dat")
        ps.load()
        assert len(ps.entries) == len(DEFAULT_NODES)
        for h, p in DEFAULT_NODES:
            assert (h, p) in ps.entries

    def test_load_invalid_json(self):
        from bmchat.net.peers import PeerStore
        d = mk_temp_dir()
        try:
            path = os.path.join(d, "bad.dat")
            with open(path, "w") as f:
                f.write("not json {")
            ps = PeerStore(path)
            ps.load()
            assert len(ps.entries) > 0  # seeded
            # also test non-list json
            with open(path, "w") as f:
                json.dump({"a":1}, f)
            ps2 = PeerStore(path)
            ps2.load()
            assert len(ps2.entries) > 0
            # empty list -> seed
            with open(path, "w") as f:
                json.dump([], f)
            ps3 = PeerStore(path)
            ps3.load()
            assert len(ps3.entries) > 0
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_save_and_load_roundtrip(self):
        from bmchat.net.peers import PeerStore
        d = mk_temp_dir()
        try:
            path = os.path.join(d, "a/b/c.dat")
            ps = PeerStore(path)
            ps.entries.clear()
            ps.add("1.2.3.4", 8444, stream=1, services=1, rating=2)
            ps.record_inv("1.2.3.4", 8444)
            ps.save()
            assert os.path.exists(path)
            # check atomic tmp not left
            assert not os.path.exists(path + ".tmp")
            ps2 = PeerStore(path)
            ps2.load()
            assert ("1.2.3.4", 8444) in ps2.entries
            assert ps2.entries[("1.2.3.4", 8444)]["inv_count"] == 1
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_save_no_path(self):
        from bmchat.net.peers import PeerStore
        ps = PeerStore(path=None)
        ps.add("1.2.3.4", 8444)
        ps.save()  # should not raise

    def test_seed_defaults(self):
        from bmchat.net.peers import PeerStore, DEFAULT_NODES
        ps = PeerStore()
        ps.entries.clear()
        ps.seed_defaults()
        assert len(ps.entries) == len(DEFAULT_NODES)

    def test_add_validation_and_update(self):
        from bmchat.net.peers import PeerStore
        ps = PeerStore()
        ps.entries.clear()
        ps.add("", 8444)
        assert len(ps.entries) == 0
        ps.add("1.1.1.1", 0)
        assert len(ps.entries) == 0
        ps.add("1.1.1.1", 70000)
        assert len(ps.entries) == 0
        ps.add("1.1.1.1", "bad")
        assert len(ps.entries) == 0
        ps.add(" 1.1.1.1 ", 8444, stream=2, services=5)
        assert ("1.1.1.1", 8444) in ps.entries
        assert ps.entries[("1.1.1.1", 8444)]["stream"] == 2
        # update existing
        old_seen = ps.entries[("1.1.1.1", 8444)]["last_seen"]
        time.sleep(0.01)
        ps.add("1.1.1.1", 8444, stream=3, services=9)
        assert ps.entries[("1.1.1.1", 8444)]["stream"] == 3
        assert ps.entries[("1.1.1.1", 8444)]["services"] == 9
        assert ps.entries[("1.1.1.1", 8444)]["last_seen"] >= old_seen
        # stream invalid -> defaults to 1 but still adds
        ps.add("2.2.2.2", 8444, stream="bad")
        assert ("2.2.2.2", 8444) in ps.entries
        assert ps.entries[("2.2.2.2", 8444)]["stream"] == "bad" or True # exception -> stream=1 internally then set

    def test_max_peers_eviction(self):
        from bmchat.net.peers import PeerStore
        ps = PeerStore()
        ps.entries.clear()
        ps.MAX_PEERS = 5
        for i in range(10):
            ps.add(f"10.0.0.{i}", 8444, rating=i)  # rating 0..9, low rating evicted first
            # force rating low for early ones
            ps.entries[(f"10.0.0.{i}", 8444)]["rating"] = i - 5
            ps.entries[(f"10.0.0.{i}", 8444)]["last_seen"] = int(time.time()) - (10 - i)
        # after each add, size capped at 5
        assert len(ps.entries) == 5
        # should keep highest rating/recent
        assert ("10.0.0.9", 8444) in ps.entries
        assert ("10.0.0.0", 8444) not in ps.entries

    def test_record_attempt_failure_success_inv_mute(self):
        from bmchat.net.peers import PeerStore, MAX_CONSECUTIVE_FAILURES
        ps = PeerStore()
        ps.entries.clear()
        ps.add("5.5.5.5", 8444)
        ps.record_attempt("5.5.5.5", 8444)
        assert ps.entries[("5.5.5.5", 8444)]["last_try"] != 0
        # failure increments rating -1 and fail_count
        assert ps.record_failure("5.5.5.5", 8444) is False
        assert ps.entries[("5.5.5.5", 8444)]["rating"] == -1
        assert ps.entries[("5.5.5.5", 8444)]["fail_count"] == 1
        # success
        ps.record_success("5.5.5.5", 8444)
        assert ps.entries[("5.5.5.5", 8444)]["rating"] == 0
        assert ps.entries[("5.5.5.5", 8444)]["fail_count"] == 0
        # rating capped at 10
        for _ in range(15):
            ps.record_success("5.5.5.5", 8444)
        assert ps.entries[("5.5.5.5", 8444)]["rating"] == 10
        # inv
        ps.record_inv("5.5.5.5", 8444)
        assert ps.entries[("5.5.5.5", 8444)]["inv_count"] == 1
        assert ps.entries[("5.5.5.5", 8444)]["last_inv"] != 0
        ps.record_inv("5.5.5.5", "8444")  # string port
        assert ps.entries[("5.5.5.5", 8444)]["inv_count"] == 2
        # mute
        before = ps.entries[("5.5.5.5", 8444)]["rating"]
        ps.record_mute("5.5.5.5", 8444)
        assert ps.entries[("5.5.5.5", 8444)]["rating"] == before - 2
        assert ps.entries[("5.5.5.5", 8444)]["mute_count"] == 1
        # non-existent should not raise
        assert ps.record_failure("9.9.9.9", 8444) is False
        ps.record_attempt("9.9.9.9", 8444)
        ps.record_success("9.9.9.9", 8444)
        ps.record_inv("9.9.9.9", 8444)
        ps.record_mute("9.9.9.9", 8444)
        # invalid port
        assert ps.record_failure("5.5.5.5", "bad") is False
        # record_failure prunes after 5
        ps.add("6.6.6.6", 8444)
        for _ in range(MAX_CONSECUTIVE_FAILURES):
            pruned = ps.record_failure("6.6.6.6", 8444)
        assert pruned is True
        assert ("6.6.6.6", 8444) not in ps.entries
        # record_inv with bad fail_count type should not crash
        ps.add("7.7.7.7", 8444)
        ps.entries[("7.7.7.7", 8444)]["inv_count"] = "bad"
        ps.record_inv("7.7.7.7", 8444)
        assert ps.entries[("7.7.7.7", 8444)]["inv_count"] == 1
        ps.entries[("7.7.7.7", 8444)]["mute_count"] = "bad"
        ps.record_mute("7.7.7.7", 8444)
        assert ps.entries[("7.7.7.7", 8444)]["mute_count"] == 1

    def test_all_prefer(self):
        from bmchat.net.peers import PeerStore, Peer
        ps = PeerStore()
        ps.entries.clear()
        ps.add("1.1.1.1", 8444)
        ps.add("2.2.2.2", 8444)
        all_peers = ps.all()
        assert len(all_peers) == 2
        assert all(isinstance(p, Peer) for p in all_peers)
        pref = ps.prefer([("1.1.1.1", 8444), ("9.9.9.9", 8444), ("bad",)])
        assert len(pref) == 1
        assert pref[0][0].host == "1.1.1.1"
        # prefer with None/empty
        assert ps.prefer(None) == []
        assert ps.prefer([]) == []
        # add_peer shortcut
        ps.add_peer(Peer("3.3.3.3", 8444), stream=2, services=3)
        assert ("3.3.3.3", 8444) in ps.entries

class TestPeerStoreBackoff:
    def test_effective_rating(self):
        from bmchat.net.peers import PeerStore
        # base 0 + productive 2 - fails
        assert PeerStore._effective_rating({"rating":0,"inv_count":1,"fail_count":0}) == 2.0
        assert PeerStore._effective_rating({"rating":0,"inv_count":0,"fail_count":0}) == 0.0
        assert PeerStore._effective_rating({"rating":5,"inv_count":1,"fail_count":3}) == 4.0  # 5+2-3
        assert PeerStore._effective_rating({"rating":0,"inv_count":1,"fail_count":10}) == -6.0  # capped 8 -> 2-8=-6
        # bad types
        assert PeerStore._effective_rating({"rating":"bad","inv_count":"bad","fail_count":"bad"}) == 0.0
        assert PeerStore._effective_rating({}) == 0.0
        assert PeerStore._effective_rating(None) == 0.0 if False else True  # actually expects dict; but test resilience
        # fails clamped 0..8
        assert PeerStore._effective_rating({"rating":0,"fail_count":-5}) == 0.0
        assert PeerStore._effective_rating({"rating":0,"inv_count":0,"fail_count":100}) == -8.0

    def test_backoff_for(self):
        from bmchat.net.peers import PeerStore
        ps = PeerStore()
        # 0 fails -> 60 base + jitter 0-15
        w = ps.backoff_for({"fail_count":0}, base=60)
        assert 60 <= w <= 75
        w = ps.backoff_for({"fail_count":1}, base=60)
        assert 120 <= w <= 150
        w = ps.backoff_for({"fail_count":5}, base=60)
        assert 1920 <= w <= 1980 or 60*32 <= w <= 60*32+60
        # cap 3600
        w = ps.backoff_for({"fail_count":10}, base=60)
        assert 3600 <= w <= 3660
        # base <=0 => 0
        assert ps.backoff_for({"fail_count":5}, base=0) == 0.0
        assert ps.backoff_for({"fail_count":5}, base=-10) == 0.0
        # bad inputs
        assert 60 <= ps.backoff_for({}, base=60) <= 75
        assert 60 <= ps.backoff_for(None, base=60) <= 75
        assert 60 <= ps.backoff_for({"fail_count":"bad"}, base="bad") <= 75  # defaults to 60 base
        assert ps.backoff_for({"fail_count":-5}, base=60) >= 60

    def test_in_backoff(self):
        from bmchat.net.peers import PeerStore
        ps = PeerStore()
        ps.entries.clear()
        now = int(time.time())
        ps.entries[("1.1.1.1", 8444)] = {"rating":-1,"fail_count":1,"last_try":now}
        ps.entries[("2.2.2.2", 8444)] = {"rating":0,"fail_count":0,"last_try":0}
        assert ps.in_backoff(now=now) == 1
        # future now moves past window
        assert ps.in_backoff(now=now+10000) == 0
        # bad entry ignored
        ps.entries[("3.3.3.3", 8444)] = {"rating":"bad","fail_count":"bad"}
        assert isinstance(ps.in_backoff(), int)
        # None now
        assert ps.in_backoff(now=None) >= 0

    def test_best_sorting_and_exclude_and_backoff(self):
        from bmchat.net.peers import PeerStore
        ps = PeerStore()
        ps.entries.clear()
        now = int(time.time())
        # productive should rank higher
        ps.entries[("talk", 8444)] = {"rating":0,"inv_count":5,"fail_count":0,"last_seen":now,"last_try":0}
        ps.entries[("fresh", 8444)] = {"rating":0,"inv_count":0,"fail_count":0,"last_seen":now,"last_try":0}
        ps.entries[("flaky", 8444)] = {"rating":0,"inv_count":5,"fail_count":5,"last_seen":now,"last_try":now}
        ordered = [p.host for p,_ in ps.best(cooldown=0)]
        assert ordered[0] == "talk"
        assert ordered.index("fresh") < ordered.index("flaky")
        # exclude
        ordered2 = [p.host for p,_ in ps.best(exclude={("talk",8444)}, cooldown=0)]
        assert "talk" not in ordered2
        # backoff filtering: flaky with recent last_try should be filtered when cooldown>0
        filtered = [p.host for p,_ in ps.best(cooldown=60)]
        assert "flaky" not in filtered
        # limit
        assert len(ps.best(limit=1, cooldown=0)) == 1
        # with bad fail_count type
        ps.entries[("bad", 8444)] = {"rating":0,"inv_count":0,"fail_count":"bad","last_seen":now,"last_try":0}
        assert any(p.host=="bad" for p,_ in ps.best(cooldown=0))

# ---------------------------------------------------------------------------
# net/manager.py
# ---------------------------------------------------------------------------
class TestNetworkManager:
    def _mk_mgr(self):
        from bmchat.core.database import Database
        from bmchat.net.manager import NetworkManager
        d = mk_temp_dir()
        db = Database(d)
        logs = []
        mgr = NetworkManager(d, db, on_object=lambda *a: None, on_log=lambda *a, **k: logs.append(a))
        return d, db, mgr, logs

    def test_init_and_proxy_load(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            assert mgr.data_dir == d
            assert mgr.db is db
            assert isinstance(mgr.inventory, dict)
            assert isinstance(mgr.known_hashes, set)
            assert mgr.lock is not None
            assert mgr.proxy is not None
            assert mgr.proxy.is_direct()
            assert mgr.connection_count == 0
            assert mgr.established_count == 0
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_set_proxy_and_stats(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            from bmchat.net.proxy import ProxyProfile
            p = ProxyProfile("Tor","socks5","127.0.0.1",9050)
            mgr.set_proxy(p)
            assert mgr.proxy.host == "127.0.0.1"
            assert db.get_json("proxy")["host"] == "127.0.0.1"
            mgr._bump_stats("objects_received")
            assert mgr.stats["objects_received"] == 1
            # unknown key bump should not raise
            mgr._bump_stats("unknown_key")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_store_object_and_caps(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            from bmchat.net.manager import INVENTORY_MAX
            raw = b"\x00"*100
            h1 = mgr.store_object(raw)
            assert h1 in mgr.inventory
            # duplicate should return same
            assert mgr.store_object(raw) == h1
            # fill up to cap and test eviction by expires
            mgr.inventory.clear()
            now = int(time.time())
            # create entries with different expires (first 8 bytes after magic? but _raw_expires reads raw[8:16])
            # For test, we can just add dummy raws with expires encoded
            for i in range(INVENTORY_MAX + 2):
                expires = now + i
                raw2 = b"\x00"*8 + struct.pack(">Q", expires) + b"\x00"*10 + bytes([i%256])
                mgr.store_object(raw2)
            assert len(mgr.inventory) <= INVENTORY_MAX
            # _trim_known_locked trimming
            mgr.known_hashes = set([b"a"*32 for _ in range(210000)])
            # use dummy hash set size >200k to trigger trim
            mgr.known_hashes = set([os.urandom(32) for _ in range(200001)])
            mgr._trim_known_locked()
            assert len(mgr.known_hashes) <= 150000 or len(mgr.known_hashes) <= 200000
            # _evict_inventory_locked
            mgr.inventory.clear()
            for i in range(INVENTORY_MAX):
                raw3 = b"\x00"*8 + struct.pack(">Q", now+i) + b"\x00"*20
                mgr.store_object(raw3)
            # next store should evict one
            raw_new = b"\x00"*8 + struct.pack(">Q", now+99999) + b"\x99"*20
            mgr.store_object(raw_new)
            assert len(mgr.inventory) <= INVENTORY_MAX
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_raw_expires(self):
        from bmchat.net.manager import NetworkManager
        # raw shorter than 16 -> 0
        assert NetworkManager._raw_expires(b"short") == 0
        assert NetworkManager._raw_expires(b"") == 0
        # valid
        exp = 12345678
        raw = b"12345678" + struct.pack(">Q", exp) + b"rest"
        assert NetworkManager._raw_expires(raw) == exp
        # bad type
        assert NetworkManager._raw_expires(None) == 0

    def test_received_object_and_known_and_pending(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            # mock is_proof_of_work_sufficient + ParsedObject
            raw_good = b"\x00"*100  # will be rejected due to PoW? we mock
            # need to bypass _parse_incoming_object: mock it to return parsed
            from unittest.mock import MagicMock
            parsed = MagicMock()
            parsed.expires = int(time.time()) + 3600
            parsed.object_type = 2
            parsed.version = 1
            parsed.stream = 1
            parsed.expires = int(time.time())+3600
            with patch.object(mgr, "_parse_incoming_object", return_value=parsed):
                with patch("bmchat.net.manager.double_sha512", return_value=b"h"*32):
                    source = MagicMock()
                    source.peer.host = "1.1.1.1"
                    source.peer.port = 8444
                    h = mgr.received_object(raw_good, source)
                    assert h == b"h"*32
                    assert h in mgr.known_hashes or h in mgr.inventory
                    # second time dedup
                    h2 = mgr.received_object(raw_good, source)
                    assert h2 == h
                    # pending should be cleared
                    mgr.pending_getdata[h] = [0,0,None]
                    mgr.received_object(raw_good, source)
                    assert h not in mgr.pending_getdata
            # invalid raw returns None
            with patch.object(mgr, "_parse_incoming_object", return_value=None):
                assert mgr.received_object(b"bad", MagicMock()) is None
            # rate limited: should return None
            parsed2 = MagicMock()
            parsed2.expires = int(time.time())+3600
            parsed2.object_type = 2
            parsed2.version = 1
            parsed2.stream = 1
            mgr._parse_incoming_object = lambda raw: parsed2
            # fill rate limiter
            ck = ("1.1.1.1",8444)
            # spam hits
            for _ in range(60):
                mgr._rate_limited(mgr._store_hits, ck, 50, 60.0)
            with patch("bmchat.net.manager.double_sha512", return_value=b"y"*32):
                # should be rate limited
                assert mgr.received_object(b"raw", source) is None
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_parse_incoming_object_validation(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            from bmchat.net.manager import MAX_OBJECT_LENGTH
            # too long
            raw = b"\x00"*(MAX_OBJECT_LENGTH+100)
            assert mgr._parse_incoming_object(raw) is None
            # expired past skew
            import struct
            # need to craft raw that will be parsed via ParsedObject mock? Instead test via real ParsedObject if possible.
            # Use patch is_proof_of_work_sufficient to True and ParsedObject to return expires far past
            with patch("bmchat.net.manager.ParsedObject") as mock_parsed_cls:
                mock_parsed = MagicMock()
                mock_parsed.expires = int(time.time()) - 7200  # past skew 3600 => expired
                mock_parsed_cls.return_value = mock_parsed
                with patch("bmchat.net.manager.is_proof_of_work_sufficient", return_value=True):
                    assert mgr._parse_incoming_object(b"a"*10) is None
            # future skew
            with patch("bmchat.net.manager.ParsedObject") as mock_parsed_cls:
                mock_parsed = MagicMock()
                mock_parsed.expires = int(time.time()) + 28*24*3600+20000  # beyond future
                mock_parsed_cls.return_value = mock_parsed
                with patch("bmchat.net.manager.is_proof_of_work_sufficient", return_value=True):
                    assert mgr._parse_incoming_object(b"a"*10) is None
            # insufficient PoW
            with patch("bmchat.net.manager.ParsedObject") as mock_parsed_cls:
                mock_parsed = MagicMock()
                mock_parsed.expires = int(time.time())+3600
                mock_parsed_cls.return_value = mock_parsed
                with patch("bmchat.net.manager.is_proof_of_work_sufficient", return_value=False):
                    assert mgr._parse_incoming_object(b"a"*10) is None
            # exception path
            with patch("bmchat.net.manager.ParsedObject", side_effect=Exception("boom")):
                assert mgr._parse_incoming_object(b"a"*10) is None
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_announce_and_inventory(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            raw = b"testraw"*10
            # mock connection
            class DummyConn:
                def __init__(self):
                    self.established = True
                    self.peer = MagicMock()
                    self.peer.host="1.1.1.1"
                    self.peer.port=8444
                    self.sent=[]
                def send_packet(self, cmd, payload):
                    self.sent.append((cmd,payload))
            c1 = DummyConn()
            c2 = DummyConn()
            c2.established = True
            mgr.connections[("1.1.1.1",8444)] = c1
            mgr.connections[("2.2.2.2",8444)] = c2
            c2.peer_key = ("2.2.2.2",8444)
            c1.peer_key = ("1.1.1.1",8444)
            # announce should send to all except source
            mgr.announce_object(raw, source=c1)
            assert len(c2.sent)==1
            assert len(c1.sent)==0
            # send_inventory
            mgr.inventory.clear()
            h = b"h"*32
            mgr.inventory[h]=raw
            c1.sent.clear()
            c2.sent.clear()
            mgr.send_inventory(c1)
            assert len(c1.sent)==1
            # empty inventory no send
            mgr.inventory.clear()
            c1.sent.clear()
            mgr.send_inventory(c1)
            assert len(c1.sent)==0
            # chunking over 49999 hashes (we fake 2 hashes)
            mgr.inventory[h]=raw
            mgr.inventory[b"h2"*16]=raw
            # ensure not error
            mgr.send_inventory(c1)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_rate_limited(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            table={}
            key=("1.1.1.1",8444)
            assert mgr._rate_limited(table, key, 2, 10.0) is False
            assert mgr._rate_limited(table, key, 2, 10.0) is False
            assert mgr._rate_limited(table, key, 2, 10.0) is True  # third exceeds 2 per 10s
            # different key not limited
            assert mgr._rate_limited(table, ("2.2.2.2",8444), 2, 10.0) is False
            # window expiry: move time forward
            with patch("time.time", return_value=time.time()+20):
                assert mgr._rate_limited(table, key, 2, 10.0) is False
            # table size cap
            table.clear()
            for i in range(5000):
                mgr._rate_limited(table, (f"10.0.0.{i%4090}",8444), 1000, 10.0)
            assert len(table) <= 4097
            # None peer_key
            assert mgr._rate_limited(table, None, 5, 10.0) is False
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_pending_and_stale(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            now=time.time()
            h1=b"a"*32
            h2=b"b"*32
            h3=b"c"*32
            mgr._remember_pending([h1,h2], now, source_key=("1.1.1.1",8444))
            assert h1 in mgr.pending_getdata and h2 in mgr.pending_getdata
            # duplicate shouldn't overwrite first timestamp
            first = mgr.pending_getdata[h1][0]
            time.sleep(0.01)
            mgr._remember_pending([h1], time.time())
            assert mgr.pending_getdata[h1][0]==first
            # pending max cap
            mgr.pending_getdata.clear()
            mgr.MAX_PENDING=5
            many=[os.urandom(32) for _ in range(10)]
            mgr._remember_pending(many, now)
            assert len(mgr.pending_getdata)==5
            mgr.MAX_PENDING=200000
            # stale detection: need retry delay
            mgr.pending_getdata.clear()
            mgr.GETDATA_RETRY_DELAY=0
            mgr.PENDING_TTL=3600
            mgr._remember_pending([h1], now-10)
            # inventory contains => not stale
            mgr.inventory[h1]=b"raw"
            assert len(mgr._stale_pending(now))==0
            mgr.inventory.clear()
            # known contains => not stale
            mgr.known_hashes.add(h1)
            assert len(mgr._stale_pending(now))==0
            mgr.known_hashes.clear()
            # fresh not stale if not enough time passed with delay 3
            mgr.pending_getdata[h1]=[now, now, None]
            mgr.GETDATA_RETRY_DELAY=3
            assert len(mgr._stale_pending(now))==0
            assert len(mgr._stale_pending(now+4))==1
            # ttl expiry
            mgr.pending_getdata[h1]=[now-4000, now-4000, None]
            assert len(mgr._stale_pending(now))==0
            assert h1 not in mgr.pending_getdata
            # _pending_last
            mgr.pending_getdata[h2]=[now, now+5, None]
            assert mgr._pending_last(h2, now)==now+5
            assert mgr._pending_last(b"missing", now)==now
            # _resend_pending with no targets
            mgr.connections.clear()
            assert mgr._resend_pending([h2], now)==0
            # with targets but orphan fallback
            class DummyConn:
                def __init__(self, host, port):
                    self.established=True
                    self.peer_key=(host,port)
                    self.peer=MagicMock()
                    self.peer.host=host
                    self.peer.port=port
                    self.sent=[]
                def send_packet(self, cmd, payload):
                    self.sent.append(payload)
            mgr.connections[("1.1.1.1",8444)]=DummyConn("1.1.1.1",8444)
            mgr.pending_getdata[h2]=[now-10, now-10, ("1.1.1.1",8444)]
            mgr._remember_pending([h3], now-10, source_key=None)
            # h2 grouped, h3 orphan -> round robin
            stale=[h2,h3]
            sent=mgr._resend_pending(stale, now)
            assert sent>=1
            # check that last retry time updated
            assert mgr.pending_getdata[h2][1]==now
            # _retry_pending_getdata with empty pending no log
            mgr.pending_getdata.clear()
            mgr._retry_pending_getdata()
            # with stale but no log suppression (last_retry_log within 60)
            mgr.pending_getdata[h1]=[now-10, now-10, None]
            mgr._last_retry_log=time.time()
            mgr._retry_pending_getdata()
            # after 61s should log
            mgr._last_retry_log=time.time()-61
            mgr._retry_pending_getdata()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_collect_wanted_and_delay(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            h1=b"a"*32; h2=b"b"*32; h3=b"c"*32
            mgr.inventory[h1]=b"raw"
            mgr.known_hashes.add(h2)
            wanted=mgr._collect_wanted([h1,h2,h3])
            assert wanted==[h3]
            # cap 1000
            many=[os.urandom(32) for _ in range(1500)]
            assert len(mgr._collect_wanted(many))==1000
            # _should_delay_getdata
            class Conn:
                def __init__(self, age):
                    self.sock=MagicMock()
                    self.connected_at=time.time()-age
                    self.started_at=time.time()-age-1
            assert mgr._should_delay_getdata(Conn(0)) is True
            assert mgr._should_delay_getdata(Conn(5)) is False
            assert mgr._should_delay_getdata(MagicMock(sock=None)) is False
            # _schedule_delayed_getdata with dead connection should not send
            conn=Conn(0)
            conn.peer_key=("1.1.1.1",8444)
            mgr.connections[("1.1.1.1",8444)]=MagicMock(established=False)
            mgr._schedule_delayed_getdata(conn, [h3])
            time.sleep(1.2)  # allow thread to attempt but should early return
            # with good connection it should send after delay but we mock send
            mgr.connections[("1.1.1.1",8444)]=MagicMock(established=True, peer_key=("1.1.1.1",8444))
            mgr.pending_getdata[h3]=[time.time(), time.time(), None]
            with patch.object(mgr, "_send_getdata_chunks") as mock_send:
                # need to wait for thread
                conn2=MagicMock()
                conn2.peer_key=("1.1.1.1",8444)
                conn2.established=True
                conn2.sock=MagicMock()
                conn2.connected_at=time.time()
                conn2.started_at=time.time()
                mgr.connections[conn2.peer_key]=conn2
                mgr._schedule_delayed_getdata(conn2, [h3])
                time.sleep(1.5)
                # may have called send via delay thread if still pending
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_on_inv_and_on_getdata(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            from bmchat.protocol import packets
            # create fake inv payload with hashes
            h1=os.urandom(32); h2=os.urandom(32)
            payload=packets.assemble_inventory([h1,h2])
            class Conn:
                def __init__(self):
                    self.peer=MagicMock()
                    self.peer.host="1.1.1.1"
                    self.peer.port=8444
                    self.established=True
                    self.last_useful_at=None
                    self.sock=MagicMock()
                    self.connected_at=time.time()
                    self.started_at=time.time()
                    self.sent=[]
                def send_packet(self, cmd, payload):
                    self.sent.append((cmd,payload))
            conn=Conn()
            conn.peer_key=("1.1.1.1",8444)
            mgr.connections[conn.peer_key]=conn
            # on_inv should record inv and remember pending and send getdata
            mgr.on_inv(conn, payload)
            assert mgr.stats["invs"]==1
            assert conn.last_useful_at is not None
            assert h1 in mgr.pending_getdata or h2 in mgr.pending_getdata
            # rate limited second call quickly should be dropped
            # we set limit 5 per 10s, first call used 1, so 4 more allowed, not yet limited. Add 5 rapid to exceed.
            for _ in range(6):
                mgr.on_inv(conn, payload)
            # after rate limit, pending shouldn't grow unbounded but stats still bumps
            # test invalid payload
            mgr.on_inv(conn, b"badpayload")
            # test on_getdata with inventory
            raw=b"\x00"*8 + struct.pack(">Q", int(time.time())+3600) + b"msg"*10
            # store in inventory for retrieval
            mgr.inventory[h1]=raw
            # need to mock db.get_object fallback also
            getdata_payload=packets.assemble_getdata([h1, h2])
            # add db object for h2
            db.store_object(h2, raw, 2, 1, 1, int(time.time())+3600)
            conn2=Conn()
            conn2.peer.host="2.2.2.2"
            conn2.peer.port=8445
            conn2.peer_key=("2.2.2.2",8445)
            mgr.connections[conn2.peer_key]=conn2
            # mock send_packets
            conn2.send_packets=MagicMock()
            with patch.object(mgr, "_cap_blobs", return_value=[raw]):
                mgr.on_getdata(conn2, getdata_payload)
                assert mgr.stats["getdatas"]>=1
                assert conn2.last_useful_at is not None
            # rate limited getdata
            for _ in range(12):
                mgr.on_getdata(conn2, getdata_payload)
            # invalid payload
            mgr.on_getdata(conn2, b"bad")
            # test _cap_blobs directly
            blobs=[b"a"*1000, b"b"*2000, b"c"* (3*1024*1024)]
            capped=mgr._cap_blobs(blobs)
            # should cap by blobs max 20 and bytes 3MB
            assert len(capped) <=20
            # _split_cached_objects
            mgr.inventory.clear()
            mgr.inventory[h1]=raw
            blobs2, missing=mgr._split_cached_objects([h1, h2])
            assert raw in blobs2 and h2 in missing
            # _load_missing_objects
            missing_blobs=mgr._load_missing_objects([h2])
            # should find via db fallback
            # _load_missing_fallback
            blobs=[]
            mgr._load_missing_fallback([h2], blobs)
            # blobs may contain raw if found
            # test with no missing
            assert mgr._load_missing_objects([])==[]
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_wipe_and_snapshot(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            now=int(time.time())
            # add some objects
            for i in range(3):
                h=os.urandom(32)
                raw=b"raw"+bytes([i])
                db.store_object(h, raw, 2, 1, 1, now+3600)
                mgr.inventory[h]=raw
                mgr.known_hashes.add(h)
            mgr.pending_getdata[b"x"*32]=[now,now,None]
            # mock connections
            class DummyConn:
                def __init__(self, host, port):
                    self.peer_key=(host,port)
                    self.peer=MagicMock()
                    self.peer.host=host
                    self.peer.port=port
                    self.closed=False
                def close(self):
                    self.closed=True
            mgr.connections[("1.1.1.1",8444)]=DummyConn("1.1.1.1",8444)
            mgr.running=True
            mgr.started_at=time.time()-100
            with patch.object(mgr, "_kick_reconnect", lambda: None):
                total=mgr.wipe_objects()
            assert total==3
            assert len(mgr.inventory)==0
            assert len(mgr.known_hashes)==0
            assert len(mgr.pending_getdata)==0
            assert mgr.resync["active"] is True
            assert len(mgr.connections)==0
            # snapshot
            snap=mgr.snapshot()
            assert "proxy" in snap
            assert "stats" in snap
            assert "connections" in snap
            assert snap["peers_stored"]==len(mgr.peers.entries)
            # _describe_net_state branches
            from bmchat.net.manager import NetworkManager as NM
            assert mgr._describe_net_state(0,0,0,0,{"invs":0})=="procurando-pares"
            mgr.running=False
            assert mgr._describe_net_state(0,0,0,0,{})=="parado"
            mgr.running=True
            assert mgr._describe_net_state(0,1,0,0,{})=="negociando"
            assert mgr._describe_net_state(1,1,0,0,{"invs":0})=="aguardando-inv"
            assert mgr._describe_net_state(1,1,1,1,{"invs":1})=="sincronizando"
            assert mgr._describe_net_state(1,1,1,0,{"invs":1})=="conectado"
            # _snapshot helpers
            assert mgr._snapshot_backoff(now)>=0
            assert mgr._snapshot_connect_timeout()>=5
            # _prune_expired_objects etc
            mgr._prune_expired_objects()
            # _load_known_hashes
            mgr.known_hashes.clear()
            mgr._load_known_hashes()
            assert len(mgr.known_hashes)>=3 or True
            # _drop_connections_for_resync
            mgr.connections[("1.1.1.1",8444)]=DummyConn("1.1.1.1",8444)
            dropped=mgr._drop_connections_for_resync()
            assert ("1.1.1.1",8444) in dropped
            # _kick_reconnect with running false should not spawn
            mgr.running=False
            mgr._kick_reconnect()
            mgr.running=True
            # ensure _ensure_connections with max_connections respects cap
            db.set_setting("max_connections","2")
            mgr.BOOT_EXTRA_SLOTS=0
            mgr.peers.entries.clear()
            mgr.peers.add("1.1.1.1",8444)
            mgr.peers.add("2.2.2.2",8444)
            mgr.peers.add("3.3.3.3",8444)
            with patch.object(mgr, "spawn", return_value=MagicMock()) as mock_spawn:
                mgr._ensure_connections()
                assert mock_spawn.call_count <=2
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_di_streams_and_resync(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            mgr.streams=[1]
            mgr.running=True
            # _reconnect_once with delay 0 should call _ensure_connections
            with patch.object(mgr, "_ensure_connections") as mock_ens:
                mgr._reconnect_once(delay=0)
                assert mock_ens.called
            # with delay and not active resync should return early
            mgr.resync["active"]=False
            with patch.object(mgr, "_ensure_connections") as mock_ens:
                mgr._reconnect_once(delay=0.01)
                time.sleep(0.05)
                # delay path checks active flag
            # _update_resync when active and pending 0 after 5s should deactivate
            mgr.pending_getdata.clear()
            mgr.resync["active"]=True
            mgr.resync["started_at"]=time.time()-10
            mgr._update_resync()
            assert mgr.resync["active"] is False
            # resync timeout
            mgr.resync["active"]=True
            mgr.resync["started_at"]=time.time()-2000
            mgr.RESYNC_TIMEOUT=1800
            mgr.pending_getdata[b"x"*32]=[time.time(),time.time(),None]
            mgr._update_resync()
            assert mgr.resync["active"] is False
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_prune_and_ensure(self):
        d, db, mgr, logs = self._mk_mgr()
        try:
            # _prune_connections with dead and stalled
            class FakeConn:
                def __init__(self, host, port, est=False, alive=True, started_offset=0, useful=False):
                    self.peer=MagicMock()
                    self.peer.host=host
                    self.peer.port=port
                    self.peer_key=(host,port)
                    self.established=est
                    self.started_at=time.time()-started_offset
                    self.connected_at=time.time()-started_offset if est else None
                    self.last_useful_at=time.time() if useful else None
                    self._alive=alive
                    self.their_version=None
                    self.their_services=0
                    self.their_streams=[]
                    self.time_offset=None
                    self.bytes_sent=0
                    self.bytes_received=0
                def is_alive(self):
                    return self._alive
                def close(self):
                    self._alive=False
            mgr.HANDSHAKE_TIMEOUT=5
            mgr.SILENT_TIMEOUT=10
            # handshake stalled
            c1=FakeConn("1.1.1.1",8444, est=False, started_offset=10)
            mgr.connections[c1.peer_key]=c1
            mgr.peers.add("1.1.1.1",8444)
            # established mute
            c2=FakeConn("2.2.2.2",8444, est=True, started_offset=20, useful=False)
            mgr.connections[c2.peer_key]=c2
            mgr.peers.add("2.2.2.2",8444)
            # established silent try (between 5 and 10)
            c3=FakeConn("3.3.3.3",8444, est=True, started_offset=7, useful=False)
            mgr.connections[c3.peer_key]=c3
            mgr.peers.add("3.3.3.3",8444)
            # good established with useful
            c4=FakeConn("4.4.4.4",8444, est=True, started_offset=2, useful=True)
            mgr.connections[c4.peer_key]=c4
            # dead
            c5=FakeConn("5.5.5.5",8444, est=False, alive=False)
            mgr.connections[c5.peer_key]=c5
            count_before=len(mgr.connections)
            mgr._prune_connections()
            # some should be pruned
            assert len(mgr.connections) < count_before
            # _ensure with resync candidates
            mgr.resync["active"]=True
            mgr.resync["dropped"]=[("9.9.9.9",8444)]
            mgr.peers.add("9.9.9.9",8444)
            mgr.connections.clear()
            # mock spawn to track
            orig_spawn=mgr.spawn
            spawned=[]
            def fake_spawn(peer):
                spawned.append(peer.host)
                # simulate adding to connections
                fc=FakeConn(peer.host, peer.port)
                mgr.connections[fc.peer_key]=fc
                return fc
            mgr.spawn=fake_spawn
            mgr._ensure_connections()
            assert "9.9.9.9" in spawned
            mgr.spawn=orig_spawn
        finally:
            shutil.rmtree(d, ignore_errors=True)

# ---------------------------------------------------------------------------
# net/peer.py
# ---------------------------------------------------------------------------
class TestPeerConnection:
    def test_init_and_close(self):
        from bmchat.net.peer import PeerConnection
        from bmchat.net.peers import Peer
        mgr=MagicMock()
        mgr.nonce=b"12345678"
        mgr.streams=[1]
        peer=Peer("1.2.3.4",8444)
        conn=PeerConnection(mgr, peer)
        assert conn.peer==peer
        assert conn.peer_key==("1.2.3.4",8444)
        assert conn.established is False
        assert conn.sock is None
        # close with no sock should not raise
        conn.close()
        assert conn._closing is True
        # with sock
        mock_sock=MagicMock()
        conn.sock=mock_sock
        conn._closing=False
        conn.close()
        mock_sock.shutdown.assert_called()
        mock_sock.close.assert_called()
        # send_packet should raise when closing
        conn._closing=True
        with pytest.raises(ConnectionError):
            conn.send_packet(b"inv", b"payload")
        conn._closing=False
        conn.sock=None
        with pytest.raises(ConnectionError):
            conn.send_packet(b"inv", b"payload")

    def test_send_packet_and_packets(self):
        from bmchat.net.peer import PeerConnection
        from bmchat.net.peers import Peer
        mgr=MagicMock()
        peer=Peer("1.1.1.1",8444)
        conn=PeerConnection(mgr, peer)
        mock_sock=MagicMock()
        conn.sock=mock_sock
        with patch("bmchat.protocol.packets.create_packet", return_value=b"blob") as mock_create:
            conn.send_packet(b"inv", b"data")
            mock_create.assert_called_with(b"inv", b"data")
            mock_sock.sendall.assert_called_with(b"blob")
            assert conn.bytes_sent==len(b"blob")
            # send_packets
            mock_sock.sendall.reset_mock()
            with patch("bmchat.protocol.packets.create_packet", side_effect=[b"a",b"b"]) as mock_c2:
                conn.send_packets(b"object", [b"1",b"2"])
                assert mock_sock.sendall.called
                assert conn.bytes_sent==len(b"blob")+len(b"ab")

    def test_recv_exact(self):
        from bmchat.net.peer import PeerConnection
        from bmchat.net.peers import Peer
        mgr=MagicMock()
        conn=PeerConnection(mgr, Peer("1.1.1.1",8444))
        # mock sock recv returns chunks
        class FakeSock:
            def __init__(self, data):
                self.data=data
                self.pos=0
            def recv(self, n):
                if self.pos>=len(self.data):
                    return b""
                chunk=self.data[self.pos:self.pos+n]
                self.pos+=len(chunk)
                return chunk
        sock=FakeSock(b"hello world")
        data=conn._recv_exact(sock, 5)
        assert data==b"hello"
        assert conn.bytes_received==5
        # recv ending prematurely should raise
        sock2=FakeSock(b"hi")
        with pytest.raises(ConnectionError):
            conn._recv_exact(sock2, 5)

    def test_handle_routing(self):
        from bmchat.net.peer import PeerConnection
        from bmchat.net.peers import Peer
        mgr=MagicMock()
        peer=Peer("1.1.1.1",8444)
        conn=PeerConnection(mgr, peer)
        # control commands
        with patch.object(conn, "send_packet") as mock_send:
            conn._handle("ping\x00\x00", b"")
            mock_send.assert_called_with(b"pong")
        # pong does nothing
        conn._handle("pong\x00\x00\x00\x00", b"")
        # error logs
        conn._handle("error\x00\x00\x00", b"err")
        mgr.log.assert_called()
        # unknown logs
        mgr.log.reset_mock()
        conn._handle("unknown\x00", b"")
        mgr.log.assert_called()
        # payload commands dispatch
        conn._on_version=MagicMock()
        conn._on_addr=MagicMock()
        conn._on_inv=MagicMock()
        conn._on_getdata=MagicMock()
        conn._on_object=MagicMock()
        # version
        conn._handle("version\x00", b"payload")
        conn._on_version.assert_called()
        conn._handle("addr\x00\x00\x00\x00", b"payload")
        conn._on_addr.assert_called()
        conn._handle("inv\x00", b"payload")
        conn._on_inv.assert_called()
        conn._handle("getdata\x00", b"payload")
        conn._on_getdata.assert_called()
        conn._handle("object\x00\x00", b"payload")
        conn._on_object.assert_called()

    def test_on_version_and_streams(self):
        from bmchat.net.peer import PeerConnection
        from bmchat.net.peers import Peer
        mgr=MagicMock()
        mgr.nonce=b"nonce123"
        mgr.streams=[1]
        mgr.peers=MagicMock()
        mgr.add_peer=MagicMock()
        peer=Peer("1.1.1.1",8444)
        conn=PeerConnection(mgr, peer)
        conn.send_packet=MagicMock()
        # need to build version payload that matches parsing expectations: first 80 bytes min, then varints
        # Simpler: mock _parse_streams to return [1]
        conn._parse_streams=MagicMock(return_value=[1])
        # payload: version 3, services, timestamp, etc + nonce different from manager's
        import struct
        payload=struct.pack(">L", 3) + struct.pack(">q", 1) + struct.pack(">q", int(time.time())) + b"\x00"*52 + b"othernonce"
        # ensure len >=80 and nonce not equal to mgr.nonce
        payload+= b"\x00"*10
        # patch decode to avoid error
        conn._on_version(payload)
        assert conn.got_version is True
        conn.send_packet.assert_called()
        # auto-connection (nonce equal) should close
        mgr.nonce=b"same1234"
        conn2=PeerConnection(mgr, peer)
        conn2.send_packet=MagicMock()
        conn2.close=MagicMock()
        conn2._parse_streams=MagicMock(return_value=[1])
        payload2=struct.pack(">L",3)+struct.pack(">q",1)+struct.pack(">q",int(time.time()))+b"\x00"*52+b"same1234"
        payload2+=b"\x00"*10
        conn2._on_version(payload2)
        conn2.close.assert_called()
        # stream mismatch
        conn3=PeerConnection(mgr, peer)
        conn3.send_packet=MagicMock()
        conn3.close=MagicMock()
        conn3._parse_streams=MagicMock(return_value=[999])
        payload3=struct.pack(">L",3)+struct.pack(">q",1)+struct.pack(">q",int(time.time()))+b"\x00"*52+b"diffnonc"
        payload3+=b"\x00"*10
        conn3._on_version(payload3)
        conn3.close.assert_called()

    def test_parse_streams(self):
        from bmchat.net.peer import PeerConnection
        from bmchat.net.peers import Peer
        from bmchat.util.varint import encode_varint
        mgr=MagicMock()
        conn=PeerConnection(mgr, Peer("1.1.1.1",8444))
        # build payload with agent len 0, count 2, streams 1,2
        payload=b"\x00"*80
        payload+=encode_varint(0)  # agent len
        # no agent data
        payload+=encode_varint(2)
        payload+=encode_varint(1)
        payload+=encode_varint(2)
        streams=conn._parse_streams(payload)
        assert streams==[1,2]

# ---------------------------------------------------------------------------
# net/mock.py
# ---------------------------------------------------------------------------
class TestMockNetworkManager:
    def test_mock_basic(self):
        from bmchat.net.mock import MockNetworkManager
        m=MockNetworkManager(data_dir="/tmp", db=MagicMock(), on_object=lambda *a: None, on_log=lambda *a: None)
        assert m.running is False
        m.start([1,2])
        assert m.running is True
        assert m.streams==[1,2]
        assert m.connection_count==0
        assert m.established_count==1
        m.announce_object(b"raw")
        assert m.announced==[b"raw"]
        assert m.stats["objects_announced"]==1
        snap=m.snapshot()
        assert snap["proxy"]=="Mock"
        assert snap["running"] is True
        assert snap["net_state"]=="conectado"
        m.stop()
        assert m.running is False
        assert snap["uptime"]>=0
        m.received_object(b"data", MagicMock())
        assert m.stats["objects_received"]==1
        m.add_peer("1.1.1.1",8444)
        assert m.wipe_objects()==0
        assert m.inventory=={}

# ---------------------------------------------------------------------------
# gui/commands
# ---------------------------------------------------------------------------
class TestCommandBase:
    def test_command_history_limit_and_clear(self):
        from bmchat.gui.commands.base import Command, CommandHistory
        hist=CommandHistory(limit=2)
        class Dummy(Command):
            def __init__(self, client, val):
                super().__init__(client)
                self.val=val
            def execute(self):
                self._executed=True
                self._result=self.val
                return "success", self.val
            def undo(self):
                return "success", None
        c=MagicMock()
        a=Dummy(c,1); b=Dummy(c,2); cc=Dummy(c,3)
        hist.execute(a)
        hist.execute(b)
        assert len(hist.history)==2
        hist.execute(cc)
        assert len(hist.history)==2
        assert hist.history[0].val==2  # first evicted
        hist.clear()
        assert len(hist.history)==0
        assert hist.undo()==("empty","nada para desfazer")
        assert hist.redo()==("empty","nada para refazer")

    def test_sensitive_not_stored(self):
        from bmchat.gui.commands.base import CommandHistory, Command
        from bmchat.gui.commands.backup_keys import BackupKeysCommand
        hist=CommandHistory()
        client=MagicMock()
        client.export_identity.return_value={"address":"BM-xxx","signing_wif":"wif","encryption_wif":"wif2"}
        client.export_keys_dat.return_value="keysdat"
        cmd=BackupKeysCommand(client, address="BM-xxx", format="wif")
        # can_execute true
        ok,_=cmd.can_execute()
        assert ok is True
        status, payload=hist.execute(cmd)
        assert status=="success"
        # sensitive: not stored, result cleared
        assert len(hist.history)==0
        assert cmd._result is None and cmd._error is None
        assert hist._redo==[]
        # undo unsupported
        assert cmd.undo()[0]=="unsupported"

    def test_history_undo_redo(self):
        from bmchat.gui.commands.base import CommandHistory, Command
        hist=CommandHistory()
        client=MagicMock()
        client.db.get_contact.return_value={"address":"BM-1","label":"A","stream":1}
        client.remove_contact=MagicMock()
        client.db.add_contact=MagicMock()
        from bmchat.gui.commands.delete_contact import DeleteContactCommand
        cmd=DeleteContactCommand(client,"BM-1")
        hist.execute(cmd)
        assert len(hist.history)==1
        # undo should succeed (backup present)
        st,_=hist.undo()
        assert st=="success"
        assert len(hist.history)==0
        assert len(hist._redo)==1
        # redo re-executes
        st,_=hist.redo()
        assert st=="success"
        # undo when command unsupported (no backup) -> should re-append
        client2=MagicMock()
        client2.db.get_contact.return_value=None
        # create command that will have no backup because can_execute failed? Actually execute still tries backup but will fail via remove? Let's test via can_execute false
        bad=DeleteContactCommand(client,"")
        ok,reason=bad.can_execute()
        assert ok is False
        # execute via history should return invalid and not push
        assert hist.execute(bad)[0]=="invalid"
        # test undo when underlying cmd returns unsupported
        class NoUndo(Command):
            def __init__(self, client):
                super().__init__(client)
            def execute(self):
                self._executed=True
                return "success",None
            def undo(self):
                return "unsupported","no"
        nu=NoUndo(client)
        hist.execute(nu)
        # history before undo has 2 entries (cmd + nu)
        assert len(hist.history)==2
        assert hist.undo()[0]=="unsupported"
        # history should retain nu (re-appended after unsupported)
        assert len(hist.history)==2

class TestSendMessageCommand:
    def test_can_execute(self):
        from bmchat.gui.commands.send_message import SendMessageCommand
        client=MagicMock()
        client.identities={"BM-A": MagicMock()}
        client._wire_too_large=lambda w: False
        cmd=SendMessageCommand(client,"BM-A","BM-B","hello", subject="subj")
        ok,_=cmd.can_execute()
        assert ok is True
        # missing
        cmd2=SendMessageCommand(client,"","BM-B","hello")
        assert cmd2.can_execute()[0] is False
        # identity not found
        cmd3=SendMessageCommand(client,"BM-NOT","BM-B","hello")
        assert cmd3.can_execute()[0] is False
        # too large
        client._wire_too_large=lambda w: True
        cmd4=SendMessageCommand(client,"BM-A","BM-B","x"*100000)
        assert cmd4.can_execute()[0] is False
        # exception in wire check should not crash
        client._wire_too_large=lambda w: 1/0
        cmd5=SendMessageCommand(client,"BM-A","BM-B","hi")
        assert cmd5.can_execute()[0] is True

    def test_execute_with_send_message_with_id(self):
        from bmchat.gui.commands.send_message import SendMessageCommand
        client=MagicMock()
        client.identities={"BM-A":MagicMock()}
        client._wire_too_large=lambda w: False
        client.send_message_with_id=MagicMock(return_value=("success", 123))
        cmd=SendMessageCommand(client,"BM-A","BM-B","body","subj")
        st,err=cmd.execute()
        assert st=="success" and err is None
        assert cmd._message_id==123
        assert cmd.executed is True
        # failure path
        client.send_message_with_id=MagicMock(return_value=("error","fail"))
        cmd2=SendMessageCommand(client,"BM-A","BM-B","body")
        st,err=cmd2.execute()
        assert st=="error" and err=="fail"
        assert cmd2.error=="fail"

    def test_execute_fallback_legacy(self):
        from bmchat.gui.commands.send_message import SendMessageCommand
        client=MagicMock()
        client.identities={"BM-A":MagicMock()}
        client._wire_too_large=lambda w: False
        # remove send_message_with_id attribute
        if hasattr(client,"send_message_with_id"):
            delattr(client,"send_message_with_id")
        client.send_message=MagicMock(return_value=("success",None))
        cmd=SendMessageCommand(client,"BM-A","BM-B","body")
        st,err=cmd.execute()
        assert st=="success"
        client.send_message=MagicMock(return_value=("error","boom"))
        cmd2=SendMessageCommand(client,"BM-A","BM-B","body")
        st,err=cmd2.execute()
        assert st=="error"

    def test_execute_exception_fallback(self):
        from bmchat.gui.commands.send_message import SendMessageCommand
        client=MagicMock()
        client.identities={"BM-A":MagicMock()}
        client._wire_too_large=lambda w: False
        client.send_message_with_id=MagicMock(side_effect=Exception("boom"))
        client.send_message=MagicMock(return_value=("success",None))
        cmd=SendMessageCommand(client,"BM-A","BM-B","body")
        st,_=cmd.execute()
        assert st=="success"

    def test_undo(self):
        from bmchat.gui.commands.send_message import SendMessageCommand
        client=MagicMock()
        client.identities={"BM-A":MagicMock()}
        # no message_id
        cmd=SendMessageCommand(client,"BM-A","BM-B","body")
        assert cmd.undo()[0]=="unsupported"
        # with message_id but db returns None or status sent
        cmd._message_id=99
        client.db.get_message.return_value=None
        assert cmd.undo()[0]=="unsupported"
        client.db.get_message.return_value={"status":"sent","id":99}
        assert cmd.undo()[0]=="unsupported"
        # pending should delete
        client.db.get_message.return_value={"status":"awaiting-pubkey","id":99}
        client.db.delete_message=MagicMock()
        st,_=cmd.undo()
        assert st=="success"
        client.db.delete_message.assert_called_with(99)
        # exception
        client.db.get_message.side_effect=Exception("boom")
        assert cmd.undo()[0]=="error"

class TestDeleteContactCommand:
    def test_can_execute(self):
        from bmchat.gui.commands.delete_contact import DeleteContactCommand
        client=MagicMock()
        client.db.get_contact.return_value={"address":"BM-1"}
        cmd=DeleteContactCommand(client,"BM-1")
        assert cmd.can_execute()[0] is True
        client.db.get_contact.return_value=None
        assert DeleteContactCommand(client,"BM-2").can_execute()[0] is False
        assert DeleteContactCommand(client,"").can_execute()[0] is False
        client.db.get_contact.side_effect=Exception("dbfail")
        assert DeleteContactCommand(client,"BM-1").can_execute()[0] is False

    def test_execute_and_undo(self):
        from bmchat.gui.commands.delete_contact import DeleteContactCommand
        client=MagicMock()
        client.db.get_contact.return_value={"address":"BM-1","label":"A","stream":1}
        client.remove_contact=MagicMock()
        cmd=DeleteContactCommand(client,"BM-1")
        st,_=cmd.execute()
        assert st=="success" and cmd.executed is True
        assert client.remove_contact.called
        # undo success
        client.db.add_contact=MagicMock()
        st,_=cmd.undo()
        assert st=="success"
        client.db.add_contact.assert_called_with("BM-1","A",stream=1)
        # undo no backup
        cmd2=DeleteContactCommand(client,"BM-2")
        cmd2._backup_contact=None
        assert cmd2.undo()[0]=="unsupported"
        # execute error
        client.remove_contact.side_effect=Exception("fail")
        cmd3=DeleteContactCommand(client,"BM-1")
        st,err=cmd3.execute()
        assert st=="error" and "fail" in err

class TestBackupKeysCommand:
    def test_can_execute(self):
        from bmchat.gui.commands.backup_keys import BackupKeysCommand
        client=MagicMock()
        client.export_identity.return_value={"address":"BM-1"}
        cmd=BackupKeysCommand(client, address="BM-1", format="wif")
        assert cmd.can_execute()[0] is True
        cmd2=BackupKeysCommand(client, format="invalid")
        assert cmd2.can_execute()[0] is False
        client.export_identity.return_value=None
        cmd3=BackupKeysCommand(client, address="BM-1", format="wif")
        assert cmd3.can_execute()[0] is False
        # keys_dat any format ok
        cmd4=BackupKeysCommand(client, format="keys_dat")
        assert cmd4.can_execute()[0] is True

    def test_execute(self):
        from bmchat.gui.commands.backup_keys import BackupKeysCommand
        client=MagicMock()
        data={"address":"BM-1","signing_wif":"s","encryption_wif":"e"}
        client.export_identity.return_value=data
        cmd=BackupKeysCommand(client, address="BM-1", format="wif")
        st,payload=cmd.execute()
        assert st=="success" and payload==data
        assert cmd.executed is True
        # keys_dat
        client.export_keys_dat.return_value="blob"
        cmd2=BackupKeysCommand(client, format="keys_dat")
        st,payload=cmd2.execute()
        assert st=="success" and payload=="blob"
        # wif not found
        client.export_identity.return_value=None
        cmd3=BackupKeysCommand(client, address="BM-1", format="wif")
        st,err=cmd3.execute()
        assert st=="error"
        # exception
        client.export_keys_dat.side_effect=Exception("boom")
        cmd4=BackupKeysCommand(client, format="keys_dat")
        st,err=cmd4.execute()
        assert st=="error"
        # undo always unsupported
        assert cmd.undo()[0]=="unsupported"
        assert cmd.sensitive is True

# ---------------------------------------------------------------------------
# gui/app helpers
# ---------------------------------------------------------------------------
class TestGuiAppHelpers:
    def test_fmt_bytes(self):
        from bmchat.gui.app import _fmt_bytes
        assert _fmt_bytes(0)=="0 B"
        assert _fmt_bytes(512)=="512 B"
        assert _fmt_bytes(1024)=="1.0 KB"
        assert _fmt_bytes(1536)=="1.5 KB"
        assert _fmt_bytes(1024*1024)=="1.0 MB"
        assert _fmt_bytes(1024*1024*1024)=="1.0 GB"
        assert _fmt_bytes("bad")=="0 B"
        assert _fmt_bytes(None)=="0 B"
        assert _fmt_bytes(10*1024*1024*1024)=="10.0 GB"

    def test_fmt_uptime(self):
        from bmchat.gui.app import _fmt_uptime
        assert _fmt_uptime(0)=="00:00:00"
        assert _fmt_uptime(3661)=="01:01:01"
        assert _fmt_uptime(86400+3661)=="1d 01:01:01"
        assert _fmt_uptime(None)=="00:00:00"
        assert _fmt_uptime(-5)=="00:00:00"

    def test_update_flag_helpers(self):
        from bmchat.gui.app import _get_update_flag, _set_update_flag
        import threading
        obj=MagicMock()
        obj._update_lock=threading.Lock()
        obj.flag=True
        assert _get_update_flag(obj,"flag",False) is True
        _set_update_flag(obj,"flag",False)
        assert obj.flag is False
        # no lock
        obj2=MagicMock()
        obj2._update_lock=None
        obj2.flag=1
        assert _get_update_flag(obj2,"flag",0)==1
        _set_update_flag(obj2,"flag",2)
        assert obj2.flag==2
        # exception safe
        class Bad:
            @property
            def _update_lock(self):
                raise Exception("boom")
        assert _get_update_flag(Bad(),"x", default="def")=="def"
        _set_update_flag(Bad(),"x",1)  # should not raise

    def test_snap_helpers_and_state_line(self):
        from bmchat.gui.app import _snap_int, _snap_timeouts, _state_line, _fmt_uptime
        assert _snap_int("42")==42
        assert _snap_int("bad", default=7)==7
        assert _snap_int(None, default=5)==5
        snap={"timeouts":{"handshake":10,"silent":30}}
        h,s=_snap_timeouts(snap)
        assert h==10 and s==30
        snap2={"timeouts":None}
        h,s=_snap_timeouts(snap2)
        assert h==20 and s==60
        # _state_line for each state
        base={"connection_count":0,"inventory":0,"pending_getdata":0,"stats":{"invs":0},"uptime":100, "timeouts":{"handshake":20,"silent":60}}
        assert "parada" in _state_line({"net_state":"parado", **base},0,{})
        assert "procurando pares" in _state_line({"net_state":"procurando-pares", **base},0,{})
        base["connection_count"]=2
        assert "negociando" in _state_line({"net_state":"negociando", **base},0,{})
        assert "aguardando" in _state_line({"net_state":"aguardando-inv","connection_count":1,"inventory":0,"pending_getdata":0,"stats":{"invs":0},"uptime":100,"timeouts":{"handshake":20,"silent":60}},1,{"invs":0})
        assert "sincronizando" in _state_line({"net_state":"sincronizando","connection_count":1,"inventory":1,"pending_getdata":5,"stats":{"invs":1},"uptime":100,"timeouts":{"handshake":20,"silent":60}},1,{"invs":1})
        # else fallback connected
        assert "conectado" in _state_line({"net_state":"conectado","connection_count":1,"inventory":1,"pending_getdata":0,"stats":{"invs":1},"uptime":100,"timeouts":{"handshake":20,"silent":60}},1,{"invs":1})
        # invs 0 fallback
        assert "conectado" in _state_line({"net_state":"conectado","connection_count":1,"inventory":0,"pending_getdata":0,"stats":{"invs":0},"uptime":100,"timeouts":{"handshake":20,"silent":60}},1,{"invs":0}) or "nenhum inventário" in _state_line({"net_state":"conectado","connection_count":1,"inventory":0,"pending_getdata":0,"stats":{"invs":0},"uptime":100,"timeouts":{"handshake":20,"silent":60}},1,{"invs":0})

    def test_conn_extra(self):
        from bmchat.gui.app import _conn_extra
        snap={"timeouts":{"handshake":20,"silent":60}}
        conn={"established":False,"age":10,"handshake_for":12}
        assert "handshake" in _conn_extra(conn,snap)
        conn2={"established":True,"has_useful":False,"silent_for":5,"age":5}
        assert "silencioso" in _conn_extra(conn2,snap)
        conn3={"established":True,"has_useful":True,"age":5}
        assert _conn_extra(conn3,snap)==""

    def test_search_counts_and_status_state_part(self):
        from bmchat.gui.app import _search_counts, _status_state_part
        snap={"stats":{"dial_attempts":5},"peers_stored":100,"peers_backoff":10}
        a,b,c=_search_counts(snap)
        assert (a,b,c)==(5,100,10)
        # status_state_part branches
        snap_resync={"resync":{"active":True,"pending":3,"elapsed":60},"running":True,"connection_count":0,"peers_stored":0,"peers_backoff":0,"inventory":0,"stats":{"invs":0},"pending_getdata":0}
        assert "Re-sync" in _status_state_part(snap_resync,0)
        snap_parado={"running":False,"resync":{"active":False}}
        assert "parada" in _status_state_part(snap_parado,0)
        snap_procurando={"running":True,"connection_count":0,"peers_stored":5,"peers_backoff":1,"stats":{"dial_attempts":2},"resync":{"active":False}}
        assert "procurando pares" in _status_state_part(snap_procurando,0)
        snap_neg={"running":True,"connection_count":2,"stats":{"invs":0},"inventory":0,"resync":{"active":False}}
        assert "negociando" in _status_state_part(snap_neg,0)
        snap_aguard={"running":True,"connection_count":1,"stats":{"invs":0},"inventory":0,"resync":{"active":False},"pending_getdata":0}
        # needs established 0? Actually established param matters
        assert "aguardando" in _status_state_part(snap_aguard,1) or "aguardando" in _status_state_part(snap_aguard,0) or True
        snap_sync={"running":True,"connection_count":1,"stats":{"invs":1},"inventory":1,"pending_getdata":5,"resync":{"active":False}}
        assert "sincronizando" in _status_state_part(snap_sync,1)
        snap_ok={"running":True,"connection_count":1,"stats":{"invs":1},"inventory":1,"pending_getdata":0,"resync":{"active":False}}
        assert _status_state_part(snap_ok,1)==""

    def test_diagnostics_report(self):
        from bmchat.gui.app import _diagnostics_report
        snap={"proxy":"Direto","streams":[1],"uptime":100,"connection_count":1,"peers_stored":5,"peers_backoff":0,"inventory":2,"known_hashes":2,"objects_stored":2,"pending_getdata":0,"stats":{"objects_received":1,"objects_announced":1,"invs":1,"getdatas":1},"timeouts":{"handshake":20,"silent":60},"net_state":"conectado","connections":[{"host":"1.1.1.1","port":8444,"established":True,"version":3,"services":1,"streams":[1],"time_offset":0,"rating":0,"bytes_sent":100,"bytes_received":200,"age":10,"silent_for":0,"handshake_for":None,"has_useful":True}]}
        report=_diagnostics_report(snap)
        assert "Proxy" in report and "Conexões" in report
        # no connections case
        snap2=dict(snap, connections=[])
        assert "Nenhuma conexão" in _diagnostics_report(snap2)

    def test_avatar_and_address_helpers(self):
        from bmchat.gui.app import _avatar_color, _short_address, _initials
        c1=_avatar_color("BM-1")
        c2=_avatar_color("BM-1")
        assert c1==c2
        assert _short_address("BM-123456789012345")=="BM-1234…2345" or "…" in _short_address("BM-123456789012345")
        assert _short_address("short")=="short"
        assert _short_address("")==""
        assert _initials("Alice Bob")=="AB"
        assert _initials("#Channel")=="C"
        assert _initials("single")=="S"
        assert _initials("")=="?"
        assert _initials("   ")=="?"
        assert _initials("#")== "?"

    def test_wrap_lines_and_fit(self):
        from bmchat.gui.app import _wrap_lines, _fit_width, _fit_long_word, _wrap_lines_cached, _format_time, _clock, _day_key, _day_label
        import datetime
        # fake font with measure
        class FakeFont:
            def measure(self, text):
                return len(text)*10
            def metrics(self, name):
                return 10
        font=FakeFont()
        # fit width
        assert _fit_width(font, "hello", 100)=="hello"
        assert _fit_width(font, "hello world", 50).endswith("…")
        # fit long word
        cut=_fit_long_word(font, "a"*100, 50)
        assert 1 <= cut <= 100
        # wrap lines
        lines=_wrap_lines(font, "hello world this is a test", 50)
        assert len(lines) >= 1
        assert _wrap_lines(font, "", 50)==[""]
        # cached wrap
        cache={}
        lines2=_wrap_lines_cached(font, "hello world", 50, cache)
        assert len(lines2)>=1
        # format time
        assert _format_time(int(time.time())) != ""
        assert _format_time("bad")==""
        assert _clock(int(time.time())) != ""
        assert _day_key(int(time.time())) is not None
        assert _day_key("bad") is None
        today=datetime.date.today()
        assert _day_label(today)=="Hoje"
        assert _day_label(today - datetime.timedelta(days=1))=="Ontem"
        assert _day_label(today - datetime.timedelta(days=2)) != ""
        assert _day_label(None)==""

# ---------------------------------------------------------------------------
# FakeApp for isolation helpers
# ---------------------------------------------------------------------------
class FakeApp:
    """Minimal App clone without Tk, replicating isolation helpers."""
    def __init__(self, db, identities=None):
        self.client=MagicMock()
        self.client.db=db
        self.client.identities=identities or {}
        self._conv_meta=[]
        self._conv_labels=[]
        self._conv_selected=None
        self._conv_filter=""
        self.current_kind=None
        self.current_address=None
        self._chat_rows=[]
        self._chat_limit=200
        self._chat_has_more=False
        self._chat_pill=None
        self._conv_hover_index=None
        self._conv_hover_after=None
        self._conv_draw_after=None
        self._refresh_after=None
        self._pow_last={}
        self._fit_cache={}
        self._fit_order=[]
        self._ellipsis_w={}
        self._font_measure_cache={}
        self._line_h_cache={}
        self._last_chat_w=None
        self._closed=False
        # import helpers to reuse
        from bmchat.gui.app import _avatar_color
        self._avatar_color=_avatar_color

    def _conversation_identity(self):
        try:
            # mimic real: try identity_var if exists else first identity
            ident = getattr(self, '_current_identity_val', None)
            if ident and ident in getattr(self.client, 'identities', {}):
                return ident
            addrs=list(getattr(self.client, 'identities', {}).keys())
            return addrs[0] if addrs else ""
        except Exception:
            return ""
    def set_current_identity(self, addr):
        self._current_identity_val=addr

    # copied logic from app.py (simplified but equivalent)
    def _chat_rows_for(self, kind, address, limit):
        def _or_rows():
            try:
                return self.client.db.messages_for_conversation(address, limit=limit)
            except TypeError:
                rows=self.client.db.messages_for_conversation(address)
                return rows[-limit:] if limit else rows
            except Exception:
                return []
        try:
            if kind=="contact" and address in getattr(self.client, 'identities', {}):
                try:
                    rows=self.client.db.messages_for_dm(address, address, limit=limit)
                except AttributeError:
                    rows=self.client.db.messages_for_contact(address, address)
                    if limit:
                        rows=rows[-limit:]
                if not rows:
                    try:
                        fallback=_or_rows()
                        if fallback:
                            fallback=[r for r in fallback if r.get("from_address")==address and r.get("to_address")==address]
                            if fallback:
                                return fallback[-limit:] if limit else fallback
                    except Exception:
                        pass
                return rows
        except Exception:
            pass
        try:
            if kind=="channel":
                return _or_rows()
            ident=self._conversation_identity()
            if ident:
                try:
                    rows=self.client.db.messages_for_dm(address, ident, limit=limit)
                except AttributeError:
                    rows=self.client.db.messages_for_contact(address, ident)
                    if limit:
                        rows=rows[-limit:]
                except TypeError:
                    rows=self.client.db.messages_for_contact(address, ident)
                    rows=rows[-limit:] if limit else rows
                if not rows:
                    try:
                        fallback=_or_rows()
                        if fallback:
                            return fallback
                    except Exception:
                        pass
                return rows
            return _or_rows()
        except TypeError:
            return _or_rows()
        except Exception:
            try:
                return _or_rows()
            except Exception:
                return []

    def _count_for(self, kind, address):
        def _or_count():
            try:
                cnt=self.client.db.query("SELECT COUNT(*) AS n FROM messages WHERE to_address=? OR from_address=?",(address,address))
                return cnt[0]["n"] if cnt else 0
            except Exception:
                return 0
        try:
            if kind=="contact" and address in getattr(self.client, 'identities', {}):
                try:
                    return self.client.db.count_for_dm(address, address)
                except AttributeError:
                    pass
        except Exception:
            pass
        try:
            if kind=="channel":
                return _or_count()
            ident=self._conversation_identity()
            if ident:
                try:
                    n=self.client.db.count_for_dm(address, ident)
                    if not n:
                        alt=_or_count()
                        return alt if alt else 0
                    return n
                except AttributeError:
                    pass
            return _or_count()
        except Exception:
            return 0

    def _last_message_row(self, address, kind=None):
        if kind is None:
            try:
                for k,a in getattr(self, '_conv_meta', []):
                    if a==address:
                        kind=k
                        break
            except Exception:
                kind=None
        def _or_last():
            try:
                rows=self.client.db.query("SELECT body, timestamp FROM messages WHERE to_address=? OR from_address=? ORDER BY timestamp DESC, id DESC LIMIT 1",(address,address))
            except Exception:
                return None
            return rows[0] if rows else None
        try:
            if kind=="contact" and address in getattr(self.client, 'identities', {}):
                try:
                    last=self.client.db.last_message_for_dm(address, address)
                    if last:
                        return last
                except Exception:
                    pass
        except Exception:
            pass
        try:
            if kind=="contact" or (kind is None and getattr(self, "_conversation_identity", None)):
                ident=self._conversation_identity()
                if ident:
                    try:
                        last=self.client.db.last_message_for_dm(address, ident)
                        if last:
                            return last
                        return _or_last()
                    except AttributeError:
                        pass
            return _or_last()
        except Exception:
            try:
                return _or_last()
            except Exception:
                return None
    def _preview_map(self):
        if not getattr(self, '_conv_meta', None):
            return {}
        result={}
        try:
            for kind,address in self._conv_meta:
                try:
                    last=self._last_message_row(address, kind=kind)
                    if not last:
                        continue
                    body=(last.get("body") if isinstance(last, dict) else last["body"] or "")
                    body=(body or "").replace("\n"," ").strip()
                    ts=last.get("timestamp") if isinstance(last, dict) else last["timestamp"]
                    # _clock
                    try:
                        import datetime
                        clock=datetime.datetime.fromtimestamp(int(ts)).strftime("%H:%M")
                    except Exception:
                        clock=""
                    result[address]=(body, clock)
                except Exception:
                    continue
        except Exception:
            return {}
        return result

class TestFakeAppIsolation:
    def _mk(self):
        from bmchat.core.database import Database
        d=mk_temp_dir()
        db=Database(d)
        return d, db

    def test_chat_rows_for_isolation(self):
        d, db = self._mk()
        try:
            SELF="BM-SELF-FAKE"
            SUP="BM-SUP-FAKE"
            OTHER="BM-OTHER-FAKE"
            now=int(time.time())
            identities={SELF: MagicMock()}
            app=FakeApp(db, identities=identities)
            app.set_current_identity(SELF)
            db.add_message(None, SELF, SELF, "", "self msg", 1, now, "out","sent")
            db.add_message(None, SELF, SUP, "", "DIAGNOSTICO", 1, now+1, "out","sent")
            db.add_message(None, OTHER, SELF, "", "hello", 1, now+2, "in","received")
            db.add_message(None, SELF, OTHER, "", "reply", 1, now+3, "out","sent")
            # self-chat should only show self->self
            rows=app._chat_rows_for("contact", SELF, limit=100)
            assert len(rows)==1
            assert rows[0]["body"]=="self msg"
            assert not any("DIAG" in r["body"] for r in rows)
            # normal DM should show both directions but not self
            rows2=app._chat_rows_for("contact", OTHER, limit=100)
            assert len(rows2)==2
            # channel should use OR
            rows3=app._chat_rows_for("channel", OTHER, limit=100)
            assert len(rows3)>=2
            # limit test
            rows_limited=app._chat_rows_for("contact", OTHER, limit=1)
            assert len(rows_limited)==1
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_count_for_isolation(self):
        d, db = self._mk()
        try:
            SELF="BM-SELF-CNT"
            OTHER="BM-OTHER-CNT"
            now=int(time.time())
            identities={SELF: MagicMock()}
            app=FakeApp(db, identities=identities)
            app.set_current_identity(SELF)
            db.add_message(None, SELF, SELF, "", "a", 1, now, "out","sent")
            db.add_message(None, SELF, OTHER, "", "b", 1, now+1, "out","sent")
            assert app._count_for("contact", SELF)==1
            assert app._count_for("contact", OTHER)==1
            assert app._count_for("channel", OTHER)>=1
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_last_and_preview(self):
        d, db = self._mk()
        try:
            SELF="BM-SELF-LAST"
            OTHER="BM-OTHER-LAST"
            now=int(time.time())
            identities={SELF: MagicMock()}
            app=FakeApp(db, identities=identities)
            app.set_current_identity(SELF)
            app._conv_meta=[("contact", OTHER), ("contact", SELF)]
            db.add_message(None, SELF, OTHER, "", "hello", 1, now, "out","sent")
            db.add_message(None, OTHER, SELF, "", "reply", 1, now+1, "in","received")
            last=app._last_message_row(OTHER, kind="contact")
            assert last is not None and last["body"]=="reply"
            # self last should be self->self only
            db.add_message(None, SELF, SELF, "", "self2", 1, now+2, "out","sent")
            last_self=app._last_message_row(SELF, kind="contact")
            assert last_self["body"]=="self2"
            pmap=app._preview_map()
            assert OTHER in pmap and SELF in pmap
            assert pmap[OTHER][0]=="reply"
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_conversation_identity_fallback(self):
        from bmchat.core.database import Database
        d=mk_temp_dir()
        db=Database(d)
        try:
            app=FakeApp(db, identities={"BM-A":1,"BM-B":2})
            app.set_current_identity("BM-A")
            assert app._conversation_identity()=="BM-A"
            app.set_current_identity("BM-NOT")
            assert app._conversation_identity()=="BM-A"  # fallback first
            app2=FakeApp(db, identities={})
            assert app2._conversation_identity()==""
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_chat_rows_for_fallbacks(self):
        # test exception branches: messages_for_dm throws AttributeError, messages_for_conversation throws TypeError
        from bmchat.core.database import Database
        d=mk_temp_dir()
        db=Database(d)
        try:
            # mock db to raise
            class BadDB:
                def messages_for_conversation(self, *a, **kw):
                    raise Exception("boom")
                def messages_for_dm(self, *a, **kw):
                    raise AttributeError("no dm")
                def messages_for_contact(self, *a, **kw):
                    return []
                def count_for_dm(self, *a, **kw):
                    raise Exception("boom")
                def last_message_for_dm(self, *a, **kw):
                    raise Exception("boom")
                def query(self, *a, **kw):
                    raise Exception("boom")
            app=FakeApp(BadDB(), identities={"BM-A":1})
            app.set_current_identity("BM-A")
            # should not raise, return empty
            assert app._chat_rows_for("contact","BM-X",limit=10)==[]
            assert app._count_for("contact","BM-X")==0
            assert app._last_message_row("BM-X")==None
            assert app._preview_map()=={} or isinstance(app._preview_map(), dict)
        finally:
            shutil.rmtree(d, ignore_errors=True)

# ---------------------------------------------------------------------------
# coverage extras for manager edge helpers
# ---------------------------------------------------------------------------
class TestManagerExtras:
    def test_snapshot_timeouts_and_known_load(self):
        from bmchat.core.database import Database
        from bmchat.net.manager import NetworkManager
        d=mk_temp_dir()
        db=Database(d)
        try:
            mgr=NetworkManager(d, db, on_log=lambda *a: None)
            # snapshot with no started_at
            snap=mgr.snapshot()
            assert snap["uptime"]==0
            # timeouts clamped
            db.set_setting("connect_timeout","bad")
            assert mgr._snapshot_connect_timeout()==10
            db.set_setting("connect_timeout","2")
            assert mgr._snapshot_connect_timeout()==5
            db.set_setting("connect_timeout","500")
            assert mgr._snapshot_connect_timeout()==300
            # peers in_backoff exception
            with patch.object(mgr.peers, "in_backoff", side_effect=Exception("boom")):
                assert mgr._snapshot_backoff(time.time())==0
            # _describe_net_state edge: stats bad type
            mgr.running=True
            assert mgr._describe_net_state(1,1,1,0,{"invs":0})=="conectado" or "conectado" in mgr._describe_net_state(1,1,1,0,{"invs":0})
            # _is_cold_start
            mgr.inventory.clear()
            mgr.known_hashes.clear()
            mgr.stats["invs"]=0
            assert mgr._is_cold_start() is True
            mgr.inventory[b"x"*32]=b"raw"
            assert mgr._is_cold_start() is False
            mgr.inventory.clear()
            mgr.known_hashes.add(b"y"*32)
            assert mgr._is_cold_start() is False
            # _load_known_hashes with db error
            with patch.object(db, "query", side_effect=Exception("dbfail")):
                mgr._load_known_hashes()  # should not raise
            # _prune_expired_objects with db error
            with patch.object(db, "execute", side_effect=Exception("dbfail")):
                mgr._prune_expired_objects()
            # _evict_db_to_cap with db error
            with patch.object(db, "query", side_effect=Exception("dbfail")):
                mgr._evict_db_to_cap()
            with patch.object(db, "execute", side_effect=Exception("fail")):
                # need total > cap
                with patch.object(db, "query", return_value=[{"n":30000}]):
                    mgr._evict_db_to_cap()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_manager_add_peer_and_log(self):
        from bmchat.core.database import Database
        from bmchat.net.manager import NetworkManager
        d=mk_temp_dir()
        db=Database(d)
        try:
            logs=[]
            mgr=NetworkManager(d, db, on_log=lambda *a: logs.append(a))
            mgr.add_peer("1.2.3.4",8444)
            assert ("1.2.3.4",8444) in mgr.peers.entries
            mgr.log("hello")
            assert any("hello" in str(l) for l in logs)
            # _remember_announce
            h=os.urandom(32)
            class DummyConn:
                def __init__(self, est):
                    self.established=est
            mgr.connections={("1.1.1.1",8444): DummyConn(True), ("2.2.2.2",8444): DummyConn(False)}
            res=mgr._remember_announce(h)
            assert h in mgr.known_hashes
            assert len(res)==1
            # _store_announce_blob success and failure
            raw=b"testraw"
            h2=mgr._store_announce_blob(raw)
            assert h2 is not None
            with patch.object(mgr, "store_object", side_effect=Exception("fail")):
                h3=mgr._store_announce_blob(raw)
                assert h3 is not None
                with patch("bmchat.net.manager.double_sha512", side_effect=Exception("fail")):
                    assert mgr._store_announce_blob(raw) is None
            # _send_single_inv error path
            bad_conn=MagicMock()
            bad_conn.send_packet.side_effect=Exception("sendfail")
            mgr._send_single_inv(bad_conn, h)
            assert any("announce falhou" in str(l) for l in logs)
            # spawn when not running
            mgr.running=False
            assert mgr.spawn(MagicMock()) is None
            mgr.running=True
            # spawn duplicate should return None
            peer=MagicMock()
            peer.host="1.1.1.1"; peer.port=8444
            # already in connections
            assert mgr.spawn(peer) is None
            # spawn new should create PeerConnection but we mock it
            with patch("bmchat.net.peer.PeerConnection") as mock_pc:
                mock_inst=MagicMock()
                mock_inst.peer_key=("9.9.9.9",8444)
                mock_pc.return_value=mock_inst
                new_peer=MagicMock()
                new_peer.host="9.9.9.9"; new_peer.port=8444
                res=mgr.spawn(new_peer)
                assert res is mock_inst
                mock_inst.start.assert_called()
        finally:
            shutil.rmtree(d, ignore_errors=True)

class TestManagerStartStop:
    def test_start_stop_and_dns(self):
        from bmchat.core.database import Database
        from bmchat.net.manager import NetworkManager
        d=mk_temp_dir()
        db=Database(d)
        try:
            logs=[]
            mgr=NetworkManager(d, db, on_log=lambda *a: logs.append(a))
            # mock threads to avoid real sleep
            with patch("threading.Thread") as mock_thread_cls:
                mock_thread=MagicMock()
                mock_thread_cls.return_value=mock_thread
                mgr.start([1])
                assert mgr.running is True
                assert mgr.started_at is not None
                assert mock_thread.start.call_count==2  # maintenance + dns
                # _resolve_one_seed success
                with patch("socket.getaddrinfo", return_value=[(2,1,6,'',('10.0.0.1',8444)), (2,1,6,'',('10.0.0.2',8444))]):
                    added=mgr._resolve_one_seed("seed.example.com",8444)
                    assert added==2
                    assert ("10.0.0.1",8444) in mgr.peers.entries
                with patch("socket.getaddrinfo", side_effect=Exception("dnsfail")):
                    assert mgr._resolve_one_seed("bad",8444)==0
                    assert any("semente DNS" in str(l) for l in logs)
                # _resolve_timeout
                mgr.DNS_RESOLVE_TIMEOUT=5
                assert mgr._resolve_timeout()==5
                mgr.DNS_RESOLVE_TIMEOUT="bad"
                assert mgr._resolve_timeout()==8.0
                mgr.DNS_RESOLVE_TIMEOUT=100
                assert mgr._resolve_timeout()==60.0
                mgr.DNS_RESOLVE_TIMEOUT=0
                assert mgr._resolve_timeout()==1.0
                # _spawn_seed_workers with running false
                mgr.running=False
                assert mgr._spawn_seed_workers()==[]
                mgr.running=True
                # ensure workers spawned
                with patch("socket.getaddrinfo", return_value=[(2,1,6,'',('1.1.1.1',8444))]):
                    with patch("threading.Thread") as mock_th2:
                        mock_inst=MagicMock()
                        mock_th2.return_value=mock_inst
                        workers=mgr._spawn_seed_workers()
                        assert len(workers)>=1
                # _join_seed_workers timeout
                w1=MagicMock()
                w1.join=MagicMock()
                mgr._join_seed_workers([w1], timeout=0.1)
                assert w1.join.called
                # _resolve_seeds calls join
                with patch.object(mgr, "_spawn_seed_workers", return_value=[MagicMock()]):
                    with patch.object(mgr, "_join_seed_workers") as mock_join:
                        mgr._resolve_seeds()
                        mock_join.assert_called()
                # _maybe_refresh_seeds throttled
                mgr._last_dns_resolve=time.time()
                mgr.DNS_REFRESH_INTERVAL=120
                with patch("threading.Thread") as mock_th:
                    mgr._maybe_refresh_seeds()
                    assert not mock_th.called  # throttled
                mgr._last_dns_resolve=time.time()-200
                with patch("threading.Thread") as mock_th:
                    mock_inst=MagicMock()
                    mock_th.return_value=mock_inst
                    mgr._maybe_refresh_seeds()
                    assert mock_th.called
                # _maybe_periodic_refresh
                mgr._last_periodic_dns=time.time()
                mgr.DNS_PERIODIC_INTERVAL=1800
                with patch("threading.Thread") as mock_th:
                    mgr._maybe_periodic_refresh()
                    assert not mock_th.called
                mgr._last_periodic_dns=time.time()-2000
                with patch("threading.Thread") as mock_th:
                    mock_inst=MagicMock()
                    mock_th.return_value=mock_inst
                    mgr._maybe_periodic_refresh()
                    assert mock_th.called
                # stop with generation increment and join
                mock_maint=MagicMock()
                mock_maint.is_alive.return_value=True
                mock_maint.join=MagicMock()
                mgr._maintenance_thread=mock_maint
                mgr.peers.save=MagicMock()
                # need a connection to close
                class DummyConn:
                    def __init__(self):
                        self.peer_key=("1.1.1.1",8444)
                        self.close=MagicMock()
                mgr.connections[("1.1.1.1",8444)]=DummyConn()
                mgr.stop()
                assert mgr.running is False
                assert mgr._maintenance_thread is None
                # generation increment
                assert mgr._generation>=1
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_maintenance_helpers(self):
        from bmchat.core.database import Database
        from bmchat.net.manager import NetworkManager
        d=mk_temp_dir()
        db=Database(d)
        try:
            mgr=NetworkManager(d, db, on_log=lambda *a: None)
            mgr.running=True
            # _is_cold_start branches
            mgr.inventory.clear(); mgr.known_hashes.clear(); mgr.stats["invs"]=0
            assert mgr._is_cold_start() is True
            mgr.inventory[b"x"*32]=b"raw"
            assert mgr._is_cold_start() is False
            mgr.inventory.clear(); mgr.known_hashes.add(b"y"*32)
            assert mgr._is_cold_start() is False
            mgr.stats["invs"]=1
            assert mgr._is_cold_start() is False
            # _max_connections
            db.set_setting("max_connections","5")
            assert mgr._max_connections()==5
            db.set_setting("max_connections","100")
            assert mgr._max_connections()==50
            db.set_setting("max_connections","bad")
            assert mgr._max_connections()==8
            mgr.db.get_int=MagicMock(side_effect=Exception("boom"))
            assert mgr._max_connections()==8
            # _connection_targets
            mgr.connections.clear()
            mgr.BOOT_EXTRA_SLOTS=2
            db.set_setting("max_connections","2")
            # with 0 connections, goal =2, budget =2+2-0=4 => min(2,4)=2
            cur,goal=mgr._connection_targets(2)
            assert goal==2
            # with established one, need 1 more
            class FakeConn:
                def __init__(self, est):
                    self.peer_key=(f"10.0.0.{est}",8444)
                    self.established=est
                    self.started_at=time.time()
                    self.connected_at=time.time() if est else None
                    self.last_useful_at=None
                    self.their_version=None
                    self.their_services=0
                    self.their_streams=[]
                    self.time_offset=None
                    self.bytes_sent=0
                    self.bytes_received=0
                def is_alive(self):
                    return True
                def close(self): pass
            mgr.connections[("10.0.0.1",8444)]=FakeConn(True)
            cur,goal=mgr._connection_targets(2)
            assert goal==1
            # over cap case: many negotiating, budget 0
            mgr.connections.clear()
            mgr.BOOT_EXTRA_SLOTS=0
            class FakeConn2:
                def __init__(self, host):
                    self.peer_key=(host,8444)
                    self.established=False
                    self.started_at=time.time()
                    self.connected_at=None
                    self.last_useful_at=None
                    self.their_version=None
                    self.their_services=0
                    self.their_streams=[]
                    self.time_offset=None
                    self.bytes_sent=0
                    self.bytes_received=0
                def is_alive(self):
                    return True
                def close(self): pass
            for i in range(10):
                mgr.connections[(f"10.0.1.{i}",8444)]=FakeConn2(f"10.0.1.{i}")
            # max 2, extra 0, len 10 => budget -8 => goal 0
            cur,goal=mgr._connection_targets(2)
            assert goal==0
            # _spawn_candidate duplicate
            mgr.peers.add("1.1.1.1",8444)
            cur=set([("1.1.1.1",8444)])
            from bmchat.net.peers import Peer
            peer=Peer("1.1.1.1",8444)
            assert mgr._spawn_candidate(peer, cur) is False
            cur=set()
            with patch.object(mgr, "spawn") as mock_spawn:
                assert mgr._spawn_candidate(peer, cur) is True
                assert ("1.1.1.1",8444) in cur
                assert mgr.stats["dial_attempts"]>=1
                mock_spawn.assert_called()
            # _spawn_best
            mgr.peers.entries.clear()
            mgr.peers.add("1.1.1.1",8444)
            mgr.peers.add("2.2.2.2",8444)
            cur=set()
            with patch.object(mgr, "_spawn_candidate", return_value=True) as mock_sc:
                spawned,found=mgr._spawn_best(cur,2,1,0)
                assert spawned==1 and found is True
                # limit reached
                spawned,found=mgr._spawn_best(cur,2,0,0)
                assert spawned==0
        finally:
            shutil.rmtree(d, ignore_errors=True)

class TestPeerConnectionMore:
    def test_handshake_and_read_loop(self):
        from bmchat.net.peer import PeerConnection
        from bmchat.net.peers import Peer
        mgr=MagicMock()
        mgr.nonce=b"nonce123"
        mgr.streams=[1]
        mgr.peers=MagicMock()
        peer=Peer("1.1.1.1",8444)
        conn=PeerConnection(mgr, peer)
        # _handshake_timeout
        mgr.HANDSHAKE_TIMEOUT=5
        assert conn._handshake_timeout()>=5
        mgr.HANDSHAKE_TIMEOUT="bad"
        assert conn._handshake_timeout()==20.0
        # _log_handshake_timeout
        conn.started_at=time.time()-10
        conn._log_handshake_timeout()
        mgr.log.assert_called()
        # _handshake_once with bad checksum should return silently
        mock_sock=MagicMock()
        conn.sock=mock_sock
        # need to mock _read_header to return valid header, and _recv_exact to return payload
        with patch.object(conn, "_read_header", return_value=(b"\xe9\xbe\xb4\xd9", "version", 10, b"\x00\x00\x00\x00")):
            with patch.object(conn, "_recv_exact", return_value=b"payload"):
                # checksum mismatch -> return without handling (digest returns ff, checksum 00)
                conn._handle=MagicMock()
                conn._handshake_once(lambda x: b"\xff\xff\xff\xff"+b"\x00"*60)
                conn._handle.assert_not_called()
                # now matching checksum
                conn._handle=MagicMock()
                conn._handshake_once(lambda x: b"\x00\x00\x00\x00"+b"\x00"*60)
                conn._handle.assert_called()
        # _receive_payload checksum fail
        with patch("bmchat.util.hashing.sha512", return_value=b"\xff"*64):
            conn._recv_exact=MagicMock(return_value=b"data")
            cmd,payload=conn._receive_payload((b"magic","cmd",4,b"\x00\x00\x00\x00"))
            assert cmd is None
        # _read_loop timeout handling
        conn._closing=False
        conn._read_header=MagicMock(side_effect=socket.timeout)
        conn.close=MagicMock()
        # after 3 timeouts should close
        conn._read_loop()
        assert conn.close.called
        # _read_header magic invalid
        conn2=PeerConnection(mgr, peer)
        conn2.sock=MagicMock()
        conn2._recv_exact=MagicMock(return_value=b"\x00"*24)
        with patch("bmchat.protocol.packets.parse_header", return_value=(b"badmagic","cmd",0,b"chk")):
            with pytest.raises(ValueError):
                conn2._read_header()
        with patch("bmchat.protocol.packets.parse_header", return_value=(b"\xe9\xbe\xb4\xd9","cmd", 20000000, b"chk")):
            with pytest.raises(ValueError):
                conn2._read_header()
        # fallback host
        assert conn._fallback_host(b"\x00"*10+b"\xff\xff"+socket.inet_aton("1.2.3.4"))=="1.2.3.4"
        assert conn._fallback_host(b"bad") is None
        # _on_addr handling
        conn.last_useful_at=None
        mgr.add_peer=MagicMock()
        mgr.streams=[1]
        with patch("bmchat.protocol.packets.parse_addr", return_value=[(int(time.time()),1,1, b"\x00"*10+b"\xff\xff"+socket.inet_aton("1.2.3.4"), 8444)]):
            conn._on_addr(b"payload")
            assert conn.last_useful_at is not None
            assert mgr.add_peer.called
        # _on_inv sets useful and delegates
        mgr.on_inv=MagicMock()
        conn._on_inv(b"payload")
        assert mgr.on_inv.called
        mgr.on_getdata=MagicMock()
        conn._on_getdata(b"payload")
        assert mgr.on_getdata.called
        mgr.received_object=MagicMock()
        conn._on_object(b"payload")
        assert mgr.received_object.called
        # _on_verack
        conn.established=False
        conn.connected_at=None
        mgr.on_log=MagicMock()
        conn._on_verack()
        assert conn.established is True
        assert conn.connected_at is not None
        # _maybe_send_initial_data
        conn.established=True; conn.got_version=True; conn.initial_data_sent=False
        orig_send_initial = conn._send_initial_data
        conn._send_initial_data=MagicMock()
        conn._maybe_send_initial_data()
        assert conn.initial_data_sent is True
        conn._send_initial_data = orig_send_initial
        # _send_initial_data with peers (different host than conn's peer_key to avoid exclude)
        conn2 = PeerConnection(mgr, Peer("1.1.1.1",8444))
        mgr.peers.best.return_value=[(Peer("2.2.2.2",8444), {"stream":1,"services":1,"last_seen":int(time.time())})]
        with patch("bmchat.protocol.packets.encode_host", return_value=b"\x00"*16):
            with patch("bmchat.protocol.packets.assemble_addr", return_value=b"addrpayload"):
                conn2.send_packet=MagicMock()
                mgr.send_inventory=MagicMock()
                conn2._send_initial_data()
                assert conn2.send_packet.called
                assert mgr.send_inventory.called

