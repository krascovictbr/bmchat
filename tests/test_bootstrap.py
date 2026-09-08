"""Bootstrap fresco e discagem rápida: backoff exponencial + poda de mortos,
dial paralelo com timeout curto, DNS paralelo e refresh contínuo.

Cenário do dono: entrar na rede demora porque o cliente testa IP por IP
uma lista cheia de mortos/proxies/rotativos. Exigência: lista SEMPRE
fresca via bootstrap + testar rápido e desistir rápido do que não presta.
"""
import shutil
import socket
import tempfile
import threading
import time

from bmchat.core.database import Database
from bmchat.net.manager import NetworkManager
from bmchat.net.peers import (
    PeerStore,
    BACKOFF_BASE_SECONDS,
    BACKOFF_CAP_SECONDS,
    MAX_CONSECUTIVE_FAILURES,
)


class FakeConn:
    """Conexão fake mínima para _ensure/_prune."""

    def __init__(self, host, port, established=False):
        from bmchat.net.peers import Peer
        self.peer = Peer(host, port)
        self.peer_key = (host, port)
        self.established = established
        now = time.time()
        self.started_at = now
        self.connected_at = now if established else None
        self.last_useful_at = None
        self.their_version = None
        self.their_services = 0
        self.their_streams = []
        self.time_offset = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self.closed = False

    def is_alive(self):
        return not self.closed

    def close(self):
        self.closed = True


def _make_manager():
    directory = tempfile.mkdtemp(prefix='bmchat-boot-')
    db = Database(directory)
    logs = []
    mgr = NetworkManager(
        directory, db, on_log=lambda *a: logs.append(a))
    mgr.running = True
    mgr.peers.entries.clear()
    return directory, db, mgr, logs


def _close(directory, db):
    try:
        db.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_backoff_cresce_exponencial_com_teto():
    store = PeerStore()
    assert BACKOFF_BASE_SECONDS == 60
    assert BACKOFF_CAP_SECONDS == 3600
    assert MAX_CONSECUTIVE_FAILURES == 5
    expected = {0: 60.0, 1: 120.0, 2: 240.0, 3: 480.0, 4: 960.0}
    for fails, floor in expected.items():
        window = store.backoff_for({'fail_count': fails}, 60)
        assert floor <= window <= floor + 60, (fails, window)
    # Teto ~1h: 60×2^6 estouraria, fica em 3600+jitter(≤60).
    window = store.backoff_for({'fail_count': 9}, 60)
    assert 3600.0 <= window <= 3660.0, window
    # base<=0 desliga (escape hatch, ex.: best(cooldown=0)).
    assert store.backoff_for({'fail_count': 4}, 0) == 0.0
    # Entrada legada sem fail_count comporta-se como 0 falhas.
    window = store.backoff_for({}, 60)
    assert 60.0 <= window <= 75.0, window


def test_poda_apos_cinco_falhas():
    store = PeerStore()
    store.add('10.30.0.1', 8444)
    for _ in range(MAX_CONSECUTIVE_FAILURES - 1):
        pruned = store.record_failure('10.30.0.1', 8444)
        assert pruned is False
        assert ('10.30.0.1', 8444) in store.entries
    assert store.entries[('10.30.0.1', 8444)]['fail_count'] == 4
    assert store.record_failure('10.30.0.1', 8444) is True
    assert ('10.30.0.1', 8444) not in store.entries


def test_sucesso_zera_sequencia():
    store = PeerStore()
    store.add('10.30.0.2', 8444)
    for _ in range(3):
        store.record_failure('10.30.0.2', 8444)
    assert store.entries[('10.30.0.2', 8444)]['fail_count'] == 3
    store.record_success('10.30.0.2', 8444)
    entry = store.entries[('10.30.0.2', 8444)]
    assert entry['fail_count'] == 0
    assert entry['rating'] == -2  # -3 + 1, sem bonus indevido


def test_nunca_retesta_dentro_da_janela():
    store = PeerStore()
    now = int(time.time())
    store.entries[('10.30.0.3', 8444)] = {
        'stream': 1, 'services': 1, 'last_seen': now, 'rating': -2,
        'last_try': now, 'inv_count': 0, 'last_inv': 0, 'mute_count': 0,
        'fail_count': 2}
    keys = [(p.host, p.port) for p, _i in store.best()]
    assert ('10.30.0.3', 8444) not in keys  # janela 240s+jitter
    assert store.in_backoff() == 1
    # Fora da janela volta ao giro (não é ban).
    store.entries[('10.30.0.3', 8444)]['last_try'] = now - 10000
    keys = [(p.host, p.port) for p, _i in store.best()]
    assert ('10.30.0.3', 8444) in keys
    assert store.in_backoff() == 0


def test_produtivo_primeiro_com_penalidade_de_falha():
    store = PeerStore()
    now = int(time.time())
    fresh = ('10.30.1.2', 8444)
    talker = ('10.30.1.3', 8444)
    flaky = ('10.30.1.4', 8444)
    store.entries[fresh] = {
        'stream': 1, 'services': 1, 'last_seen': now, 'rating': 0,
        'last_try': 0, 'inv_count': 0, 'last_inv': 0, 'mute_count': 0,
        'fail_count': 0}
    store.entries[talker] = {
        'stream': 1, 'services': 1, 'last_seen': now, 'rating': 0,
        'last_try': 0, 'inv_count': 4, 'last_inv': now, 'mute_count': 0,
        'fail_count': 0}
    store.entries[flaky] = {
        'stream': 1, 'services': 1, 'last_seen': now, 'rating': 0,
        'last_try': 0, 'inv_count': 4, 'last_inv': now, 'mute_count': 0,
        'fail_count': 3}
    ordered = [(p.host, p.port) for p, _i in store.best(cooldown=0)]
    assert ordered[0] == talker  # falante saudável primeiro
    assert ordered.index(fresh) < ordered.index(flaky)  # falha afunda


def test_persiste_contadores_no_knownnodes():
    directory = tempfile.mkdtemp(prefix='bmchat-bootstore-')
    try:
        path = directory + '/knownnodes.dat'
        store = PeerStore(path)
        store.add('10.30.0.5', 8444)
        store.record_failure('10.30.0.5', 8444)
        store.record_failure('10.30.0.5', 8444)
        store.save()
        reloaded = PeerStore(path)
        reloaded.load()
        entry = reloaded.entries[('10.30.0.5', 8444)]
        assert entry['fail_count'] == 2
        assert entry['rating'] == -2
        assert entry['last_try'] > 0
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _dial_worker(mgr, key, delay, live):
    time.sleep(delay)
    with mgr.lock:
        conn = mgr.connections.get(key)
    if conn is None:
        return
    if live:
        conn.established = True
        conn.connected_at = time.time()
        try:
            mgr.peers.record_success(*key)
        except Exception:
            pass
    else:
        try:
            mgr.peers.record_failure(*key)
        except Exception:
            pass
        with mgr.lock:
            if mgr.connections.get(key) is conn:
                mgr.connections.pop(key, None)


def test_dial_paralelo_encontra_vivo_em_tempo_limitado():
    """12 mortos (0.3s p/ falhar) + 1 vivo por último (0.1s).

    Serial levaria ≥12×0.3=3.6s só nos mortos; em paralelo o vivo
    aparece em tempo limitado mesmo sendo o último da lista.
    """
    directory, db, mgr, _logs = _make_manager()
    try:
        dead = [('10.31.0.%d' % i, 8444) for i in range(1, 13)]
        live = ('10.31.0.99', 8444)
        for key in dead + [live]:
            mgr.peers.add(*key)

        def fake_spawn(peer):
            key = (peer.host, peer.port)
            with mgr.lock:
                if key in mgr.connections:
                    return None
                conn = FakeConn(peer.host, peer.port)
                mgr.connections[key] = conn
            threading.Thread(
                target=_dial_worker,
                args=(mgr, key, 0.1 if key == live else 0.3,
                      key == live),
                daemon=True).start()
            return conn

        mgr.spawn = fake_spawn
        start = time.time()
        found_at = None
        while time.time() - start < 5.0:
            mgr._ensure_connections()
            mgr._prune_connections()
            with mgr.lock:
                conn = mgr.connections.get(live)
                live_up = conn is not None and conn.established
            if live_up:
                found_at = time.time() - start
                break
            time.sleep(0.02)
        assert found_at is not None, 'vivo nunca foi estabelecido'
        assert found_at < 3.0, 'sem paralelismo levaria >3.6s: %.2fs' \
            % found_at
        assert int(mgr.stats.get('dial_attempts', 0)) >= 1
    finally:
        _close(directory, db)


def test_timeout_de_connect_respeitado(monkeypatch):
    """Default 10s (era 30s); configuração do usuário continua valendo."""
    from bmchat.net import proxy as proxy_mod
    from bmchat.net.peer import PeerConnection
    from bmchat.net.peers import Peer
    directory, db, mgr, _logs = _make_manager()
    try:
        seen = {}

        class DummySock:
            def setsockopt(self, *a):
                pass

            def settimeout(self, timeout):
                seen['recv'] = timeout

        def fake_connect(host, port, proxy=None, timeout=30):
            seen['timeout'] = timeout
            return DummySock()

        monkeypatch.setattr(proxy_mod, 'connect_socket', fake_connect)
        conn = PeerConnection(mgr, Peer('10.99.0.1', 8444))
        conn._connect()
        assert seen['timeout'] == 10, seen
        db.set_setting('connect_timeout', '25')
        conn._connect()
        assert seen['timeout'] == 25, seen
    finally:
        _close(directory, db)


def test_refresh_dns_mescla_sem_duplicar(monkeypatch):
    """DNS paralelo: lenta não trava; merge dedupa IP:porta."""
    import bmchat.net.manager as manager_mod
    directory, db, mgr, logs = _make_manager()
    try:
        mgr.DNS_RESOLVE_TIMEOUT = 1.0  # floor: timeout nunca < 1s

        def fake_getaddrinfo(host, port, *args):
            if '8080' in host:
                time.sleep(2.0)  # semente lenta
                return [(2, 1, 6, '', ('10.40.0.1', port)),
                        (2, 1, 6, '', ('10.40.0.1', port)),  # dup no DNS
                        (2, 1, 6, '', ('10.40.0.2', port))]
            return [(2, 1, 6, '', ('10.40.0.2', port)),
                    (2, 1, 6, '', ('10.40.0.3', port))]

        monkeypatch.setattr(socket, 'getaddrinfo', fake_getaddrinfo)
        assert manager_mod.DNS_SEEDS, 'sem sementes configuradas'
        start = time.time()
        mgr._resolve_seeds()
        elapsed = time.time() - start
        assert elapsed < 1.8, 'semente lenta travou as outras: %.2fs' \
            % elapsed
        # Rápida já mesclou (porta do seed, como getaddrinfo real).
        assert ('10.40.0.2', 8444) in mgr.peers.entries
        assert ('10.40.0.3', 8444) in mgr.peers.entries
        time.sleep(1.5)  # lenta termina e mescla sozinha
        slow_keys = sorted(k for k in mgr.peers.entries if k[1] == 8080)
        assert slow_keys == [('10.40.0.1', 8080), ('10.40.0.2', 8080)]
    finally:
        _close(directory, db)


def test_refresh_periodico_independente():
    directory, db, mgr, logs = _make_manager()
    try:
        resolved = []
        mgr._resolve_seeds = lambda: resolved.append(True)
        mgr.DNS_PERIODIC_INTERVAL = 1800
        mgr._last_periodic_dns = time.time() - 2000
        mgr._maybe_periodic_refresh()
        time.sleep(0.3)
        assert resolved, 'refresh periódico não disparou'
        assert any('periódica' in str(m) for m in logs)
        resolved.clear()
        mgr._maybe_periodic_refresh()
        time.sleep(0.1)
        assert not resolved, 'disparou sem respeitar o intervalo'
    finally:
        _close(directory, db)


def test_status_procurando_mostra_tentativas_conhecidos_ignorados():
    from bmchat.gui.app import _status_state_part
    snap = {'running': True, 'connection_count': 0, 'peers_stored': 715,
            'peers_backoff': 700, 'inventory': 0,
            'stats': {'invs': 0, 'dial_attempts': 37},
            'resync': {'active': False}}
    text = _status_state_part(snap, 0)
    assert 'procurando pares: 37 tentativa(s), 715 conhecido(s), ' \
        '700 ignorado(s) por falha recente' in text, text
