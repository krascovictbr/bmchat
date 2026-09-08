import os
import queue
import shutil
import subprocess
import sys
import tempfile

import pytest

from bmchat import update as updater


def _git(repo, *args):
    subprocess.run(
        ['git', '-C', repo] + list(args), check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)


def _commit(repo, message):
    _git(repo, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit',
         '--allow-empty', '-qm', message)


@pytest.fixture
def cloned():
    base = tempfile.mkdtemp(prefix='bmchat-upd-')
    origin = os.path.join(base, 'origin')
    os.makedirs(origin)
    _git(origin, 'init', '-q')
    _commit(origin, 'v1')
    clone = os.path.join(base, 'clone')
    subprocess.run(
        ['git', 'clone', '-q', 'file://' + origin, clone], check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    yield origin, clone
    shutil.rmtree(base, ignore_errors=True)


def test_no_repo(tmp_path):
    assert updater.check_for_updates(str(tmp_path))['status'] == 'no-repo'
    ok, _ = updater.perform_update(str(tmp_path))
    assert ok is False


def test_update_flow(cloned):
    origin, clone = cloned
    assert updater.check_for_updates(clone)['status'] == 'up-to-date'
    _commit(origin, 'v2')
    result = updater.check_for_updates(clone)
    assert result['status'] == 'update-available'
    assert result['behind'] == 1
    ok, message = updater.perform_update(clone)
    assert ok, message
    assert updater.check_for_updates(clone)['status'] == 'up-to-date'
    log = subprocess.run(
        ['git', '-C', clone, 'log', '--oneline'], capture_output=True,
        timeout=60)
    assert 'v2' in log.stdout.decode('utf-8', 'replace')


def test_dirty_tree_blocks(cloned):
    origin, clone = cloned
    _commit(origin, 'v2')
    with open(os.path.join(clone, 'local.txt'), 'w') as handle:
        handle.write('trabalho local')
    ok, message = updater.perform_update(clone)
    assert ok is False
    assert 'locais' in message
    assert updater.check_for_updates(clone)['status'] == 'update-available'


def test_preview_commits_and_shorts(cloned):
    origin, clone = cloned
    _commit(origin, 'v2-nova-func')
    result = updater.check_for_updates(clone)
    assert result['status'] == 'update-available'
    assert result['local_short'] != result['remote_short']
    assert len(result['local_short']) == 7
    assert any('v2-nova-func' in line for line in result['commits'])
    preview = updater.get_update_preview(clone)
    assert preview['behind'] == 1
    assert preview['local'] == result['local']
    assert preview['remote'] == result['remote']
    assert any('v2-nova-func' in line for line in preview['commits'])


def test_preview_no_network_after_check(cloned):
    """Prévia é só leitura: funciona mesmo com o remoto fora do ar."""
    origin, clone = cloned
    _commit(origin, 'v2')
    assert updater.check_for_updates(clone)['status'] == 'update-available'
    _git(clone, 'remote', 'set-url', 'origin', 'file:///nonexistente-bmchat-xyz')
    preview = updater.get_update_preview(clone)
    assert preview['behind'] == 1
    assert any('v2' in line for line in preview['commits'])


def test_ahead(cloned):
    origin, clone = cloned
    _commit(clone, 'local-solo')
    result = updater.check_for_updates(clone)
    assert result['status'] == 'ahead'
    assert result['ahead'] == 1
    assert 'nada a atualizar' in updater.describe_update_result(result)


def test_diverged(cloned):
    origin, clone = cloned
    _commit(origin, 'v2-origin')
    _commit(clone, 'v2-local')
    result = updater.check_for_updates(clone)
    assert result['status'] == 'diverged'
    assert result['behind'] == 1
    assert result['ahead'] == 1
    ok, message = updater.perform_update(clone)
    assert ok is False
    assert 'fast-forward' in message


def test_fetch_failed(cloned):
    origin, clone = cloned
    _git(clone, 'remote', 'set-url', 'origin', 'file:///nonexistente-bmchat-xyz')
    result = updater.check_for_updates(clone, fetch_timeout=10)
    assert result['status'] == 'fetch-failed'
    assert 'tente de novo' in updater.describe_update_result(result)
    ok, message = updater.perform_update(clone)
    assert ok is False
    assert 'tente de novo' in message


def test_no_upstream(cloned):
    origin, clone = cloned
    _git(clone, 'checkout', '-qb', 'sem-upstream')
    result = updater.check_for_updates(clone)
    assert result['status'] == 'no-upstream'
    text = updater.describe_update_result(result)
    assert 'mão' not in text
    assert 'git pull' not in text.lower()


def test_ensure_upstream_idempotent_when_present(cloned):
    origin, clone = cloned
    before = updater._upstream(clone)
    assert before is not None
    first = updater.ensure_upstream(clone)
    assert first == {'fixed': False, 'upstream': before}
    second = updater.ensure_upstream(clone)
    assert second == first
    assert updater._upstream(clone) == before


def test_ensure_upstream_unresolvable_without_rolling_release(cloned):
    origin, clone = cloned
    _git(clone, 'checkout', '-qb', 'sem-upstream-sem-rr')
    assert updater._upstream(clone) is None
    fix = updater.ensure_upstream(clone)
    assert fix == {'fixed': False, 'upstream': None}
    result = updater.check_for_updates(clone)
    assert result['status'] == 'no-upstream'


def test_ensure_upstream_never_raises(tmp_path):
    fix = updater.ensure_upstream(str(tmp_path))
    assert fix == {'fixed': False, 'upstream': None}


def test_check_resolves_missing_upstream_via_rolling_release(cloned):
    origin, clone = cloned
    _git(origin, 'checkout', '-qb', 'rolling-release')
    _commit(origin, 'v2-rr')
    _git(clone, 'fetch', 'origin')
    _git(clone, 'checkout', '-qb', 'ramo-sem-upstream')
    assert updater._upstream(clone) is None
    result = updater.check_for_updates(clone)
    assert result['status'] == 'update-available'
    assert result.get('upstream_fixed') is True
    assert updater._upstream(clone) == 'origin/rolling-release'


def test_ensure_upstream_fixes_then_up_to_date(cloned):
    origin, clone = cloned
    _git(origin, 'branch', 'rolling-release')
    _git(clone, 'fetch', 'origin')
    _git(clone, 'checkout', '-qb', 'ramo-sem-upstream-2')
    assert updater._upstream(clone) is None
    fix = updater.ensure_upstream(clone)
    assert fix['fixed'] is True
    assert fix['upstream'] == 'origin/rolling-release'
    result = updater.check_for_updates(clone)
    assert result['status'] == 'up-to-date'
    assert result['status'] != 'no-upstream'


def test_describe_has_no_terminal_instructions():
    for status in ('up-to-date', 'no-repo', 'diverged', 'ahead',
                   'no-upstream', 'fetch-failed', 'unknown', 'error'):
        text = updater.describe_update_result(
            {'status': status, 'error': 'x', 'ahead': 1, 'behind': 1})
        assert 'git pull' not in text.lower()
        assert 'mão' not in text


def test_manual_no_upstream_dialog_without_terminal_terms(monkeypatch):
    pytest.importorskip('tkinter')
    from bmchat.gui import dialogs
    warns = []
    infos = []
    monkeypatch.setattr(dialogs, 'warn', lambda *args: warns.append(args))
    monkeypatch.setattr(dialogs, 'info', lambda *args: infos.append(args))
    app = _FakeApp()
    app._show_update_check({'status': 'no-upstream'})
    assert warns != []
    text = warns[-1][-1]
    assert 'mão' not in text
    assert 'git pull' not in text.lower()


def test_manual_upstream_fixed_flashes_status(monkeypatch):
    pytest.importorskip('tkinter')
    from bmchat.gui import dialogs
    monkeypatch.setattr(dialogs, 'info', lambda *args: None)
    monkeypatch.setattr(dialogs, 'warn', lambda *args: None)
    app = _FakeApp()
    app._show_update_check({'status': 'up-to-date', 'upstream_fixed': True})
    assert app.status_texts and 'Ramo ligado' in app.status_texts[-1]


def test_is_tree_clean(cloned):
    origin, clone = cloned
    assert updater.is_tree_clean(clone) is True
    with open(os.path.join(clone, 'rascunho.txt'), 'w') as handle:
        handle.write('x')
    assert updater.is_tree_clean(clone) is False


@pytest.mark.parametrize('status,keyword', [
    ('up-to-date', 'mais nova'),
    ('no-repo', 'sem git'),
    ('diverged', 'divergiu'),
    ('no-upstream', 'automáticas'),
    ('fetch-failed', 'tente de novo'),
    ('unknown', 'Tente de novo'),
    ('error', 'Tente de novo'),
])
def test_describe_update_result(status, keyword):
    text = updater.describe_update_result({'status': status, 'error': 'x'})
    assert keyword in text


def test_restart_preserves_argv_and_runs_pre_exec(tmp_path, monkeypatch):
    run_py = tmp_path / 'run.py'
    run_py.write_text('x = 1\n')
    calls = {}
    monkeypatch.setattr(sys, 'argv', ['run.py', '--data', '/tmp/x'])

    def fake_execv(exe, args):
        calls['exe'] = exe
        calls['args'] = list(args)
        raise RuntimeError('para-aqui')

    monkeypatch.setattr(os, 'execv', fake_execv)
    pre = []
    with pytest.raises(RuntimeError):
        updater.restart_program(str(tmp_path), pre_exec=lambda: pre.append(1))
    assert pre == [1]
    assert calls['exe'] == sys.executable
    assert calls['args'] == [sys.executable, str(run_py), '--data', '/tmp/x']


def test_restart_pre_exec_error_ignored(tmp_path, monkeypatch):
    (tmp_path / 'run.py').write_text('x = 1\n')
    calls = {}

    def fake_execv(exe, args):
        calls['args'] = list(args)

    def bad_pre():
        raise ValueError('stop falhou')

    monkeypatch.setattr(os, 'execv', fake_execv)
    updater.restart_program(str(tmp_path), pre_exec=bad_pre)
    assert calls['args'][0] == sys.executable


def test_restart_missing_runpy(tmp_path):
    with pytest.raises(FileNotFoundError):
        updater.restart_program(str(tmp_path))


def test_version_fallback_without_git(monkeypatch):
    import bmchat.version as ver
    monkeypatch.setattr(ver, '_git_output', lambda args, timeout=3: None)
    ver.get_version.cache_clear()
    try:
        assert ver.get_version() == '0.0.0+unknown'
        assert ver.user_agent_version() == '0.0.0.unknown'
    finally:
        ver.get_version.cache_clear()


class _FakeDB:
    def __init__(self):
        self.values = {}

    def get_setting(self, key, default=''):
        return self.values.get(key, default)

    def set_setting(self, key, value):
        self.values[key] = value if isinstance(value, str) else str(value)

    def get_int(self, key, default=0):
        try:
            return int(self.get_setting(key, default))
        except Exception:
            return default


class _FakeClient:
    def __init__(self):
        self.db = _FakeDB()
        self.ui_queue = queue.Queue()
        self.logs = []
        self.stopped = False

    def _log(self, level, message):
        self.logs.append((level, message))
        self.ui_queue.put(('log', level, str(message)))

    def stop(self):
        self.stopped = True


class _Var:
    def __init__(self, value=''):
        self._value = value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


class _Entry:
    def __init__(self):
        self.options = {}

    def config(self, **kwargs):
        self.options.update(kwargs)


class _StatusBar:
    def __init__(self, texts):
        self.texts = texts

    def config(self, **kwargs):
        if 'text' in kwargs:
            self.texts.append(kwargs['text'])


class _FakeApp:
    """Reutiliza os métodos reais de update do App sem precisar de Tk."""

    _METHODS = ('_auto_update_enabled', '_update_interval_h', '_cancel_periodic_update_check',
                '_schedule_periodic_update_check', '_periodic_update_fire', '_update_progress_from_worker',
                '_safe_auto_enabled', '_safe_tree_clean', '_queue_ui_event', '_log_auto_check_issue',
                '_notify_dirty_hold_once', '_handle_auto_check_result', '_auto_update_check', '_do_update',
                '_on_update_result', '_restart_after_update', '_save_pending_draft', '_take_pending_draft',
                '_pending_meta', '_apply_pending_draft', '_restore_pending_draft', '_clear_placeholder',
                '_shutdown_client', '_flash_status', '_check_updates_manual', '_show_update_check',
                '_update_offer_text', '_offer_update')
    _STATIC = ('_result_behind', '_scan_draft_meta', '_find_pending_conversation')

    def __init__(self):
        pytest.importorskip('tkinter')
        from bmchat.gui.app import App
        for name in self._METHODS:
            setattr(self, name, getattr(App, name).__get__(self))
        for name in self._STATIC:
            setattr(self, name, getattr(App, name))
        self._closed = False
        self._update_checking = False
        self._update_applying = False
        self._update_auto = False
        self._update_last_check = 0.0
        self._update_dirty_notified = False
        self._update_timer_after = None
        self.client = _FakeClient()
        self.status_texts = []
        self.statusbar = _StatusBar(self.status_texts)
        self.after_calls = []
        self.cancelled = []
        self._conv_meta = []
        self._conv_selected = None
        self._placeholder_on = False
        self.input_var = _Var()
        self.input_entry = _Entry()
        self.current_kind = None
        self.current_address = None
        self.opened = []

    def after(self, ms, func):
        self.after_calls.append((ms, func))
        return len(self.after_calls)

    def after_cancel(self, ident):
        self.cancelled.append(ident)

    def _open_conversation(self, kind, address):
        self.opened.append((kind, address))


def _drain_events(app):
    events = []
    while True:
        try:
            events.append(app.client.ui_queue.get_nowait())
        except queue.Empty:
            return events


@pytest.fixture
def auto_clone(cloned, monkeypatch):
    """Redireciona as chamadas git do App (sem repo_root) para o clone local."""
    origin, clone = cloned
    real_check = updater.check_for_updates
    real_clean = updater.is_tree_clean
    real_perform = updater.perform_update
    monkeypatch.setattr(updater, 'check_for_updates',
                        lambda repo_root=clone, fetch_timeout=15: real_check(clone, fetch_timeout=fetch_timeout))
    monkeypatch.setattr(updater, 'is_tree_clean', lambda repo_root=clone: real_clean(clone))
    monkeypatch.setattr(updater, 'perform_update',
                        lambda repo_root=clone, fetch_timeout=60, progress=None: real_perform(
                            clone, fetch_timeout=fetch_timeout, progress=progress))
    return origin, clone


def _clone_has_commit(clone, message):
    log = subprocess.run(['git', '-C', clone, 'log', '--oneline'], capture_output=True, timeout=60)
    return message in log.stdout.decode('utf-8', 'replace')


def test_parse_auto_update_and_interval():
    assert updater.parse_auto_update('1') == 1
    assert updater.parse_auto_update('0') == 0
    assert updater.parse_auto_update(1) == 1
    assert updater.parse_auto_update(0) == 0
    assert updater.parse_auto_update('', 1) == 1
    assert updater.parse_auto_update('x', 0) == 0
    assert updater.parse_auto_update(None, 1) == 1
    assert updater.parse_update_interval_h('6') == 6.0
    assert updater.parse_update_interval_h('1,5') == 1.5
    assert updater.parse_update_interval_h('0') == 0.0
    assert updater.parse_update_interval_h('x') == 6.0
    assert updater.parse_update_interval_h('-1') == 6.0
    assert updater.parse_update_interval_h(None) == 6.0


def test_should_auto_apply_policy():
    available = {'status': 'update-available', 'behind': 2}
    assert updater.should_auto_apply(available, True, True) is True
    assert updater.should_auto_apply(available, 1, 1) is True
    assert updater.should_auto_apply(available, False, True) is False
    assert updater.should_auto_apply(available, True, False) is False
    assert updater.should_auto_apply({'status': 'diverged'}, True, True) is False
    assert updater.should_auto_apply({'status': 'up-to-date'}, True, True) is False
    assert updater.should_auto_apply(None, True, True) is False
    assert 'pausada por mudanças locais' in updater.describe_dirty_hold(3)
    assert '2' in updater.describe_dirty_hold(2)


def test_pending_draft_roundtrip():
    db = _FakeDB()
    assert updater.is_draft_text('Mensagem') is False
    assert updater.is_draft_text('   ') is False
    assert updater.is_draft_text('oi') is True
    assert updater.save_pending_draft(db, 'Mensagem', 'contact', 'BM-a') is None
    assert updater.load_pending_draft(db) is None
    draft = updater.save_pending_draft(db, 'rascunho!', 'contact', 'BM-a')
    assert draft == {'text': 'rascunho!', 'kind': 'contact', 'address': 'BM-a'}
    assert updater.load_pending_draft(db) == draft
    updater.clear_pending_draft(db)
    assert updater.load_pending_draft(db) is None
    assert updater.save_pending_draft(db, 'oi', 'contact', '') is None
    assert updater.load_pending_draft(db) is None
    assert updater.save_pending_draft(db, '', 'contact', 'BM-a') is None
    assert updater.load_pending_draft(db) is None


def test_pending_draft_rejects_garbage():
    db = _FakeDB()
    db.set_setting(updater.PENDING_DRAFT_KEY, 'não-é-json')
    assert updater.load_pending_draft(db) is None
    db.set_setting(updater.PENDING_DRAFT_KEY, '[1, 2]')
    assert updater.load_pending_draft(db) is None


def test_perform_update_progress_phases(cloned):
    origin, clone = cloned
    _commit(origin, 'v2-progresso')
    phases = []
    ok, _message = updater.perform_update(clone, progress=phases.append)
    assert ok
    assert phases == ['fetch', 'merge']


def test_perform_update_bad_progress_ignored(cloned):
    origin, clone = cloned
    _commit(origin, 'v2-progresso-ruim')

    def bad_progress(_phase):
        raise RuntimeError('callback quebrou')

    ok, _message = updater.perform_update(clone, progress=bad_progress)
    assert ok


def test_auto_apply_clean_applies_and_restarts(auto_clone, monkeypatch):
    pytest.importorskip('tkinter')
    origin, clone = auto_clone
    _commit(origin, 'v2-auto')
    app = _FakeApp()
    app.client.db.set_setting('auto_update', '1')
    app._auto_update_check()
    assert app._update_applying is True
    assert app._update_auto is True
    assert _clone_has_commit(clone, 'v2-auto')
    events = _drain_events(app)
    results = [event for event in events if event[0] == 'update-result']
    assert len(results) == 1
    assert results[0][1] is True
    assert not any(event[0] == 'update-available' for event in events)
    assert any('Baixando' in message for _level, message in app.client.logs)
    assert any('Aplicando' in message for _level, message in app.client.logs)
    app._on_update_result(results[0])
    assert app._update_applying is False
    assert app._update_auto is False
    assert app.status_texts and 'Reiniciando' in app.status_texts[-1]
    assert len(app.after_calls) == 1
    assert app.after_calls[0][0] == 800
    restart_calls = {}
    monkeypatch.setattr(updater, 'restart_program',
                        lambda pre_exec=None, repo_root=None: restart_calls.update(pre_exec=pre_exec))
    warns = []
    monkeypatch.setattr('bmchat.gui.dialogs.warn', lambda *args: warns.append(args))
    app._restart_after_update()
    assert warns == []
    assert callable(restart_calls.get('pre_exec'))
    restart_calls['pre_exec']()
    assert app.client.stopped is True


def test_dirty_tree_warns_once_and_skips(auto_clone):
    pytest.importorskip('tkinter')
    origin, clone = auto_clone
    _commit(origin, 'v2-sujo')
    with open(os.path.join(clone, 'local.txt'), 'w') as handle:
        handle.write('trabalho local')
    app = _FakeApp()
    app.client.db.set_setting('auto_update', '1')
    app._auto_update_check()
    app._auto_update_check()
    events = _drain_events(app)
    assert app._update_applying is False
    assert [event for event in events if event[0] == 'update-result'] == []
    assert [event for event in events if event[0] == 'update-available'] == []
    holds = [event for event in events if event[0] == 'log' and 'pausada por mudanças locais' in event[2]]
    assert len(holds) == 1
    assert not _clone_has_commit(clone, 'v2-sujo')
    assert updater.check_for_updates(clone)['status'] == 'update-available'


def test_optout_only_notifies(auto_clone):
    pytest.importorskip('tkinter')
    origin, clone = auto_clone
    _commit(origin, 'v2-optout')
    app = _FakeApp()
    app.client.db.set_setting('auto_update', '0')
    app._auto_update_check()
    events = _drain_events(app)
    offers = [event for event in events if event[0] == 'update-available']
    assert len(offers) == 1
    assert offers[0][1] == 1
    assert [event for event in events if event[0] == 'update-result'] == []
    assert app._update_applying is False
    assert not _clone_has_commit(clone, 'v2-optout')


def test_auto_check_offline_is_silent(auto_clone):
    pytest.importorskip('tkinter')
    _origin, clone = auto_clone
    _git(clone, 'remote', 'set-url', 'origin', 'file:///nonexistente-bmchat-xyz')
    app = _FakeApp()
    app.client.db.set_setting('auto_update', '1')
    app._auto_update_check()
    events = _drain_events(app)
    noisy = [event for event in events if event[0] in ('update-available', 'update-result', 'update-check-result')]
    assert noisy == []
    assert any(level == 'update' for level, _message in app.client.logs)


def test_update_result_popup_only_manual(monkeypatch):
    pytest.importorskip('tkinter')
    from bmchat.gui import dialogs
    warns = []
    monkeypatch.setattr(dialogs, 'warn', lambda *args: warns.append(args))
    manual = _FakeApp()
    manual._update_auto = False
    manual._on_update_result(('update-result', False, 'falha x'))
    assert warns != []
    warns.clear()
    auto = _FakeApp()
    auto._update_auto = True
    auto._on_update_result(('update-result', False, 'falha x'))
    assert warns == []
    assert any('falha x' in message for _level, message in auto.client.logs)


def test_draft_restore_selects_conversation():
    pytest.importorskip('tkinter')
    app = _FakeApp()
    app._conv_meta = [('contact', 'BM-a'), ('contact', 'BM-b')]
    app._placeholder_on = True
    updater.save_pending_draft(app.client.db, 'rascunho pendente', 'contact', 'BM-b')
    app._restore_pending_draft()
    assert app.opened == [('contact', 'BM-b')]
    assert app._conv_selected == 1
    assert app.input_var.get() == 'rascunho pendente'
    assert app._placeholder_on is False
    assert updater.load_pending_draft(app.client.db) is None


def test_draft_restore_ignores_placeholder_and_unknown():
    pytest.importorskip('tkinter')
    app = _FakeApp()
    app._conv_meta = [('contact', 'BM-a')]
    updater.save_pending_draft(app.client.db, 'Mensagem', 'contact', 'BM-a')
    app._restore_pending_draft()
    assert app.opened == []
    updater.save_pending_draft(app.client.db, 'oi', 'contact', 'BM-desconhecido')
    app._restore_pending_draft()
    assert app.opened == []


def test_periodic_schedule_respects_interval():
    pytest.importorskip('tkinter')
    app = _FakeApp()
    app.client.db.set_setting('update_interval_h', '6')
    app._schedule_periodic_update_check()
    assert len(app.after_calls) == 1
    assert app.after_calls[0][0] == 6 * 3600 * 1000
    app._schedule_periodic_update_check()
    assert len(app.after_calls) == 2
    assert app.cancelled != []
    off = _FakeApp()
    off.client.db.set_setting('update_interval_h', '0')
    off._schedule_periodic_update_check()
    assert off.after_calls == []
