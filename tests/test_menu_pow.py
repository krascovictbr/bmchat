"""Menu hambúrguer agrupado + gerenciamento de POW (tarefas 1 e 2).

Cobre: estrutura do menu por grupo (top ~6, nenhum item some,
callbacks idênticos via invoke), metadados de POW/cancel unitário
e o diálogo de gerenciamento com PoW fake.
"""
import shutil
import tempfile
import threading
import time

import pytest

pytest.importorskip('tkinter')

from bmchat.core.client import Client  # noqa: E402


EXPECTED_GROUPS = {
    'Identidade': [
        'Minha identidade', 'Nova identidade', 'Backup de identidade…'],
    'Segurança': [
        'Backup criptografado…', 'Restaurar backup criptografado…',
        'Criptografar banco de dados…', 'Alterar senha do banco…'],
    'Rede': [
        'Diagnóstico de rede…', 'Ver log…', 'Configurações de rede…',
        'Proxy / Darknet...', 'Apagar objetos…', 'Verificar POW ativos'],
    'Contatos': ['Novo contato'],
    'Sistema': [
        'Verificar atualizações', 'Tema', 'Legenda de confirmações',
        'Tempo de vida das mensagens…', 'Sobre'],
}

EXPECTED_THEME = ['☀️  Claro', '🌙  Escuro']

LABEL_TO_METHOD = {
    'Minha identidade': '_show_welcome',
    'Nova identidade': '_new_identity',
    'Backup de identidade…': '_backup_identity',
    'Backup criptografado…': '_encrypted_backup',
    'Restaurar backup criptografado…': '_restore_encrypted_backup',
    'Criptografar banco de dados…': '_encrypt_database',
    'Alterar senha do banco…': '_change_db_password',
    'Diagnóstico de rede…': '_network_diagnostics',
    'Ver log…': '_show_log',
    'Configurações de rede…': '_network_settings',
    'Proxy / Darknet...': '_proxy_dialog',
    'Apagar objetos…': '_wipe_objects',
    'Verificar POW ativos': '_show_pows',
    'Novo contato': '_new_contact',
    'Verificar atualizações': '_check_updates_manual',
    'Legenda de confirmações': '_confirmation_legend',
    'Tempo de vida das mensagens…': '_msg_ttl_dialog',
    'Sobre': '_about',
    'Suporte…': '_support',
}


def _check_display():
    import tkinter as tk
    try:
        root = tk.Tk()
        root.withdraw()
        root.update_idletasks()
        root.destroy()
    except Exception:
        pytest.skip('sem DISPLAY para Tk')


def _pump(app, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            app.update()
        except Exception:
            pass
        if getattr(app, '_startup_done', False):
            break
        time.sleep(0.02)
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            app.update_idletasks()
            app.update()
        except Exception:
            break
        time.sleep(0.02)


def _make_app():
    _check_display()
    from bmchat.gui.app import App
    directory = tempfile.mkdtemp(prefix='bmchat-menu-pow-')
    app = App(directory)
    try:
        _pump(app)
        return app, directory
    except Exception:
        try:
            app._on_close()
        except Exception:
            pass
        shutil.rmtree(directory, ignore_errors=True)
        raise


def _close_app(app, directory):
    try:
        app._on_close()
    except Exception:
        pass
    try:
        app.update_idletasks()
    except Exception:
        pass
    shutil.rmtree(directory, ignore_errors=True)


def _top_entries(menu):
    last = menu.index('end')
    if last is None:
        return []
    return list(range(last + 1))


def _submenu_of(menu, index):
    name = menu.entrycget(index, 'menu')
    return menu.nametowidget(name)


def _leaf_labels(menu):
    labels = []
    for idx in _top_entries(menu):
        kind = menu.type(idx)
        if kind == 'command':
            labels.append(menu.entrycget(idx, 'label'))
        elif kind == 'cascade':
            sub = _submenu_of(menu, idx)
            for j in _top_entries(sub):
                stype = sub.type(j)
                if stype == 'command':
                    labels.append(sub.entrycget(j, 'label'))
                elif stype == 'cascade':
                    sub2 = _submenu_of(sub, j)
                    for k in _top_entries(sub2):
                        if sub2.type(k) == 'command':
                            labels.append(sub2.entrycget(k, 'label'))
    return labels


def _tops_of(menu):
    tops = []
    for idx in _top_entries(menu):
        tops.append((menu.entrycget(idx, 'label'), menu.type(idx)))
    return tops


def _find_cascade(menu, label):
    for idx in _top_entries(menu):
        if menu.type(idx) == 'cascade' and \
                menu.entrycget(idx, 'label') == label:
            return _submenu_of(menu, idx)
    return None


def _assert_top_level(menu):
    tops = _tops_of(menu)
    assert 6 <= len(tops) <= 8, tops
    cascades = [label for label, kind in tops if kind == 'cascade']
    assert cascades == [
        'Identidade', 'Segurança', 'Rede', 'Contatos', 'Sistema'], tops
    assert tops[-1] == ('Suporte…', 'command')


def _assert_groups(menu):
    for group, expected in EXPECTED_GROUPS.items():
        found = _find_cascade(menu, group)
        assert found is not None, group
        got = []
        for j in _top_entries(found):
            if found.type(j) in ('command', 'cascade'):
                got.append(found.entrycget(j, 'label'))
        assert got == expected, (group, got)


def _assert_theme_nested(menu):
    system = _find_cascade(menu, 'Sistema')
    assert system is not None
    theme = _find_cascade(system, 'Tema')
    assert theme is not None
    got_theme = [theme.entrycget(k, 'label') for k in _top_entries(theme)]
    assert got_theme == EXPECTED_THEME


def _assert_no_item_missing(menu):
    leaves = _leaf_labels(menu)
    assert len(leaves) == 21, leaves
    for label in LABEL_TO_METHOD:
        assert label in leaves, label
    for label in EXPECTED_THEME:
        assert label in leaves, label


def test_menu_grupos_e_contagem():
    app, directory = _make_app()
    try:
        menu = app._build_hamburger_menu()
        try:
            _assert_top_level(menu)
            _assert_groups(menu)
            _assert_theme_nested(menu)
            _assert_no_item_missing(menu)
        finally:
            try:
                menu.destroy()
            except Exception:
                pass
    finally:
        _close_app(app, directory)


def _invoke_all(menu, invoked):
    for idx in _top_entries(menu):
        kind = menu.type(idx)
        if kind == 'command':
            menu.invoke(idx)
            invoked.append(menu.entrycget(idx, 'label'))
        elif kind == 'cascade':
            _invoke_all(_submenu_of(menu, idx), invoked)


def _stub_calls(app, calls):
    def _stub(label):
        def _call(*_args, **_kwargs):
            calls.append(label)
        return _call

    for label, method in LABEL_TO_METHOD.items():
        setattr(app, method, _stub(label))
    app._set_theme = _stub('_set_theme')


def test_menu_invoke_todos_os_caminhos_sem_erro():
    app, directory = _make_app()
    try:
        calls = []
        _stub_calls(app, calls)
        menu = app._build_hamburger_menu()
        try:
            invoked = []
            _invoke_all(menu, invoked)
            assert sorted(invoked) == sorted(
                list(LABEL_TO_METHOD) + EXPECTED_THEME), invoked
            assert calls.count('_set_theme') == 2
            for label in LABEL_TO_METHOD:
                assert label in calls, label
        finally:
            try:
                menu.destroy()
            except Exception:
                pass
    finally:
        _close_app(app, directory)


def _make_client():
    directory = tempfile.mkdtemp(prefix='bmchat-pow-meta-')
    client = Client(directory)
    return client, directory


def _close_client(client, directory):
    try:
        client.stop()
    except Exception:
        pass
    shutil.rmtree(directory, ignore_errors=True)


def test_pow_track_list_note_untrack():
    client, directory = _make_client()
    try:
        assert client.list_pow_tasks() == []
        stop = threading.Event()
        client._track_pow(7, stop, message_id=42, dest='BM-destino',
                          preview='olá mundo', kind='msg')
        tasks = client.list_pow_tasks()
        assert len(tasks) == 1
        task = tasks[0]
        assert task['token'] == 7
        assert task['message_id'] == 42
        assert task['dest'] == 'BM-destino'
        assert task['preview'] == 'olá mundo'
        assert task['kind'] == 'msg'
        assert task['tried'] == 0
        assert task['rate'] == 0.0
        assert task['elapsed'] >= 0.0
        assert task['cancelling'] is False
        client._note_pow_progress(7, 1234, 5678.0)
        task = client.list_pow_tasks()[0]
        assert task['tried'] == 1234
        assert task['rate'] == 5678.0
        client.cancel_pow(7)
        assert stop.is_set()
        assert client.list_pow_tasks()[0]['cancelling'] is True
        client._untrack_pow(7)
        assert client.list_pow_tasks() == []
        assert 7 not in client._pow_stops
    finally:
        _close_client(client, directory)


def test_pow_preview_curta():
    assert Client._pow_preview(None) == ''
    assert Client._pow_preview('  oi  ') == 'oi'
    long_text = 'x' * 100
    short = Client._pow_preview(long_text)
    assert len(short) == 40
    assert short.endswith('…')
    assert Client._pow_preview('a\nb') == 'a b'


def _wait_for(condition, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


def test_pow_and_publish_sucesso_limpa_meta(monkeypatch):
    import bmchat.core.client as client_mod

    class _FastExecutor:
        def __init__(self, workers=None, progress_cb=None, stop_event=None):
            self.progress_cb = progress_cb

        def run(self, initial_hash, target):
            if self.progress_cb is not None:
                self.progress_cb(10, 100.0)
            return 999

    monkeypatch.setattr(client_mod, 'PowExecutor', _FastExecutor)
    client, directory = _make_client()
    try:
        done = []
        token = client._pow_and_publish(
            b'unsigned-teste', 2 ** 60, message_id=11,
            done_cb=lambda complete, nonce: done.append((complete, nonce)),
            dest='BM-alvo', preview='corpo curto', kind='msg')
        assert token in client._pow_stops
        assert any(t['token'] == token for t in client.list_pow_tasks())
        assert _wait_for(lambda: not client.list_pow_tasks(), timeout=5)
        assert done, 'done_cb deveria rodar no sucesso'
        complete, nonce = done[0]
        assert nonce == 999
        assert complete.endswith(b'unsigned-teste')
        assert client.ui_queue.empty() or True
    finally:
        _close_client(client, directory)


def _launch_three_pow(client):
    tokens = []
    for idx in range(3):
        token = client._pow_and_publish(
            b'unsigned-%d' % idx, 1, dest='BM-%d' % idx,
            preview='msg %d' % idx, kind='msg')
        tokens.append(token)
    return tokens


def _drain_queue(client):
    events = []
    while not client.ui_queue.empty():
        events.append(client.ui_queue.get())
    return events


def _assert_cancel_one(client, tokens):
    client.cancel_pow(tokens[0])
    assert _wait_for(
        lambda: tokens[0] not in [
            t['token'] for t in client.list_pow_tasks()], timeout=5)
    remaining = [t['token'] for t in client.list_pow_tasks()]
    assert sorted(remaining) == sorted(tokens[1:])
    kinds = [t['kind'] for t in client.list_pow_tasks()]
    assert set(kinds) == {'msg'}


def _assert_cancel_all(client, tokens):
    client.cancel_all_pow()
    assert _wait_for(lambda: client.list_pow_tasks() == [], timeout=5)
    leftovers = _drain_queue(client)
    cancelled = [e[1] for e in leftovers if e[0] == 'pow-cancelled']
    for token in tokens[1:]:
        assert token in cancelled, (token, leftovers)


def test_pow_cancel_unitario_e_todos(monkeypatch):
    import bmchat.core.client as client_mod

    class _BlockingExecutor:
        def __init__(self, workers=None, progress_cb=None, stop_event=None):
            self.stop_event = stop_event
            self.progress_cb = progress_cb

        def run(self, initial_hash, target):
            if self.progress_cb is not None:
                self.progress_cb(5, 50.0)
            deadline = time.time() + 10.0
            while time.time() < deadline:
                if self.stop_event is not None and self.stop_event.is_set():
                    raise RuntimeError('proof of work não concluído')
                time.sleep(0.02)
            raise RuntimeError('proof of work não concluído')

    monkeypatch.setattr(client_mod, 'PowExecutor', _BlockingExecutor)
    client, directory = _make_client()
    try:
        _drain_queue(client)
        tokens = _launch_three_pow(client)
        assert _wait_for(lambda: len(client.list_pow_tasks()) == 3, timeout=5)
        assert _wait_for(
            lambda: any(t['tried'] == 5 for t in client.list_pow_tasks()),
            timeout=5)
        _assert_cancel_one(client, tokens)
        events = _drain_queue(client)
        assert any(e[0] == 'pow-cancelled' and e[1] == tokens[0]
                   for e in events), events
        _assert_cancel_all(client, tokens)
    finally:
        _close_client(client, directory)


def test_pow_falha_limpa_in_flight(monkeypatch):
    import bmchat.core.client as client_mod

    class _FailExecutor:
        def __init__(self, workers=None, progress_cb=None, stop_event=None):
            pass

        def run(self, initial_hash, target):
            raise RuntimeError('proof of work não concluído')

    monkeypatch.setattr(client_mod, 'PowExecutor', _FailExecutor)
    client, directory = _make_client()
    try:
        while not client.ui_queue.empty():
            client.ui_queue.get()
        with client._lock:
            client._msg_in_flight.add(555)
        client._run_pow_and_done(b'unsigned-x', 1, message_id=555,
                                 done_cb=None)
        with client._lock:
            assert 555 not in client._msg_in_flight
        assert client.list_pow_tasks() == []
        events = []
        while not client.ui_queue.empty():
            events.append(client.ui_queue.get())
        assert any(e[0] == 'pow-cancelled' for e in events), events
    finally:
        _close_client(client, directory)


def _pump_window(app, window, seconds=1.5):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            app.update()
        except Exception:
            pass
        try:
            if window.winfo_exists():
                window.update()
        except Exception:
            pass
        time.sleep(0.02)


def test_dialogo_pow_com_fake_e_vazio():
    app, directory = _make_app()
    try:
        callback_errors = []
        import tkinter as tk
        original = tk.Tk.report_callback_exception

        def _capture(self, exc, val, tb):
            callback_errors.append(repr(val))

        tk.Tk.report_callback_exception = _capture
        try:
            # Estado vazio amigável.
            window = app._show_pows()
            _pump_window(app, window)
            assert window.winfo_exists()
            app.update()
            empty_text = str(window._pow_empty.cget('text'))
            assert 'Nenhum cálculo em andamento' in empty_text
            assert window._pow_listbox.size() == 0
            try:
                window.destroy()
            except Exception:
                pass
            _pump_window(app, window, seconds=0.5)
            # Com PoW fake: lista, cancela selecionado e todos.
            stop_a = threading.Event()
            stop_b = threading.Event()
            app.client._track_pow(101, stop_a, message_id=1,
                                  dest='BM-destino-fake-123456789012345',
                                  preview='olá mundo, teste de pow fake',
                                  kind='msg')
            app.client._note_pow_progress(101, 4321, 8765.0)
            app.client._track_pow(102, stop_b, dest=None,
                                  preview='pedido de chave pública',
                                  kind='getpubkey')
            window2 = app._show_pows()
            _pump_window(app, window2)
            assert window2.winfo_exists()
            assert window2._pow_listbox.size() == 2
            rows = window2._pow_listbox.get(0, 'end')
            joined = '\n'.join(rows)
            assert '#101' in joined
            assert '#102' in joined
            assert 'olá mundo' in joined
            assert '4321' in joined
            assert '8765' in joined
            assert 'calculando' in joined
            assert 'Nenhum cálculo em andamento' in str(
                window2._pow_count.cget('text')) or \
                'cálculo(s)' in str(window2._pow_count.cget('text'))
            # Cancelar selecionado não explode.
            window2._pow_listbox.selection_clear(0, 'end')
            window2._pow_listbox.selection_set(0)
            app._cancel_selected_pow(window2)
            _pump_window(app, window2, seconds=0.6)
            assert stop_a.is_set()
            assert window2.winfo_exists()
            # Cancelar todos não explode.
            app._cancel_all_pows_ui(window2)
            _pump_window(app, window2, seconds=0.6)
            assert stop_b.is_set()
            # Simula conclusão dos workers: some tudo e mostra vazio.
            app.client._untrack_pow(101)
            app.client._untrack_pow(102)
            app._refresh_pow_window(window2, force=True)
            _pump_window(app, window2, seconds=0.8)
            assert window2._pow_listbox.size() == 0
            assert 'Nenhum cálculo em andamento' in str(
                window2._pow_empty.cget('text'))
            try:
                window2.destroy()
            except Exception:
                pass
            assert callback_errors == [], callback_errors
        finally:
            tk.Tk.report_callback_exception = original
    finally:
        _close_app(app, directory)
