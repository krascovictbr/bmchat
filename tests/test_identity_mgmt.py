"""Gerenciamento completo de identidade/conta (Tk real, PoW mockado).

Cobre (PT-BR, sem popup no fallback, sem report_callback_exception):
criar A e B via GUI, alternar A->B->A em 1 clique, envio isolado A vs B,
persistencia + restart no mesmo datadir, renomear/desabilitar/excluir
com guardas, detalhes e rascunho agendado com a identidade certa.
"""
import datetime
import shutil
import tempfile
import time
from unittest import mock

import pytest

pytest.importorskip('tkinter')
import tkinter as tk  # noqa: E402

import bmchat.core.client as client_mod  # noqa: E402
from bmchat.crypto.keys import generate_keys  # noqa: E402
from bmchat.crypto.pow import (  # noqa: E402
    find_nonce_single_threaded, initial_hash_of,
)
from bmchat.protocol import objects  # noqa: E402

TARGET = 2 ** 52


def _check_display():
    try:
        root = tk.Tk()
        root.withdraw()
        root.update_idletasks()
        root.destroy()
    except Exception:
        pytest.skip('sem DISPLAY para Tk')


def _pump(app, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            app.update()
        except Exception:
            pass
        if getattr(app, '_startup_done', False):
            break
        time.sleep(0.02)
    end = time.time() + 1.0
    while time.time() < end:
        try:
            app.update_idletasks()
            app.update()
        except Exception:
            break
        time.sleep(0.02)


def _sync(app):
    try:
        app.update()
    except Exception:
        pass


def _sync_full(app):
    try:
        app.update()
        app._drain_events()
        app.update()
    except Exception:
        pass


def _make_app(directory=None):
    _check_display()
    from bmchat.gui.app import App
    own = directory is None
    if own:
        directory = tempfile.mkdtemp(prefix='bmchat-ident-')
    app = App(directory)
    _pump(app)
    return app, directory, own


def _close_app(app, directory, own=True):
    try:
        app._on_close()
    except Exception:
        pass
    try:
        app.update_idletasks()
    except Exception:
        pass
    if own:
        shutil.rmtree(directory, ignore_errors=True)


def _mock_pow(app):
    announced = []
    original_target = client_mod.calculate_target
    client_mod.calculate_target = lambda *a, **k: TARGET

    def fake_run(self, unsigned, target, message_id=None, done_cb=None,
                 token=None, stop_event=None):
        nonce = find_nonce_single_threaded(
            initial_hash_of(unsigned), TARGET)
        result = objects.complete_object(unsigned, nonce)
        if done_cb is not None:
            done_cb(result, nonce)

    def fake_quick(self, unsigned, target):
        return find_nonce_single_threaded(
            initial_hash_of(unsigned), TARGET)

    app.client._run_pow_and_done = fake_run.__get__(
        app.client, type(app.client))
    app.client._quick_pow = fake_quick.__get__(
        app.client, type(app.client))
    with mock.patch.object(
            app.client.net, 'announce_object',
            lambda data, source=None: announced.append(bytes(data))):
        pass
    app.client.net.announce_object = (
        lambda data, source=None: announced.append(bytes(data)))
    return announced, original_target


def _unmock_pow(original_target):
    client_mod.calculate_target = original_target


def _capture_callbacks():
    errors = []
    original = tk.Tk.report_callback_exception

    def _capture(self, exc, val, tb):
        errors.append(repr(val))

    tk.Tk.report_callback_exception = _capture
    return errors, original


def _restore_callbacks(original):
    tk.Tk.report_callback_exception = original


def _keep_only(app, keep_addrs):
    keep = set(keep_addrs)
    try:
        rows = app.client.db.all_identities(enabled_only=False)
    except Exception:
        return
    for row in rows:
        addr = row.get('address')
        if addr not in keep:
            try:
                app.client.delete_identity(addr)
            except Exception:
                pass
    try:
        app._refresh_identity_menu()
        app._update_identity_indicator()
        app._refresh_conversations()
        app.update()
    except Exception:
        pass


def _gui_create(app, label):
    from bmchat.gui import dialogs as dialogs_mod
    fake_ask = {'label': label, 'stream': '1'}
    with mock.patch.object(
            dialogs_mod, 'ask_simple', return_value=fake_ask):
        with mock.patch.object(dialogs_mod, 'info'):
            app._new_identity()
    _sync_full(app)
    rows = app.client.db.all_identities(enabled_only=False)
    found = [r for r in rows if r.get('label') == label]
    assert found, 'identidade %s nao criada via GUI' % label
    return found[0]['address']


def _ensure_contact(app):
    keys = generate_keys(stream=1)
    address = keys.address
    app.client.add_contact(address, 'Contato-%s' % address[:8])
    app.client.db.store_pubkey(
        address, keys.signing_public, keys.encryption_public, 1000, 1000)
    app.client.pubkeys[address] = {
        'signing_public': keys.signing_public,
        'encryption_public': keys.encryption_public,
        'nonce_trials_per_byte': 1000,
        'payload_length_extra_bytes': 1000,
    }
    _sync(app)
    app._refresh_conversations()
    _sync(app)
    return address


def _assert_indicator(app, address, label):
    from bmchat.gui.app import _short_address
    short = _short_address(address)
    indicator = str(app.identity_indicator_label.cget('text'))
    assert label in indicator, indicator
    assert short in indicator, indicator
    assert app._identity_tooltip.text == address
    assert app._badge_tooltip.text == address
    badge = str(app.identity_badge_label.cget('text'))
    assert label in badge, badge
    assert short in badge, badge
    assert app._current_identity() == address


def _switch_and_check(app, address, label):
    assert app._set_current_identity(address) is True
    status = str(app.statusbar.cget('text'))
    assert 'Enviando como %s' % label in status, status
    _sync_full(app)
    _assert_indicator(app, address, label)
    placeholder = str(app.input_var.get())
    assert label in placeholder, placeholder


def _send_from_current(app, contact, body):
    app._open_conversation('contact', contact)
    _sync(app)
    app._clear_placeholder()
    app.input_var.set(body)
    app._placeholder_on = False
    app._send()
    return body


def _wait_out_message(app, contact, from_addr, body, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        _sync(app)
        rows = app.client.db.query(
            "SELECT * FROM messages WHERE to_address=? AND "
            "from_address=? AND body=? AND direction='out'",
            (contact, from_addr, body))
        if rows:
            return rows[0]
        time.sleep(0.05)
    rows = app.client.db.query(
        "SELECT * FROM messages WHERE to_address=? AND from_address=?",
        (contact, from_addr))
    assert rows, 'sem mensagem enviada'
    return rows[0]


def _last_body(app, from_addr):
    rows = app.client.db.query(
        "SELECT body FROM messages WHERE from_address=? "
        "ORDER BY id DESC LIMIT 1", (from_addr,))
    assert rows
    return rows[0]['body']


def test_identidade_criar_trocar_enviar_isolamento():
    errors, original = _capture_callbacks()
    app, directory, own = _make_app()
    _, saved_target = _mock_pow(app)
    try:
        addr_a = _gui_create(app, 'Alice')
        addr_b = _gui_create(app, 'Bob')
        _keep_only(app, [addr_a, addr_b])
        assert addr_a != addr_b
        assert len(app.client.identities) == 2
        _switch_and_check(app, addr_a, 'Alice')
        _switch_and_check(app, addr_b, 'Bob')
        _switch_and_check(app, addr_a, 'Alice')
        contact = _ensure_contact(app)
        _switch_and_check(app, addr_a, 'Alice')
        body_a = 'ola de A %d' % int(time.time())
        _send_from_current(app, contact, body_a)
        row_a = _wait_out_message(app, contact, addr_a, body_a)
        assert row_a['from_address'] == addr_a
        _switch_and_check(app, addr_b, 'Bob')
        body_b = 'ola de B %d' % int(time.time())
        _send_from_current(app, contact, body_b)
        row_b = _wait_out_message(app, contact, addr_b, body_b)
        assert row_b['from_address'] == addr_b
        assert _last_body(app, addr_a) != _last_body(app, addr_b)
        _assert_indicator(app, addr_b, 'Bob')
        assert errors == [], errors
    finally:
        _unmock_pow(saved_target)
        _restore_callbacks(original)
        _close_app(app, directory, own)


def _open_fresh(directory):
    from bmchat.gui.app import App as AppCls
    _check_display()
    fresh = AppCls(directory)
    _pump(fresh)
    return fresh


def test_identidade_persistencia_restart():
    errors, original = _capture_callbacks()
    directory = tempfile.mkdtemp(prefix='bmchat-ident-restart-')
    app, _, _ = _make_app(directory)
    _, saved_target = _mock_pow(app)
    addr_a = _gui_create(app, 'Alice')
    addr_b = _gui_create(app, 'Bob')
    _keep_only(app, [addr_a, addr_b])
    assert addr_a != addr_b
    assert app._set_current_identity(addr_b) is True
    _sync(app)
    saved = app.client.db.get_setting('current_identity', '')
    assert saved == addr_b, saved
    _unmock_pow(saved_target)
    _close_app(app, directory, own=False)
    app2 = _open_fresh(directory)
    try:
        assert app2._current_identity() == addr_b
        _assert_indicator(app2, addr_b, 'Bob')
        assert errors == [], errors
    finally:
        _restore_callbacks(original)
        try:
            app2._on_close()
        except Exception:
            pass
        shutil.rmtree(directory, ignore_errors=True)


def test_identidade_fallback_sem_popup():
    errors, original = _capture_callbacks()
    directory = tempfile.mkdtemp(prefix='bmchat-ident-fallback-')
    app, _, _ = _make_app(directory)
    _, saved_target = _mock_pow(app)
    addr_a = _gui_create(app, 'Alice')
    addr_b = _gui_create(app, 'Bob')
    _keep_only(app, [addr_a, addr_b])
    assert app._set_current_identity(addr_a) is True
    _unmock_pow(saved_target)
    app.client.db.set_setting('current_identity', 'BM-fantasma-000')
    _close_app(app, directory, own=False)
    from bmchat.gui import dialogs as dialogs_mod
    popups = []
    with mock.patch.object(
            dialogs_mod, 'warn',
            side_effect=lambda *a, **k: popups.append('warn')):
        with mock.patch.object(
                dialogs_mod, 'info',
                side_effect=lambda *a, **k: popups.append('info')):
            with mock.patch.object(
                    dialogs_mod, 'confirm', return_value=False):
                app2 = _open_fresh(directory)
    try:
        current = app2._current_identity()
        assert current in [r['address'] for r in
                           app2.client.db.all_identities(
                               enabled_only=True)]
        status = str(app2.statusbar.cget('text'))
        assert status.strip() != ''
        assert popups == [], popups
        assert errors == [], errors
    finally:
        _restore_callbacks(original)
        try:
            app2._on_close()
        except Exception:
            pass
        shutil.rmtree(directory, ignore_errors=True)


def _rename_via_gui(app, address, new_label):
    from bmchat.gui import dialogs as dialogs_mod
    with mock.patch.object(dialogs_mod, 'warn'):
        ok = app._rename_identity(address, new_label)
    _sync_full(app)
    return ok


def _disable_via_gui(app, address, enabled):
    from bmchat.gui import dialogs as dialogs_mod
    with mock.patch.object(dialogs_mod, 'warn'):
        return app._set_identity_enabled_ui(address, enabled)


def test_identidade_renomear_desabilitar_guardas():
    errors, original = _capture_callbacks()
    app, directory, own = _make_app()
    _, saved_target = _mock_pow(app)
    try:
        addr_a = _gui_create(app, 'Alice')
        addr_b = _gui_create(app, 'Bob')
        _keep_only(app, [addr_a, addr_b])
        assert _rename_via_gui(app, addr_b, 'Beto') is True
        assert app.client.db.get_identity(addr_b)['label'] == 'Beto'
        assert app._set_current_identity(addr_b) is True
        _sync(app)
        assert 'Beto' in str(
            app.identity_indicator_label.cget('text'))
        assert _rename_via_gui(app, addr_b, '   ') is False
        assert app.client.db.get_identity(addr_b)['label'] == 'Beto'
        assert _disable_via_gui(app, addr_b, False) is True
        assert addr_b not in app.client.identities
        assert app.client.db.get_identity(addr_b)['enabled'] == 0
        assert app._current_identity() == addr_a
        assert _disable_via_gui(app, addr_a, False) is False
        assert addr_a in app.client.identities
        assert errors == [], errors
    finally:
        _unmock_pow(saved_target)
        _restore_callbacks(original)
        _close_app(app, directory, own)


def test_identidade_excluir_com_guardas_e_backup():
    errors, original = _capture_callbacks()
    app, directory, own = _make_app()
    _, saved_target = _mock_pow(app)
    try:
        addr_a = _gui_create(app, 'Alice')
        addr_b = _gui_create(app, 'Bob')
        _keep_only(app, [addr_a, addr_b])
        assert app._set_current_identity(addr_b) is True
        _sync_full(app)
        from bmchat.gui import dialogs as dialogs_mod
        seen = {}
        with mock.patch.object(dialogs_mod, 'warn'):
            with mock.patch.object(
                    dialogs_mod, 'confirm',
                    side_effect=lambda *a, **k: seen.update(
                        message=(a[2] if len(a) > 2 else '')) or True):
                assert app._delete_identity(addr_a) is True
        assert 'backup' in seen.get('message', '').lower()
        assert app.client.db.get_identity(addr_a) is None
        assert app.client.export_identity(addr_a) is None
        assert addr_a not in app.client.identities
        # Ultima ativa protegida.
        last = app._current_identity()
        with mock.patch.object(dialogs_mod, 'warn'):
            with mock.patch.object(
                    dialogs_mod, 'confirm', return_value=True):
                assert app._delete_identity(last) is False
        assert app.client.db.get_identity(last) is not None
        assert errors == [], errors
    finally:
        _unmock_pow(saved_target)
        _restore_callbacks(original)
        _close_app(app, directory, own)


def _collect_detail_texts(window):
    texts = []

    def _walk(widget):
        try:
            texts.append(str(widget.cget('text')))
        except Exception:
            pass
        try:
            children = widget.winfo_children()
        except Exception:
            return
        for child in children:
            _walk(child)

    _walk(window)
    return '\n'.join(texts)


def test_identidade_detalhes_e_gerenciador():
    errors, original = _capture_callbacks()
    app, directory, own = _make_app()
    _, saved_target = _mock_pow(app)
    try:
        addr_a = _gui_create(app, 'Alice')
        addr_b = _gui_create(app, 'Bob')
        _keep_only(app, [addr_a, addr_b])
        contact = _ensure_contact(app)
        assert app._set_current_identity(addr_b) is True
        body = 'contagem 1 %d' % int(time.time())
        _send_from_current(app, contact, body)
        _wait_out_message(app, contact, addr_b, body)
        window = app._show_identity_details(addr_b)
        try:
            _sync(app)
            assert window.winfo_exists()
            joined = _collect_detail_texts(window)
            assert 'Bob' in joined, joined
            assert addr_b in joined, joined
            assert 'Mensagens' in joined
            assert 'Conversas' in joined
        finally:
            try:
                window.destroy()
            except Exception:
                pass
        manager = app._manage_identities()
        try:
            _sync(app)
            assert manager.winfo_exists()
            assert manager._ident_listbox.size() == 2
            rows = manager._ident_listbox.get(0, 'end')
            joined_rows = '\n'.join(rows)
            assert 'Alice' in joined_rows
            assert 'Bob' in joined_rows
            assert '[em uso]' in joined_rows
            assert '2 identidade(s)' in str(
                manager._ident_count.cget('text'))
        finally:
            try:
                manager.destroy()
            except Exception:
                pass
        assert errors == [], errors
    finally:
        _unmock_pow(saved_target)
        _restore_callbacks(original)
        _close_app(app, directory, own)


def test_identidade_agendado_identidade_certa():
    errors, original = _capture_callbacks()
    app, directory, own = _make_app()
    _, saved_target = _mock_pow(app)
    try:
        addr_a = _gui_create(app, 'Alice')
        addr_b = _gui_create(app, 'Bob')
        _keep_only(app, [addr_a, addr_b])
        contact = _ensure_contact(app)
        assert app._set_current_identity(addr_b) is True
        app._open_conversation('contact', contact)
        _sync(app)
        app._clear_placeholder()
        app.input_var.set('agendada de B')
        app._placeholder_on = False
        future = datetime.datetime.now() + datetime.timedelta(minutes=5)
        from bmchat.gui import dialogs as dialogs_mod
        fake = {'date': future.strftime('%d/%m/%Y'),
                'time': future.strftime('%H:%M')}
        with mock.patch.object(
                dialogs_mod, 'ask_simple', return_value=fake):
            with mock.patch.object(dialogs_mod, 'warn'):
                app._schedule_message()
        _sync(app)
        pending = app.client.db.query(
            'SELECT * FROM scheduled_messages WHERE to_address=? '
            'ORDER BY id DESC LIMIT 1', (contact,))
        assert pending, 'agendamento nao gravou'
        assert pending[0]['identity_address'] == addr_b, pending[0]
        assert pending[0]['body'] == 'agendada de B'
        due_id = app.client.db.add_scheduled_message(
            addr_b, contact, 'disparo agendado B', int(time.time()) - 1)
        app.client._send_due_scheduled()
        row = _wait_out_message(
            app, contact, addr_b, 'disparo agendado B')
        assert row['from_address'] == addr_b
        done = app.client.db.query(
            'SELECT * FROM scheduled_messages WHERE id=?', (due_id,))
        assert done and done[0]['sent'] == 1
        assert errors == [], errors
    finally:
        _unmock_pow(saved_target)
        _restore_callbacks(original)
        _close_app(app, directory, own)
