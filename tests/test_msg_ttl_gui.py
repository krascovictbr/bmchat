"""GUI do TTL global + excluir mensagem (único teste Tk do assunto)."""
import shutil
import tempfile
import time

import pytest

pytest.importorskip('tkinter')


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
    directory = tempfile.mkdtemp(prefix='bmchat-msgttl-gui-')
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
    shutil.rmtree(directory, ignore_errors=True)


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


def _widgets(window, klass):
    return [w for w in _walk(window) if w.winfo_class() == klass]


def _button(window, text):
    for widget in _widgets(window, 'Button'):
        if widget.cget('text') == text:
            return widget
    raise AssertionError('botão %r não achado' % text)


def _radio(window, text):
    for widget in _widgets(window, 'Radiobutton'):
        if widget.cget('text') == text:
            return widget
    raise AssertionError('preset %r não achado' % text)


def _window_alive(window):
    try:
        return bool(window.winfo_exists())
    except Exception:
        return False


def test_dialogo_ttl_e_excluir_mensagem(monkeypatch):
    _check_display()
    from bmchat.crypto.keys import generate_keys
    from bmchat.gui import app as app_mod
    from bmchat.gui.app import App
    app, directory = _make_app()
    try:
        window = app._msg_ttl_dialog()
        assert window is not None and _window_alive(window)
        texts = [w.cget('text') for w in _walk(window)
                 if w.winfo_class() in ('Radiobutton', 'Label')]
        for preset in ('1 hora', '1 dia', '7 dias', '21 dias'):
            assert preset in texts, preset
        assert any('rede descarta' in text for text in texts)
        _radio(window, 'Outro:').invoke()
        entry = _widgets(window, 'Entry')[0]
        entry.delete(0, 'end')
        entry.insert(0, '48')
        _button(window, 'Salvar').invoke()
        assert app.client.get_msg_ttl() == 172800
        assert not _window_alive(window)

        window = app._msg_ttl_dialog()
        _radio(window, '7 dias').invoke()
        _button(window, 'Salvar').invoke()
        assert app.client.get_msg_ttl() == 604800
        assert not _window_alive(window)

        alice = app.client.create_identity('Alice', 1)
        bob = generate_keys(stream=1).address
        app.client.add_contact(bob, 'Bob')
        now = int(time.time())
        first = app.client.db.add_message(None, alice, bob, '', 'uma', 2,
                                          now, 'out', 'sent')
        second = app.client.db.add_message(None, alice, bob, '', 'duas', 2,
                                           now, 'out', 'sent')
        app.current_address = bob
        app._reload_chat()
        assert len(app._chat_rows) == 2
        monkeypatch.setattr(app_mod.dialogs, 'confirm',
                            lambda *args, **kwargs: True)
        app._delete_message(app.client.db.get_message(first))
        assert app.client.db.get_message(first) is None
        assert app.client.db.get_message(second) is not None
        assert [row['id'] for row in app._chat_rows] == [second]
        monkeypatch.setattr(app_mod.dialogs, 'confirm',
                            lambda *args, **kwargs: False)
        app._delete_message(app.client.db.get_message(second))
        assert app.client.db.get_message(second) is not None

        assert App._format_expiry(
            {'expires': int(time.time()) + 3600}).startswith('Expira em')
        assert App._format_expiry(
            {'expires': int(time.time()) - 10}) == 'expirada'
        assert App._format_expiry({}) == '—'
    finally:
        _close_app(app, directory)
