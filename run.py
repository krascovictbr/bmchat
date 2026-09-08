import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bmchat.gui.app import main


def _ensure_writable_dir(path):
    """M4: exige diretório gravável (erro amigável em vez de falhar depois)."""
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except Exception as exc:
        raise SystemExit(
            'BMCHAT_DATA inválido: não foi possível criar %r (%s). '
            'Aponte para um diretório gravável.' % (path, exc))
    try:
        os.chmod(path, 0o700)
    except Exception:
        pass
    if not os.path.isdir(path) or not os.access(path, os.W_OK | os.X_OK):
        raise SystemExit(
            'BMCHAT_DATA inválido: %r não é um diretório gravável. '
            'Aponte para um diretório gravável.' % path)
    probe = os.path.join(path, '.bmchat-write-test')
    try:
        with open(probe, 'w', encoding='utf-8') as handle:
            handle.write('ok')
    except Exception:
        raise SystemExit(
            'BMCHAT_DATA inválido: sem permissão de escrita em %r. '
            'Aponte para um diretório gravável.' % path)
    try:
        os.unlink(probe)
    except Exception:
        pass
    return path


def data_dir_default():
    home = os.path.expanduser('~')
    path = os.path.join(home, '.bmchat')
    return _ensure_writable_dir(path)


if __name__ == '__main__':
    raw = os.environ.get('BMCHAT_DATA')
    if raw and raw.strip():
        directory = _ensure_writable_dir(
            os.path.abspath(os.path.expanduser(raw.strip())))
    else:
        directory = data_dir_default()
    main(directory)
