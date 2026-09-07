import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bmchat.gui.app import main


def data_dir_default():
    home = os.path.expanduser('~')
    path = os.path.join(home, '.bmchat')
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except Exception:
        pass
    return path


if __name__ == '__main__':
    raw = os.environ.get('BMCHAT_DATA')
    if raw and raw.strip():
        directory = os.path.abspath(os.path.expanduser(raw.strip()))
    else:
        directory = data_dir_default()
    main(directory)