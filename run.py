import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bmchat.gui.app import main


def data_dir_default():
    home = os.path.expanduser('~')
    path = os.path.join(home, '.bmchat')
    os.makedirs(path, exist_ok=True)
    return path


if __name__ == '__main__':
    directory = os.environ.get('BMCHAT_DATA') or data_dir_default()
    main(directory)