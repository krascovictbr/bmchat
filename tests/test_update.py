import os
import shutil
import subprocess
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
