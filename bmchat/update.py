"""Atualização rolling release via ``git pull``.

Fluxo: busca do remoto -> compara com o upstream -> avisa o usuário ->
com ``git pull --ff-only`` (nunca cria merge nem toca em trabalho local)
-> reinicia o programa no mesmo interpretador.
"""

import os
import subprocess
import sys

from .version import _REPO_ROOT


def _git(repo_root, args, timeout=60):
    try:
        completed = subprocess.run(
            ['git', '-C', repo_root] + args, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False)
    except Exception as exc:
        return None, str(exc)
    out = completed.stdout.decode('utf-8', 'replace').strip()
    err = completed.stderr.decode('utf-8', 'replace').strip()
    if completed.returncode != 0:
        return None, err or out or 'git falhou'
    return out, ''


def _upstream(repo_root):
    out, _ = _git(repo_root, ['rev-parse', '--abbrev-ref',
                              '--symbolic-full-name', '@{u}'])
    return out or None


def check_for_updates(repo_root=_REPO_ROOT):
    """Verifica se há commits novos no upstream. Nunca altera nada."""
    if not os.path.isdir(os.path.join(repo_root, '.git')):
        return {'status': 'no-repo'}
    fetched, error = _git(repo_root, ['fetch', 'origin'])
    if fetched is None:
        return {'status': 'fetch-failed', 'error': error}
    upstream = _upstream(repo_root)
    if not upstream:
        return {'status': 'no-upstream'}
    local, _ = _git(repo_root, ['rev-parse', 'HEAD'])
    remote, _ = _git(repo_root, ['rev-parse', '@{u}'])
    if not local or not remote:
        return {'status': 'unknown'}
    if local == remote:
        return {'status': 'up-to-date', 'local': local}
    behind, _ = _git(repo_root, ['rev-list', '--count', 'HEAD..@{u}'])
    ahead, _ = _git(repo_root, ['rev-list', '--count', '@{u}..HEAD'])
    try:
        behind, ahead = int(behind or 0), int(ahead or 0)
    except ValueError:
        behind, ahead = 0, 0
    if ahead and behind:
        return {'status': 'diverged', 'behind': behind, 'ahead': ahead,
                'local': local, 'remote': remote, 'upstream': upstream}
    if behind:
        return {'status': 'update-available', 'behind': behind,
                'local': local, 'remote': remote, 'upstream': upstream}
    return {'status': 'up-to-date', 'local': local}


def is_tree_clean(repo_root=_REPO_ROOT):
    out, _ = _git(repo_root, ['status', '--porcelain'])
    return out is not None and out == ''


def perform_update(repo_root=_REPO_ROOT):
    """Baixa e aplica com fast-forward. Retorna (ok, mensagem)."""
    if not os.path.isdir(os.path.join(repo_root, '.git')):
        return False, 'cópia sem git: atualização automática indisponível'
    if not is_tree_clean(repo_root):
        return False, ('há alterações locais não salvas; faça backup ou '
                       'descarte antes de atualizar')
    fetched, error = _git(repo_root, ['fetch', 'origin'])
    if fetched is None:
        return False, 'falha ao buscar: %s' % error
    upstream = _upstream(repo_root)
    if not upstream:
        return False, 'branch sem upstream configurado'
    merged, error = _git(repo_root, ['merge', '--ff-only', '@{u}'])
    if merged is None:
        return False, ('não é fast-forward (histórico divergiu): %s' % error)
    from .version import get_version
    return True, 'atualizado para %s' % get_version()


def restart_program(repo_root=_REPO_ROOT):
    """Troca o processo atual por uma nova execução do run.py."""
    run_path = os.path.join(repo_root, 'run.py')
    if not os.path.isfile(run_path):
        raise FileNotFoundError('run.py não encontrado para reiniciar')
    os.execv(sys.executable, [sys.executable, run_path])
