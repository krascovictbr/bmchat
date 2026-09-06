"""Versionamento rolling release.

Cada commit é uma versão: CalVer da data do HEAD + distância em commits
+ sha curto (+ '.dirty' se a árvore estiver suja). Sem git (cópia
exportada), cai para ``0.0.0+unknown``.
"""

import datetime
import os
import subprocess

_FALLBACK = '0.0.0+unknown'
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git_output(args):
    try:
        completed = subprocess.run(
            ['git'] + args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10, check=True, cwd=_REPO_ROOT)
    except Exception:
        return None
    return completed.stdout.decode('utf-8', 'replace').strip()


def get_version():
    """Retorna a versão rolling, ex.: ``2026.09.05+r42.g1a2b3c4``."""
    count = _git_output(['rev-list', '--count', 'HEAD'])
    sha = _git_output(['rev-parse', '--short', 'HEAD'])
    if not count or not sha:
        return _FALLBACK
    date = _git_output(['show', '-s', '--format=%cs', 'HEAD'])
    if not date:
        date = datetime.date.today().isoformat()
    dirty = '.dirty' if _git_output(['status', '--porcelain']) else ''
    return '%s+r%s.g%s%s' % (date.replace('-', '.'), count, sha, dirty)


def user_agent_version():
    """Variante segura para o user-agent do protocolo (só [\\w./:;-])."""
    return get_version().replace('+', '.')


__version__ = get_version()
