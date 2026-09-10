"""Atualização rolling release via ``git pull``.

Fluxo: busca do remoto -> compara com o upstream -> avisa o usuário ->
aplica com ``git merge --ff-only @{u}`` (equivale a ``git pull --ff-only``:
nunca cria commit de merge nem toca em trabalho local) -> reinicia o
programa no mesmo interpretador.

Segurança declarada (M8): NÃO há verificação de assinatura de commit
(verify-commit) e NÃO há pin de commit/tag. Qualquer commit alcançável
em ``origin/rolling-release`` é aplicado após confirmação do usuário.
O diálogo de confirmação (``App._update_offer_text``) mantém o aviso
explícito de que o código remoto será executado ao reiniciar e que só
se deve atualizar a partir de fontes confiáveis.

Auto-apply (ver ``App._auto_update_check``): com opt-in ligado
(``auto_update=1``) e árvore limpa, o check de startup/periódico aplica
sozinho em worker e reinicia; qualquer outra coisa (árvore suja,
diverged, sem upstream, opt-out) = não toca, só avisa.
"""

import json
import os
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from .version import _REPO_ROOT

#: Commits mostrados na prévia do diálogo de confirmação.
PREVIEW_LIMIT = 10
#: Timeout curto da busca só-leitura de ``check_for_updates``.
CHECK_FETCH_TIMEOUT = 15
#: Timeout da busca de ``perform_update`` (vai aplicar em seguida).
UPDATE_FETCH_TIMEOUT = 60
#: Setting do opt-out de atualização automática (``1`` = ligada).
AUTO_UPDATE_KEY = "auto_update"
#: Padrão: atualização automática ligada.
AUTO_UPDATE_DEFAULT = 1
#: Setting do intervalo da checagem periódica em horas (``0`` desliga o
#: periódico, mas nunca o check de startup).
UPDATE_INTERVAL_KEY = "update_interval_h"
#: Padrão: checagem periódica a cada 6 horas.
UPDATE_INTERVAL_DEFAULT_H = 6
#: Setting do rascunho pendente (JSON com texto + conversa aberta).
PENDING_DRAFT_KEY = "pending_draft"
#: Texto placeholder do campo de entrada (não conta como rascunho).
DRAFT_PLACEHOLDER = "Mensagem"


def _git(repo_root: str, args: List[str], timeout: int = 60) -> Tuple[Optional[str], str]:
    try:
        completed = subprocess.run(
            ["git", "-C", repo_root] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return None, str(exc)
    out = completed.stdout.decode("utf-8", "replace").strip()
    err = completed.stderr.decode("utf-8", "replace").strip()
    if completed.returncode != 0:
        return None, err or out or "git falhou"
    return out, ""


def _upstream(repo_root: str) -> Optional[str]:
    out, _ = _git(repo_root, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    return out or None


def ensure_upstream(repo_root: str = _REPO_ROOT) -> Dict[str, Any]:
    """Liga o ramo atual ao ``origin/rolling-release`` quando possível.

    Se já há ``@{u}``, não faz nada (``fixed=False``). Se não há e
    ``origin/rolling-release`` existe no remoto local, configura com
    ``git branch --set-upstream-to`` e retorna ``fixed=True``. Nunca
    altera arquivos nem aplica atualização; nunca levanta exceção.
    """
    try:
        if not os.path.isdir(os.path.join(repo_root, ".git")):
            return {"fixed": False, "upstream": None}
        current = _upstream(repo_root)
        if current:
            return {"fixed": False, "upstream": current}
        tracked, _ = _git(repo_root, ["rev-parse", "--verify", "origin/rolling-release"])
        if tracked is None:
            return {"fixed": False, "upstream": None}
        branch, _ = _git(repo_root, ["rev-parse", "--abbrev-ref", "HEAD"])
        if not branch or branch == "HEAD":
            return {"fixed": False, "upstream": None}
        linked, _ = _git(repo_root, ["branch", "--set-upstream-to=origin/rolling-release"])
        if linked is None:
            return {"fixed": False, "upstream": None}
        new_upstream = _upstream(repo_root)
        if not new_upstream:
            return {"fixed": False, "upstream": None}
        return {"fixed": True, "upstream": new_upstream}
    except Exception:
        return {"fixed": False, "upstream": None}


def _resolve_missing_upstream(repo_root: str) -> Tuple[Optional[str], bool]:
    """Tenta ligar o ramo sozinho; retorna (upstream, fixed). Nunca falha."""
    try:
        fix = ensure_upstream(repo_root)
    except Exception:
        return None, False
    if not isinstance(fix, dict) or not fix.get("fixed"):
        return None, False
    upstream = fix.get("upstream") or _upstream(repo_root)
    if not upstream:
        return None, False
    return upstream, True


def _tip_revisions(repo_root: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (local, remote) SHAs, or (None, None) when unknown."""
    local, _ = _git(repo_root, ["rev-parse", "HEAD"])
    remote, _ = _git(repo_root, ["rev-parse", "@{u}"])
    if not local or not remote:
        return None, None
    return local, remote


def _count_ahead_behind(repo_root: str) -> Tuple[int, int]:
    """Return (behind, ahead) commit counts, tolerant to bad output."""
    behind, _ = _git(repo_root, ["rev-list", "--count", "HEAD..@{u}"])
    ahead, _ = _git(repo_root, ["rev-list", "--count", "@{u}..HEAD"])
    try:
        return int(behind or 0), int(ahead or 0)
    except ValueError:
        return 0, 0


def _divergence_result(local: str, remote: str, upstream: str, behind: int, ahead: int) -> Dict[str, Any]:
    local_short = local[:7]
    remote_short = remote[:7]
    if ahead and behind:
        return {
            "status": "diverged",
            "behind": behind,
            "ahead": ahead,
            "local": local,
            "remote": remote,
            "local_short": local_short,
            "remote_short": remote_short,
            "upstream": upstream,
        }
    if behind:
        return {
            "status": "update-available",
            "behind": behind,
            "local": local,
            "remote": remote,
            "local_short": local_short,
            "remote_short": remote_short,
            "upstream": upstream,
        }
    if ahead:
        return {
            "status": "ahead",
            "behind": 0,
            "ahead": ahead,
            "local": local,
            "remote": remote,
            "local_short": local_short,
            "remote_short": remote_short,
            "upstream": upstream,
        }
    return {"status": "up-to-date", "local": local, "local_short": local_short}


def _preview_commits(repo_root: str, limit: int = PREVIEW_LIMIT) -> List[str]:
    """Lista ``git log HEAD..@{u} --oneline`` (só leitura, sem rede)."""
    out, _ = _git(repo_root, ["log", "HEAD..@{u}", "--oneline", "-n", str(limit)], timeout=15)
    if not out:
        return []
    return [line for line in out.splitlines() if line.strip()]


def get_update_preview(repo_root: str = _REPO_ROOT, limit: int = PREVIEW_LIMIT) -> Dict[str, Any]:
    """Prévia do que seria aplicado (só leitura: sem fetch, sem merge).

    Retorna chaves ``upstream``/``behind``/``ahead``/``local``/``remote``/
    ``local_short``/``remote_short``/``commits`` ou ``{'status': ...}``
    quando não dá para determinar.
    """
    if not os.path.isdir(os.path.join(repo_root, ".git")):
        return {"status": "no-repo", "commits": []}
    upstream = _upstream(repo_root)
    if not upstream:
        upstream, _fixed = _resolve_missing_upstream(repo_root)
        if not upstream:
            return {"status": "no-upstream", "commits": []}
    local, remote = _tip_revisions(repo_root)
    if local is None or remote is None:
        return {"status": "unknown", "commits": []}
    behind, ahead = _count_ahead_behind(repo_root)
    preview: Dict[str, Any] = _divergence_result(local, remote, upstream, behind, ahead)
    preview["commits"] = _preview_commits(repo_root, limit) if behind else []
    return preview


def _short_detail(detail: Any, limit: int = 300) -> str:
    text = str(detail or "").strip().replace("\n", " ")
    if len(text) > limit:
        return text[:limit].rstrip() + "…"
    return text


def describe_update_result(result: Dict[str, Any]) -> str:
    """Mensagem PT-BR com ação para o ``status`` de ``check_for_updates``."""
    status = result.get("status")
    if status == "up-to-date":
        return "Já está na versão mais nova."
    if status == "no-repo":
        return "Cópia sem git: atualização automática indisponível."
    if status == "diverged":
        return (
            "Histórico local divergiu do remoto (%(ahead)d à frente, "
            "%(behind)d atrás); a atualização foi pausada para proteger "
            "seu trabalho. Guarde ou descarte suas alterações e tente de novo."
            % {"ahead": result.get("ahead", 0), "behind": result.get("behind", 0)}
        )
    if status == "ahead":
        return "Sua cópia está à frente do remoto (%d commit(s)); nada a atualizar." % (result.get("ahead", 0) or 0)
    if status == "no-upstream":
        return "Não foi possível ligar este ramo às atualizações automáticas. Tente de novo mais tarde."
    if status == "fetch-failed":
        detail = _short_detail(result.get("error"))
        text = "Falha de rede ao buscar a atualização."
        if detail:
            text += " (%s)" % detail
        return text + " Verifique sua conexão e tente de novo."
    detail = _short_detail(result.get("error") or result.get("status"))
    text = "Não foi possível verificar."
    if detail:
        text += " %s" % detail
    return text + " Tente de novo mais tarde."


def check_for_updates(repo_root: str = _REPO_ROOT, fetch_timeout: int = CHECK_FETCH_TIMEOUT) -> Dict[str, Any]:
    """Verifica se há commits novos no upstream.

    Tenta ligar o ramo a ``origin/rolling-release`` sozinho (só config
    do git, sem aplicar nada) antes de concluir ``no-upstream``. Nunca
    altera arquivos de trabalho.
    """
    if not os.path.isdir(os.path.join(repo_root, ".git")):
        return {"status": "no-repo"}
    fetched, error = _git(repo_root, ["fetch", "origin"], timeout=fetch_timeout)
    if fetched is None:
        return {"status": "fetch-failed", "error": error}
    upstream = _upstream(repo_root)
    upstream_fixed = False
    if not upstream:
        upstream, upstream_fixed = _resolve_missing_upstream(repo_root)
        if not upstream:
            return {"status": "no-upstream"}
    local, remote = _tip_revisions(repo_root)
    if local is None or remote is None:
        return {"status": "unknown"}
    if local == remote:
        result: Dict[str, Any] = {"status": "up-to-date", "local": local, "local_short": local[:7]}
    else:
        behind, ahead = _count_ahead_behind(repo_root)
        result = _divergence_result(local, remote, upstream, behind, ahead)
        if behind:
            result["commits"] = _preview_commits(repo_root)
    if upstream_fixed:
        result["upstream"] = upstream
        result["upstream_fixed"] = True
    return result


def is_tree_clean(repo_root: str = _REPO_ROOT) -> bool:
    out, _ = _git(repo_root, ["status", "--porcelain"])
    return out is not None and out == ""


def parse_auto_update(raw: Any, default: int = AUTO_UPDATE_DEFAULT) -> int:
    """Normaliza o setting ``auto_update`` para 0/1 (tolerante a texto)."""
    try:
        if raw is None:
            return default
        if isinstance(raw, bool):
            return 1 if raw else 0
        if isinstance(raw, (int, float)):
            return 1 if int(raw) != 0 else 0
        text = str(raw).strip().lower()
        if not text:
            return default
        if text in ("1", "true", "yes", "on", "sim", "s"):
            return 1
        if text in ("0", "false", "no", "off", "nao", "não", "n"):
            return 0
    except Exception:
        pass
    return default


def parse_update_interval_h(raw: Any, default: float = UPDATE_INTERVAL_DEFAULT_H) -> float:
    """Normaliza ``update_interval_h`` (horas; 0 desliga só o periódico)."""
    try:
        if raw is None or isinstance(raw, bool):
            return default
        text = str(raw).strip().replace(",", ".")
        if not text:
            return default
        value = float(text)
    except (TypeError, ValueError):
        return default
    except Exception:
        return default
    if value < 0:
        return default
    return value


def is_draft_text(text: Any) -> bool:
    """True se há rascunho real (placeholder ``Mensagem`` não conta)."""
    try:
        stripped = str(text or "").strip()
    except Exception:
        return False
    return bool(stripped) and stripped != DRAFT_PLACEHOLDER


def build_pending_draft(text: Any, kind: Any, address: Any) -> Optional[Dict[str, Any]]:
    """Monta o rascunho a salvar ou None (sem texto real ou sem conversa)."""
    if not is_draft_text(text):
        return None
    try:
        addr = str(address or "").strip()
    except Exception:
        return None
    if not addr:
        return None
    try:
        body = str(text)
    except Exception:
        return None
    try:
        conv_kind = str(kind) if kind is not None else None
    except Exception:
        conv_kind = None
    return {"text": body, "kind": conv_kind, "address": addr}


def save_pending_draft(db: Any, text: Any, kind: Any, address: Any) -> Optional[Dict[str, Any]]:
    """Salva (ou limpa, se não há rascunho) o draft nos settings. Nunca falha."""
    draft = build_pending_draft(text, kind, address)
    try:
        if draft is None:
            db.set_setting(PENDING_DRAFT_KEY, "")
        else:
            db.set_setting(PENDING_DRAFT_KEY, json.dumps(draft, ensure_ascii=False))
    except Exception:
        pass
    return draft


def load_pending_draft(db: Any) -> Optional[Dict[str, Any]]:
    """Lê o rascunho salvo ou None (ausente/inválido/placeholder). Nunca falha."""
    try:
        raw = db.get_setting(PENDING_DRAFT_KEY, "")
    except Exception:
        return None
    if not raw:
        return None
    if isinstance(raw, dict):
        data = raw
    else:
        try:
            data = json.loads(raw)
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    return build_pending_draft(data.get("text"), data.get("kind"), data.get("address"))


def clear_pending_draft(db: Any) -> None:
    """Apaga o rascunho salvo (uso único após restaurar). Nunca falha."""
    try:
        db.set_setting(PENDING_DRAFT_KEY, "")
    except Exception:
        pass


def describe_dirty_hold(behind: Any) -> str:
    """Status 1×/sessão quando há update mas a árvore está suja (sem terminal)."""
    try:
        count = int(behind or 0)
    except (TypeError, ValueError):
        count = 0
    except Exception:
        count = 0
    return "Atualização %d disponível — pausada por mudanças locais" % count


def should_auto_apply(result: Any, auto_enabled: Any, tree_clean: Any) -> bool:
    """True só para fast-forward limpo do upstream com opt-in ligado.

    Qualquer outra coisa (diverged, sujo, opt-out) = não toca, só avisa.
    """
    try:
        if not auto_enabled or not tree_clean:
            return False
        return isinstance(result, dict) and result.get("status") == "update-available"
    except Exception:
        return False


def _notify_progress(progress: Optional[Callable[[str], None]], phase: str) -> None:
    """Chama o callback de progresso sem nunca quebrar a atualização."""
    if progress is None:
        return
    try:
        progress(phase)
    except Exception:
        pass


def perform_update(
    repo_root: str = _REPO_ROOT,
    fetch_timeout: int = UPDATE_FETCH_TIMEOUT,
    progress: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Baixa e aplica com fast-forward. Retorna (ok, mensagem).

    Sem verify-commit e sem pin (ver docstring do módulo): aplica o
    ``@{u}`` após ``fetch`` + árvore limpa, com confirmação prévia na
    GUI. ``progress`` (opcional) recebe ``'fetch'`` antes de baixar e
    ``'merge'`` antes de aplicar; erros nele são ignorados.
    """
    if not os.path.isdir(os.path.join(repo_root, ".git")):
        return False, ("cópia sem git: atualização automática indisponível nesta instalação.")
    if not is_tree_clean(repo_root):
        return False, (
            "há alterações locais não salvas; guarde ou descarte-as "
            "antes de atualizar. A atualização foi cancelada para "
            "proteger seu trabalho"
        )
    _notify_progress(progress, "fetch")
    fetched, error = _git(repo_root, ["fetch", "origin"], timeout=fetch_timeout)
    if fetched is None:
        return False, ("falha ao buscar atualização (%s). Verifique sua conexão e tente de novo" % _short_detail(error))
    upstream = _upstream(repo_root)
    if not upstream:
        upstream, _fixed = _resolve_missing_upstream(repo_root)
        if not upstream:
            return False, ("não foi possível ligar este ramo às atualizações automáticas. Tente de novo mais tarde.")
    _notify_progress(progress, "merge")
    merged, error = _git(repo_root, ["merge", "--ff-only", "@{u}"])
    if merged is None:
        return False, (
            "não foi possível aplicar (histórico local divergiu do "
            "remoto, sem fast-forward): %s. Guarde suas alterações "
            "e tente de novo" % _short_detail(error)
        )
    from . import version as _version

    try:
        _version.get_version.cache_clear()  # type: ignore[attr-defined]
    except Exception:
        pass
    return True, "atualizado para %s. O programa será reiniciado" % _version.get_version()


def restart_program(repo_root: str = _REPO_ROOT, pre_exec: Optional[Callable[[], None]] = None) -> None:
    """Troca o processo atual por uma nova execução do run.py.

    ``pre_exec`` (ex.: parada limpa do cliente: join das threads e remoção
    do ``bmchat.lock``) roda antes do ``execv``; erros nele são ignorados
    para não impedir o reinício. ``argv``/ambiente são preservados
    (``os.execv``).
    """
    if pre_exec is not None:
        try:
            pre_exec()
        except Exception:
            pass
    run_path = os.path.join(repo_root, "run.py")
    if not os.path.isfile(run_path):
        raise FileNotFoundError("run.py não encontrado para reiniciar")
    os.execv(sys.executable, [sys.executable, run_path] + sys.argv[1:])
