"""Command Pattern — base.

Encapsula ações da interface como objetos, permitindo
desacoplamento, logging, validação e futuro Undo/Redo.
"""
from abc import ABC, abstractmethod
from typing import Any


class Command(ABC):
    """Interface base para todos os comandos da GUI."""

    # Marque True para comandos que contêm dados sensíveis (ex.: chaves privadas)
    # e não devem ser mantidos em histórico em claro.
    sensitive: bool = False

    def __init__(self, client):
        self.client = client
        self._executed = False
        self._result: Any = None
        self._error: str | None = None

    @abstractmethod
    def execute(self) -> tuple[str, Any]:
        """Executa o comando. Retorna (status, payload/error)."""
        raise NotImplementedError

    def undo(self) -> tuple[str, Any]:
        """Desfaz o comando (opcional). Padrão: não suportado."""
        return 'unsupported', 'undo não implementado para %s' % self.__class__.__name__

    def can_execute(self) -> tuple[bool, str | None]:
        """Valida se comando pode ser executado. Retorna (ok, motivo)."""
        return True, None

    @property
    def executed(self) -> bool:
        return self._executed

    @property
    def result(self) -> Any:
        return self._result

    @property
    def error(self) -> str | None:
        return self._error

    def __repr__(self) -> str:
        return '<%s executed=%s>' % (self.__class__.__name__, self._executed)


class CommandHistory:
    """Invoker simples com histórico para Undo/Redo futuro."""

    def __init__(self, limit: int = 100):
        self._history: list[Command] = []
        self._redo: list[Command] = []
        self.limit = limit

    def execute(self, cmd: Command) -> tuple[str, Any]:
        ok, reason = cmd.can_execute()
        if not ok:
            return 'invalid', reason
        status, payload = cmd.execute()
        # Segurança: comandos sensíveis não permanecem em histórico com payload em claro
        if getattr(cmd, 'sensitive', False):
            # Não armazena resultado sensível; limpa imediatamente
            try:
                cmd._result = None  # type: ignore[attr-defined]
                cmd._error = None  # type: ignore[attr-defined]
            except Exception:
                pass
            # Não registra no histórico para evitar leak de chaves privadas
            self._redo.clear()
            return status, payload
        # Só registra se executou (mesmo que erro de negócio, registra para trilha)
        self._history.append(cmd)
        if len(self._history) > self.limit:
            self._history.pop(0)
        self._redo.clear()
        return status, payload

    def undo(self) -> tuple[str, Any]:
        if not self._history:
            return 'empty', 'nada para desfazer'
        cmd = self._history.pop()
        status, payload = cmd.undo()
        if status not in ('unsupported', 'error'):
            self._redo.append(cmd)
        else:
            # Se não suporta undo, devolve ao histórico
            self._history.append(cmd)
        return status, payload

    def redo(self) -> tuple[str, Any]:
        if not self._redo:
            return 'empty', 'nada para refazer'
        cmd = self._redo.pop()
        return self.execute(cmd)

    def clear(self):
        self._history.clear()
        self._redo.clear()

    @property
    def history(self):
        return list(self._history)
