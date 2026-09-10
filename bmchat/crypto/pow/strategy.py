"""Strategy Pattern para Proof-of-Work.

Define a interface abstrata PoWStrategy que desacopla a lógica de
cálculo do PoW do cliente. Permite trocar implementações
(Standard, Mock, etc.) via injeção de dependência sem alterar o
Client.
"""

from abc import ABC, abstractmethod
from typing import Callable, Optional


class PoWStrategy(ABC):
    """Interface Strategy para cálculo de Proof-of-Work.

    Implementações devem resolver o quebra-cabeça criptográfico
    e retornar o nonce que satisfaz ``pow_value <= target``.
    """

    @abstractmethod
    def solve(
        self,
        initial_hash: bytes,
        target: int,
        *,
        start_nonce: int = 0,
        progress_cb: Optional[Callable[[int, float], None]] = None,
        stop_event=None,
    ) -> int:
        """Resolve o PoW e retorna o nonce vencedor.

        Args:
            initial_hash: hash inicial de 64 bytes (sha512 do objeto sem nonce).
            target: meta numérica (quanto menor, mais difícil).
            start_nonce: nonce inicial para busca.
            progress_cb: callback(tried, rate) opcional para UI.
            stop_event: threading.Event para cancelamento cooperativo.

        Returns:
            Nonce (int) que satisfaz o target.

        Raises:
            RuntimeError se cancelado ou não concluído.
            ValueError se initial_hash inválido.
        """
        raise NotImplementedError

    def get_difficulty(self) -> int:
        """Retorna indicador de dificuldade (opcional, para métricas)."""
        return 0

    # Compatibilidade com prompt original: alias solve(data, target)
    # onde data == initial_hash. Mantido para facilitar testes.
    def solve_legacy(self, data: bytes, target: int) -> int:  # pragma: no cover
        return self.solve(data, target)
