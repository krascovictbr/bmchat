"""MockPoWStrategy — PoW instantâneo para testes.

Retorna um nonce válido sem queimar CPU multi-core. Útil para
suítes de teste que precisam validar fluxo sem esperar segundos.
"""
import hashlib
import time

from .strategy import PoWStrategy
from ...util.hashing import sha512


def _pow_value_for_nonce(nonce: int, initial_hash: bytes) -> int:
    buf = nonce.to_bytes(8, 'big') + initial_hash
    inner = hashlib.sha512(buf)
    h = hashlib.sha512(inner.digest())
    return int.from_bytes(h.digest()[:8], 'big')


class MockPoWStrategy(PoWStrategy):
    """Strategy mockada: resolve PoW de forma determinística e rápida.

    Estratégias:
    - Se ``fast=True`` (padrão em testes) tenta até ``max_tries``
      iterações single-threaded e, se não achar, retorna 0
      (útil quando o alvo é forçado grande via ``TARGET=2**52``).
    - Mantém assinatura compatível com StandardPoWStrategy para
      injeção transparente.
    """

    def __init__(self, max_tries: int = 500_000, fast_return_zero: bool = True):
        self.max_tries = max_tries
        self.fast_return_zero = fast_return_zero
        self.tried = 0

    def solve(
        self,
        initial_hash: bytes,
        target: int,
        *,
        start_nonce: int = 0,
        progress_cb=None,
        stop_event=None,
    ) -> int:
        if len(initial_hash) != 64:
            raise ValueError('initial_hash deve ter 64 bytes')
        nonce = start_nonce
        tries = 0
        # Tenta achar nonce real dentro do limite para manter validade
        while tries < self.max_tries:
            if stop_event is not None and stop_event.is_set():
                raise RuntimeError('proof of work interrompido')
            if _pow_value_for_nonce(nonce, initial_hash) <= target:
                if progress_cb:
                    progress_cb(tries + 1, 0.0)
                return nonce
            nonce += 1
            tries += 1
            # Notifica progresso a cada 8192 tentativas
            if progress_cb and tries % 8192 == 0:
                progress_cb(tries, tries / max(time.time() - (time.time() - 0.01), 1e-6))
        # Fallback: para testes com target gigante, retorna start_nonce
        # (com target 2**52 encontra em poucas tentativas; fallback raramente usado)
        if self.fast_return_zero:
            # Garante que não quebra fluxo de teste; chama callback final
            if progress_cb:
                progress_cb(tries, 0.0)
            return start_nonce
        raise RuntimeError('mock: não encontrou nonce em %d tentativas' % self.max_tries)

    def get_difficulty(self) -> int:
        return 0
