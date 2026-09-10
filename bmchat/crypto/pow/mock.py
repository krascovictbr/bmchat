"""MockPoWStrategy — PoW instantâneo para testes.

Retorna um nonce válido sem queimar CPU multi-core. Útil para
suítes de teste que precisam validar fluxo sem esperar segundos.
"""

import hashlib
import time

from .strategy import PoWStrategy


def _pow_value_for_nonce(nonce: int, initial_hash: bytes) -> int:
    """Calcula pow_value para um nonce candidato (double SHA512)."""
    buf = nonce.to_bytes(8, "big") + initial_hash
    inner = hashlib.sha512(buf)
    h = hashlib.sha512(inner.digest())
    return int.from_bytes(h.digest()[:8], "big")


class MockPoWStrategy(PoWStrategy):
    """Strategy mockada: resolve PoW de forma determinística e rápida.

    - Tenta encontrar nonce válido até ``max_tries`` (padrão 500k) de forma
      single-threaded; com target de teste (2**52) encontra em <5k tentativas.
    - Se não encontrar, levanta RuntimeError por padrão (seguro: nunca retorna
      nonce inválido em produção). Para compatibilidade com testes legados
      que forçavam target real, ``fast_return_zero=True`` pode ser opt-in para
      retornar start_nonce (inválido) mas deve ser usado só em stubs.
    - Mantém assinatura compatível com StandardPoWStrategy.
    """

    def __init__(self, max_tries: int = 500_000, fast_return_zero: bool = False):
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
            raise ValueError("initial_hash deve ter 64 bytes")
        nonce = start_nonce
        tries = 0
        begin = time.time()
        while tries < self.max_tries:
            if stop_event is not None and stop_event.is_set():
                raise RuntimeError("proof of work interrompido")
            if _pow_value_for_nonce(nonce, initial_hash) <= target:
                self.tried = tries + 1
                if progress_cb:
                    progress_cb(tries + 1, (tries + 1) / max(time.time() - begin, 1e-6))
                return nonce
            nonce += 1
            tries += 1
            if progress_cb and tries % 8192 == 0:
                elapsed = max(time.time() - begin, 1e-6)
                progress_cb(tries, tries / elapsed)
        self.tried = tries
        if self.fast_return_zero:
            # Opt-in legado: retorna nonce inválido para não quebrar stub antigo
            if progress_cb:
                progress_cb(tries, 0.0)
            return start_nonce
        raise RuntimeError("mock: não encontrou nonce em %d tentativas (target=%r)" % (self.max_tries, target))

    def get_difficulty(self) -> int:
        return 0
