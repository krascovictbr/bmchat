"""StandardPoWStrategy — implementação real com múltiplos processos.

Reutiliza a lógica paralela de ``PowExecutor`` (ProcessPoolExecutor
com step 1<<20 e polling 0.4s) para resolver PoW em produção.
"""
import hashlib
import os
import time
from concurrent.futures import ProcessPoolExecutor

from .strategy import PoWStrategy


def _search_range(args):
    """Função worker executada nos processos filhos."""
    initial_hash, target, start, budget = args
    buf = bytearray(72)
    buf[8:72] = initial_hash
    done = start
    end = start + budget
    while done < end:
        buf[0:8] = done.to_bytes(8, 'big')
        m = hashlib.sha512(buf)
        h = hashlib.sha512(m.digest())
        if int.from_bytes(h.digest()[:8], 'big') <= target:
            return done, done - start
        done += 1
    return None, budget


class StandardPoWStrategy(PoWStrategy):
    """Strategy padrão que usa múltiplos processos.

    Args:
        workers: número de processos. ``None`` usa ``max(2, cpu_count)``.
        threads: alias para workers (compatibilidade).
    """

    def __init__(self, workers: int | None = None, threads: int | None = None):
        # threads é alias pedido no prompt
        effective = workers if workers is not None else threads
        self.workers = effective or max(2, os.cpu_count() or 2)
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
        step = 1 << 20
        started = start_nonce
        futures: dict = {}
        self.tried = 0
        begin = time.time()
        pool = ProcessPoolExecutor(max_workers=self.workers)
        try:
            started = self._seed_futures(pool, futures, initial_hash, target, started, step)
            while futures:
                if stop_event is not None and stop_event.is_set():
                    break
                found = self._poll_futures(pool, futures, initial_hash, target, step, begin, progress_cb, stop_event)
                if found is not None:
                    return found
        finally:
            for remaining in list(futures):
                remaining.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
        raise RuntimeError('proof of work não concluído')

    def get_difficulty(self) -> int:
        return self.workers

    # Interna — mantida compatível com PowExecutor para testes que mockam
    def _seed_futures(self, pool, futures, initial_hash, target, started, step):
        for _ in range(self.workers):
            future = pool.submit(_search_range, (initial_hash, target, started, step))
            futures[future] = started
            started += step
        return started

    def _poll_futures(self, pool, futures, initial_hash, target, step, begin, progress_cb, stop_event):
        import concurrent.futures
        done, _pending = concurrent.futures.wait(
            futures.keys(), timeout=0.4, return_when=concurrent.futures.FIRST_COMPLETED
        )
        for future in done:
            start = futures.pop(future)
            nonce, tried = future.result()
            self.tried += tried
            if nonce is not None:
                for remaining in futures:
                    remaining.cancel()
                if progress_cb is not None:
                    progress_cb(self.tried, self._rate(begin))
                return nonce
            next_start = start + step
            new_future = pool.submit(_search_range, (initial_hash, target, next_start, step))
            futures[new_future] = next_start
        if progress_cb is not None and self.tried > 0:
            progress_cb(self.tried, self._rate(begin))
        return None

    def _rate(self, begin):
        elapsed = max(time.time() - begin, 1e-6)
        return self.tried / elapsed
