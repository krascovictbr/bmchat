"""StandardPoWStrategy — implementação real com múltiplos processos.

Reutiliza a lógica paralela de ``PowExecutor`` (ProcessPoolExecutor
com step 1<<20 e polling 0.4s) para resolver PoW em produção.
"""

import hashlib
import multiprocessing
import os
import threading
import time
from concurrent.futures import ProcessPoolExecutor

from .strategy import PoWStrategy

# P-CRIT-02: limita PoW concorrente globalmente (fork-bomb)
_pow_global_sem = threading.Semaphore(3)
_global_pow_pool = None
_global_pow_pool_workers = None
_global_pow_pool_lock = threading.Lock()
_NONCE_MASK = (1 << 64) - 1
_NONCE_CHECK_INTERVAL = 1024


def _get_global_pow_pool(workers):
    global _global_pow_pool, _global_pow_pool_workers
    with _global_pow_pool_lock:
        if _global_pow_pool is None or _global_pow_pool_workers != workers:
            if _global_pow_pool is not None:
                try:
                    _global_pow_pool.shutdown(wait=False, cancel_futures=True)
                    try:
                        inner = getattr(_global_pow_pool, "_pool", None)
                        if inner is not None:
                            inner.terminate()
                    except Exception:
                        pass
                except Exception:
                    pass
            _global_pow_pool = ProcessPoolExecutor(max_workers=workers)
            _global_pow_pool_workers = workers
        return _global_pow_pool


def _terminate_pool(pool):
    try:
        inner = getattr(pool, "_pool", None)
        if inner is not None:
            try:
                inner.terminate()
            except Exception:
                pass
            try:
                inner.join()
            except Exception:
                pass
    except Exception:
        pass


def _search_range(args):
    """Função worker executada nos processos filhos.

    Suporta cancelamento cooperativo via Event herdável (P-CRIT-01) e
    nonce wrap >2**64 (P-ALTO-03). Aceita 4 ou 5-tupla; 5ª é stop_event.
    """
    if len(args) == 5:
        initial_hash, target, start, budget, stop_evt = args
    else:
        initial_hash, target, start, budget = args
        stop_evt = None
    buf = bytearray(72)
    buf[8:72] = initial_hash
    tried = 0
    # P-ALTO-03: wrap nonce em 64 bits para não estourar to_bytes(8)
    while tried < budget:
        if stop_evt is not None and (tried % _NONCE_CHECK_INTERVAL == 0) and stop_evt.is_set():
            return None, tried
        nonce = (start + tried) & _NONCE_MASK
        buf[0:8] = nonce.to_bytes(8, "big")
        m = hashlib.sha512(buf)
        h = hashlib.sha512(m.digest())
        if int.from_bytes(h.digest()[:8], "big") <= target:
            return nonce, tried
        tried += 1
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

    def solve(  # noqa: C901
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
        # P-CRIT-02: limita concorrência global
        acquired = _pow_global_sem.acquire(timeout=30)
        if not acquired:
            raise RuntimeError("limite de PoW concorrente atingido")
        # P-CRIT-01: cria Event herdável para filhos
        mp_stop = None
        if stop_event is not None:
            try:
                # Se já é mp.Event (tem _cond ou é multiprocessing.Event), usa direto
                if hasattr(stop_event, "_cond") or "multiprocessing" in type(stop_event).__module__:
                    mp_stop = stop_event
                else:
                    mp_stop = multiprocessing.Event()

                    def _bridge():
                        while not stop_event.is_set():
                            if mp_stop.is_set():
                                break
                            time.sleep(0.05)
                            if stop_event.is_set():
                                try:
                                    mp_stop.set()
                                except Exception:
                                    pass
                                break

                    threading.Thread(target=_bridge, daemon=True, name="pow-bridge").start()
            except Exception:
                mp_stop = stop_event
        step = 1 << 20
        # P-ALTO-03: clamp start_nonce em 64 bits
        started = start_nonce & _NONCE_MASK
        futures: dict = {}
        self.tried = 0
        self._started = started  # próximo nonce livre (evita duplicação)
        begin = time.time()
        # P-CRIT-02: pool singleton opcional, mas mantém lifecycle limitado
        # Usa per-solve pool para isolamento; singleton gerenciado em _get_global_pow_pool
        # Por padrão cria novo, mas se quiser reuso global descomente abaixo:
        # pool = _get_global_pow_pool(self.workers)
        # Para mitigar fork-bomb, o semáforo já limita; pool per-solve é isolado e terminável
        pool = ProcessPoolExecutor(max_workers=self.workers)
        pool_is_global = False
        try:
            self._started = self._seed_futures(pool, futures, initial_hash, target, started, step, mp_stop)
            while futures:
                if stop_event is not None and stop_event.is_set():
                    break
                if mp_stop is not None and mp_stop.is_set():
                    break
                found = self._poll_futures(
                    pool, futures, initial_hash, target, step, begin, progress_cb, stop_event, mp_stop
                )
                if found is not None:
                    return found
        finally:
            for remaining in list(futures):
                try:
                    remaining.cancel()
                except Exception:
                    pass
            # P-CRIT-01: aborta filhos via terminate quando cancelado
            if (stop_event is not None and stop_event.is_set()) or (mp_stop is not None and mp_stop.is_set()):
                _terminate_pool(pool)
            if not pool_is_global:
                try:
                    pool.shutdown(wait=False, cancel_futures=True)
                    # Tenta terminate também para garantir morte rápida
                    _terminate_pool(pool)
                except Exception:
                    pass
            try:
                _pow_global_sem.release()
            except Exception:
                pass
        raise RuntimeError("proof of work não concluído")

    def get_difficulty(self) -> int:
        return self.workers

    # Interna — mantida compatível com PowExecutor para testes que mockam
    def _seed_futures(self, pool, futures, initial_hash, target, started, step, mp_stop=None):  # noqa: E501
        for _ in range(self.workers):
            args = (initial_hash, target, started, step, mp_stop) if mp_stop is not None else (initial_hash, target, started, step)  # noqa: E501
            future = pool.submit(_search_range, args)
            futures[future] = started
            started = (started + step) & _NONCE_MASK
        return started

    def _poll_futures(  # noqa: C901
        self, pool, futures, initial_hash, target, step, begin, progress_cb, stop_event, mp_stop=None
    ):
        import concurrent.futures

        done, _pending = concurrent.futures.wait(
            futures.keys(), timeout=0.4, return_when=concurrent.futures.FIRST_COMPLETED
        )
        for future in done:
            start = futures.pop(future)
            try:
                nonce, tried = future.result()
            except Exception:
                tried = 0
                nonce = None
            self.tried += tried
            if nonce is not None:
                for remaining in futures:
                    try:
                        remaining.cancel()
                    except Exception:
                        pass
                if progress_cb is not None:
                    progress_cb(self.tried, self._rate(begin))
                return nonce
            # Aloca próximo range sequencial (não start+step duplicado) com wrap
            try:
                next_start = self._started
                self._started = (self._started + step) & _NONCE_MASK
            except AttributeError:
                next_start = (start + step) & _NONCE_MASK
            args = (initial_hash, target, next_start, step, mp_stop) if mp_stop is not None else (initial_hash, target, next_start, step)  # noqa: E501
            new_future = pool.submit(_search_range, args)
            futures[new_future] = next_start
        if progress_cb is not None and self.tried > 0:
            progress_cb(self.tried, self._rate(begin))
        return None

    def _rate(self, begin):
        elapsed = max(time.time() - begin, 1e-6)
        return self.tried / elapsed
