"""Pacote PoW com Strategy Pattern + compatibilidade legada.

Exposição pública:

- Funções utilitárias: ``calculate_target``, ``pow_value``,
  ``is_proof_of_work_sufficient``, ``initial_hash_of``,
  ``find_nonce_single_threaded``, ``search_range``
- Classe legada: ``PowExecutor`` (alias de ``StandardPoWStrategy`` + wrapper)
- Strategies novas: ``PoWStrategy``, ``StandardPoWStrategy``, ``MockPoWStrategy``
"""
import hashlib
import struct
import time

from ...util.hashing import sha512

# Re-export strategies
from .strategy import PoWStrategy
from .standard import StandardPoWStrategy
from .mock import MockPoWStrategy
from .standard import _search_range as search_range  # compat

MIN_NONCE_TRIALS_PER_BYTE = 1000
MIN_PAYLOAD_LENGTH_EXTRA_BYTES = 1000
MIN_TTL = 300


def calculate_target(nonce_trials_per_byte, payload_length_extra_bytes, object_len, ttl):
    if nonce_trials_per_byte < MIN_NONCE_TRIALS_PER_BYTE:
        nonce_trials_per_byte = MIN_NONCE_TRIALS_PER_BYTE
    if payload_length_extra_bytes < MIN_PAYLOAD_LENGTH_EXTRA_BYTES:
        payload_length_extra_bytes = MIN_PAYLOAD_LENGTH_EXTRA_BYTES
    if ttl < MIN_TTL:
        ttl = MIN_TTL
    denominator = (
        nonce_trials_per_byte
        * (object_len + payload_length_extra_bytes
           + ((ttl * (object_len + payload_length_extra_bytes)) / (2 ** 16)))
    )
    return (2 ** 64) // int(denominator)


def pow_value(object_bytes):
    inner = sha512(object_bytes[8:])
    return int.from_bytes(
        hashlib.sha512(hashlib.sha512(
            object_bytes[:8] + inner).digest()).digest()[:8], 'big')


def is_proof_of_work_sufficient(
        object_bytes, nonce_trials_per_byte=0, payload_length_extra_bytes=0,
        recv_time=0):
    end_of_life, = struct.unpack('>Q', object_bytes[8:16])
    ttl = end_of_life - (int(recv_time) if recv_time else int(time.time()))
    if ttl < MIN_TTL:
        ttl = MIN_TTL
    return pow_value(object_bytes) <= calculate_target(
        nonce_trials_per_byte, payload_length_extra_bytes,
        len(object_bytes), ttl)


def initial_hash_of(object_without_nonce):
    return sha512(object_without_nonce)


# search_range já exposto via import do standard


class PowExecutor:
    """Wrapper legado em torno de StandardPoWStrategy.

    Mantém API antiga (PowExecutor(workers, progress_cb, stop_event).run(...))
    delegando internamente ao Strategy. Preserva compatibilidade com testes
    e com ``client.py`` até migração completa para injeção.
    """

    def __init__(self, workers=None, progress_cb=None, stop_event=None):
        import os
        self.workers = workers or max(2, os.cpu_count() or 2)
        self.progress_cb = progress_cb
        self.stop_event = stop_event
        self.tried = 0
        self._strategy = StandardPoWStrategy(workers=self.workers)

    def run(self, initial_hash, target, start_nonce=0):
        # Delega e sincroniza campo tried para compat
        def _wrapped_progress(tried, rate):
            self.tried = tried
            if self.progress_cb:
                self.progress_cb(tried, rate)

        result = self._strategy.solve(
            initial_hash, target,
            start_nonce=start_nonce,
            progress_cb=_wrapped_progress if self.progress_cb else None,
            stop_event=self.stop_event,
        )
        self.tried = getattr(self._strategy, 'tried', self.tried)
        return result

    # Métodos internos delegados para quem mocka PowExecutor
    def _seed_futures(self, *a, **k):
        return self._strategy._seed_futures(*a, **k)

    def _poll_futures(self, *a, **k):
        return self._strategy._poll_futures(*a, **k)

    def _rate(self, begin):
        return self._strategy._rate(begin)


def find_nonce_single_threaded(initial_hash, target, start=0, stop_event=None):
    nonce = start
    while True:
        if stop_event is not None and stop_event.is_set():
            raise RuntimeError('proof of work interrompido')
        buf = initial_hash
        candidate = nonce.to_bytes(8, 'big') + buf
        m = hashlib.sha512(candidate)
        h = hashlib.sha512(m.digest())
        if int.from_bytes(h.digest()[:8], 'big') <= target:
            return nonce
        nonce += 1


__all__ = [
    'PoWStrategy', 'StandardPoWStrategy', 'MockPoWStrategy',
    'PowExecutor', 'calculate_target', 'pow_value',
    'is_proof_of_work_sufficient', 'initial_hash_of',
    'search_range', 'find_nonce_single_threaded',
    'MIN_NONCE_TRIALS_PER_BYTE', 'MIN_PAYLOAD_LENGTH_EXTRA_BYTES', 'MIN_TTL',
]
