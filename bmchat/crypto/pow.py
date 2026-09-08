import hashlib
import struct
import time
from concurrent.futures import ProcessPoolExecutor

from ..util.hashing import sha512

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


def search_range(args):
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


class PowExecutor:

    def __init__(self, workers=None, progress_cb=None, stop_event=None):
        import os
        self.workers = workers or max(2, os.cpu_count() or 2)
        self.progress_cb = progress_cb
        self.stop_event = stop_event
        self.tried = 0

    def _seed_futures(self, pool, futures, initial_hash, target,
                      started, step):
        for _ in range(self.workers):
            future = pool.submit(search_range, (
                initial_hash, target, started, step))
            futures[future] = started
            started += step
        return started

    def _poll_futures(self, pool, futures, initial_hash, target, step,
                      begin):
        import concurrent.futures
        done, _pending = concurrent.futures.wait(
            futures.keys(), timeout=0.4,
            return_when=concurrent.futures.FIRST_COMPLETED)
        for future in done:
            start = futures.pop(future)
            nonce, tried = future.result()
            self.tried += tried
            if nonce is not None:
                for remaining in futures:
                    remaining.cancel()
                if self.progress_cb is not None:
                    self.progress_cb(self.tried, self._rate(begin))
                return nonce
            next_start = start + step
            new_future = pool.submit(search_range, (
                initial_hash, target, next_start, step))
            futures[new_future] = next_start
        if self.progress_cb is not None and self.tried > 0:
            self.progress_cb(self.tried, self._rate(begin))
        return None

    def run(self, initial_hash, target, start_nonce=0):
        if len(initial_hash) != 64:
            raise ValueError('initial_hash deve ter 64 bytes')
        step = 1 << 20
        started = start_nonce
        futures = {}
        self.tried = 0
        begin = time.time()
        pool = ProcessPoolExecutor(max_workers=self.workers)
        try:
            self._seed_futures(pool, futures, initial_hash, target,
                               started, step)
            while futures:
                if self.stop_event is not None and self.stop_event.is_set():
                    break
                found = self._poll_futures(pool, futures, initial_hash,
                                           target, step, begin)
                if found is not None:
                    return found
        finally:
            for remaining in list(futures):
                remaining.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
        raise RuntimeError('proof of work não concluído')

    def _rate(self, begin):
        elapsed = max(time.time() - begin, 1e-6)
        return self.tried / elapsed


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
