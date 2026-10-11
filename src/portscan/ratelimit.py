"""Limitador de velocidad global compartido por todos los hilos."""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Reparte 'slots' espaciados 1/rate segundos; seguro entre hilos."""

    def __init__(self, rate: float, clock=time.monotonic, sleep=time.sleep):
        if rate <= 0:
            raise ValueError("rate debe ser > 0")
        self.interval = 1.0 / rate
        self._clock = clock
        self._sleep = sleep
        self._next = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = self._clock()
            slot = max(now, self._next)
            self._next = slot + self.interval
        delay = slot - now
        if delay > 0:
            self._sleep(delay)
