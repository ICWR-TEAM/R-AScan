from __future__ import annotations

import threading


class RequestBudget:
    def __init__(self, concurrency: int, maximum: int):
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if maximum < 1:
            raise ValueError("maximum requests must be at least 1")
        self._semaphore = threading.BoundedSemaphore(concurrency)
        self._maximum = maximum
        self._count = 0
        self._lock = threading.Lock()
        self.cancelled = threading.Event()

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    def acquire(self) -> None:
        if self.cancelled.is_set():
            raise RuntimeError("scan cancelled")
        with self._lock:
            if self._count >= self._maximum:
                raise RuntimeError("global request budget exhausted")
            self._count += 1
        self._semaphore.acquire()

    def release(self) -> None:
        self._semaphore.release()

    def cancel(self) -> None:
        self.cancelled.set()
