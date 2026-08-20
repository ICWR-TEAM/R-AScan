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
        # Per-thread request attribution. When scanners run concurrently the
        # global ``count`` alone cannot describe how many requests a single
        # scanner issued, so each worker thread keeps its own scoped tally.
        self._scope = threading.local()

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    def begin_scope(self) -> None:
        """Reset the per-thread request counter for the current scanner."""
        self._scope.count = 0

    def scope_count(self) -> int:
        """Return requests issued on the current thread since ``begin_scope``."""
        return int(getattr(self._scope, "count", 0))

    def acquire(self) -> None:
        if self.cancelled.is_set():
            raise RuntimeError("scan cancelled")
        with self._lock:
            if self._count >= self._maximum:
                raise RuntimeError("global request budget exhausted")
            self._count += 1
        self._scope.count = getattr(self._scope, "count", 0) + 1
        self._semaphore.acquire()

    def release(self) -> None:
        self._semaphore.release()

    def cancel(self) -> None:
        self.cancelled.set()
