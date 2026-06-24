from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .scheduler import RequestBudget
from .target import Target
from .transport import HttpTransport


@dataclass(frozen=True, slots=True)
class ScanConfig:
    threads: int = 5
    max_requests: int = 5000
    timeout: float = 5.0
    verify_tls: bool = True
    max_mode: str = "safe-active"
    verbose: bool = False


@dataclass(slots=True)
class ScanContext:
    target: Target
    config: ScanConfig
    transport: HttpTransport
    budget: RequestBudget
    shared: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        target: Target,
        config: ScanConfig,
        headers: dict[str, str],
        proxy: str | None = None,
    ) -> "ScanContext":
        budget = RequestBudget(config.threads, config.max_requests)
        transport = HttpTransport(
            target,
            budget,
            timeout=config.timeout,
            verify_tls=config.verify_tls,
            headers=headers,
            proxy=proxy,
        )
        return cls(target, config, transport, budget)
