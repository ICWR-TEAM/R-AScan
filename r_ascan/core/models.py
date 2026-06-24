from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

ScannerMode = Literal["passive", "safe-active", "intrusive", "exploit"]
ScannerStatus = Literal["completed", "failed", "skipped", "cancelled"]

MODE_ORDER = {"passive": 0, "safe-active": 1, "intrusive": 2, "exploit": 3}


@dataclass(frozen=True, slots=True)
class ScannerMetadata:
    id: str
    title: str
    category: str
    mode: ScannerMode = "safe-active"
    version: str = "1.0"
    severity: str = "info"
    tags: tuple[str, ...] = ()

    @classmethod
    def from_value(cls, value: object, fallback_id: str) -> "ScannerMetadata":
        if isinstance(value, cls):
            return value
        if isinstance(value, dict):
            return cls(
                id=str(value.get("id", fallback_id)),
                title=str(value.get("title", fallback_id.replace("_", " ").title())),
                category=str(value.get("category", "general")),
                mode=str(value.get("mode", "safe-active")),  # type: ignore[arg-type]
                version=str(value.get("version", "1.0")),
                severity=str(value.get("severity", "info")),
                tags=tuple(value.get("tags", ())),
            )
        return cls(
            id=fallback_id,
            title=fallback_id.replace("_", " ").title(),
            category="general",
        )


@dataclass(slots=True)
class Finding:
    id: str
    scanner_id: str
    title: str
    description: str
    target: str
    endpoint: str
    severity: str = "info"
    confidence: str = "low"
    status: str = "potential"
    method: str = "GET"
    evidence: dict[str, Any] = field(default_factory=dict)
    reproduction: str | None = None
    remediation: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    score: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScannerResult:
    scanner: ScannerMetadata
    status: ScannerStatus
    started_at: str
    finished_at: str
    duration_ms: int
    request_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["scanner"] = asdict(self.scanner)
        return value
