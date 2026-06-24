from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from .models import MODE_ORDER, ScannerMetadata


PASSIVE = {
    "content_leak", "deployment_config", "endpoint_finder", "fingerprint_web_server",
    "frameworks_components", "hosting_environment", "security_headers", "technologies",
    "web_extractor",
}
INTRUSIVE = {
    "broken_access_control", "http_smuggler", "ldap_injection", "rate_limiting",
    "top_25_owasp_full_scanner", "xss",
}


def inferred_metadata(path: Path, explicit: object = None) -> ScannerMetadata:
    scanner_id = path.stem
    metadata = ScannerMetadata.from_value(explicit, scanner_id)
    if explicit is not None:
        return metadata
    if "exploits" in path.parts:
        mode = "exploit"
        category = "exploit"
    elif scanner_id in PASSIVE:
        mode = "passive"
        category = "reconnaissance"
    elif scanner_id in INTRUSIVE:
        mode = "intrusive"
        category = "active-testing"
    else:
        mode = "safe-active"
        category = "vulnerability"
    return ScannerMetadata(
        id=scanner_id,
        title=scanner_id.replace("_", " ").title(),
        category=category,
        mode=mode,
    )


def selected(
    metadata: ScannerMetadata,
    *,
    max_mode: str,
    include: set[str],
    exclude: set[str],
    categories: set[str],
) -> bool:
    if metadata.id in exclude:
        return False
    if include and metadata.id not in include:
        return False
    if categories and metadata.category not in categories:
        return False
    return MODE_ORDER[metadata.mode] <= MODE_ORDER[max_mode]


def csv_set(values: Iterable[str] | None) -> set[str]:
    result: set[str] = set()
    for value in values or ():
        result.update(item.strip() for item in value.split(",") if item.strip())
    return result
