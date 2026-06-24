from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

from .models import Finding, ScannerMetadata
from .target import Target

SEVERITY = {
    "apache2_struts": "critical",
    "php_unit_rce": "critical",
    "elaina_cve_2025_32433": "critical",
    "rce": "critical",
    "command_injection": "critical",
    "sqli": "high",
    "lfi": "high",
    "ssti": "high",
    "ssrf": "high",
    "xss": "medium",
    "open_redirect": "medium",
    "ldap_injection": "high",
    "http_smuggler": "high",
    "broken_access_control": "high",
    "access_control": "medium",
    "sensitive_files": "high",
    "metafiles_leak": "medium",
    "security_headers": "low",
}

CWE = {
    "sqli": "CWE-89",
    "command_injection": "CWE-78",
    "rce": "CWE-94",
    "lfi": "CWE-22",
    "xss": "CWE-79",
    "ssrf": "CWE-918",
    "ssti": "CWE-1336",
    "open_redirect": "CWE-601",
    "ldap_injection": "CWE-90",
    "broken_access_control": "CWE-284",
    "access_control": "CWE-284",
    "http_smuggler": "CWE-444",
    "sensitive_files": "CWE-200",
    "metafiles_leak": "CWE-200",
    "security_headers": "CWE-693",
}

REMEDIATION = {
    "sqli": "Use parameterized queries and strict server-side input validation.",
    "command_injection": "Avoid shell execution; use safe APIs and allowlisted arguments.",
    "rce": "Remove unsafe code execution paths and enforce strict input boundaries.",
    "lfi": "Resolve files from an allowlist and prevent user-controlled path traversal.",
    "xss": "Apply contextual output encoding and a restrictive Content Security Policy.",
    "ssrf": "Allowlist outbound destinations and block private/link-local address ranges.",
    "ssti": "Do not evaluate user input as templates; use sandboxed template contexts.",
    "open_redirect": "Allowlist redirect destinations and use server-side identifiers.",
    "security_headers": "Configure the missing security headers with appropriate directives.",
}

RISK_WEIGHT = {"info": 0.0, "low": 2.0, "medium": 5.0, "high": 8.0, "critical": 10.0}


def _endpoint(value: Any, target: Target) -> str:
    if isinstance(value, dict):
        for key in ("url", "payload", "endpoint", "path", "file", "target"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                if candidate.startswith(("http://", "https://")):
                    parsed = urlsplit(candidate)
                    return parsed.path + (f"?{parsed.query}" if parsed.query else "")
                return candidate
    return target.base_path


def _method(value: Any) -> str:
    return str(value.get("method", "GET")).upper() if isinstance(value, dict) else "GET"


def _is_positive(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    return any(
        (
            value.get("vulnerable") is True,
            value.get("vuln") is True,
            value.get("anomaly") is True,
            value.get("potential") is True,
            value.get("potentially_exposed") is True,
            value.get("status") == "vulnerable",
        )
    )


def _walk(value: Any, path: str = ""):
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from _walk(child, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


def normalize_result(
    metadata: ScannerMetadata,
    target: Target,
    raw: Any,
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, str]]]:
    findings: list[Finding] = []
    observations: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    seen: set[str] = set()

    for path, item in _walk(raw):
        if "error" in item and item["error"]:
            errors.append({"type": "ScannerDataError", "message": str(item["error"])})
        positive = _is_positive(item)
        if metadata.id == "sensitive_files" and item.get("status") == 200 and item.get("file"):
            positive = True
        if metadata.id == "enumeration_directory" and item.get("status") in (200, 401, 403):
            positive = True
        if metadata.id == "broken_access_control" and path.startswith("potential_bac"):
            positive = True
        if metadata.id == "http_smuggler" and item.get("anomaly") is True:
            positive = True
        if not positive:
            continue
        status = "potential" if (
            item.get("potential") is True
            or item.get("potentially_exposed") is True
            or item.get("status") == "potential"
            or metadata.id in {"enumeration_directory", "broken_access_control", "http_smuggler"}
        ) else "confirmed"
        confidence = str(item.get("confidence") or ("medium" if status == "confirmed" else "low"))
        severity = SEVERITY.get(metadata.id, metadata.severity)
        endpoint = _endpoint(item, target)
        identity = json.dumps([metadata.id, endpoint, _method(item), path], sort_keys=True)
        finding_id = hashlib.sha256(identity.encode()).hexdigest()[:16]
        if finding_id in seen:
            continue
        seen.add(finding_id)
        title = metadata.title
        finding = Finding(
            id=finding_id,
            scanner_id=metadata.id,
            title=title,
            description=f"{title} signal reported by scanner {metadata.id}.",
            target=target.authority,
            endpoint=endpoint,
            severity=severity,
            confidence=confidence,
            status=status,
            method=_method(item),
            evidence={"source": path or "root", "details": item},
            reproduction=item.get("curl") if isinstance(item.get("curl"), str) else None,
            remediation=REMEDIATION.get(metadata.id),
            cwe=CWE.get(metadata.id),
            score=RISK_WEIGHT.get(severity, 0.0),
        )
        findings.append(finding)

    # Configuration and exposure modules often represent findings as collections.
    if isinstance(raw, dict):
        collection_rules = (
            ("missing", "Missing security control", "low"),
            ("metafiles", "Exposed metadata file", "medium"),
        )
        for key, title, severity in collection_rules:
            value = raw.get(key)
            entries = list(value) if isinstance(value, (list, dict)) else []
            for entry in entries:
                endpoint = str(entry)
                identity = f"{metadata.id}:{key}:{endpoint}"
                finding_id = hashlib.sha256(identity.encode()).hexdigest()[:16]
                findings.append(Finding(
                    id=finding_id,
                    scanner_id=metadata.id,
                    title=f"{title}: {endpoint}",
                    description=f"{metadata.title} reported {endpoint}.",
                    target=target.authority,
                    endpoint=endpoint,
                    severity=severity,
                    confidence="high",
                    status="confirmed",
                    evidence={"source": key, "details": value[entry] if isinstance(value, dict) else entry},
                    remediation=REMEDIATION.get(metadata.id),
                    cwe=CWE.get(metadata.id),
                    score=RISK_WEIGHT[severity],
                ))

    if raw not in (None, {}, [], ""):
        observations.append({"type": "scanner_output", "data": raw})
    return findings, observations, errors


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    statuses = {"confirmed": 0, "potential": 0}
    failed = 0
    total_score = 0.0
    for result in results:
        if result["status"] == "failed":
            failed += 1
        for finding in result["findings"]:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
            statuses[finding["status"]] = statuses.get(finding["status"], 0) + 1
            total_score += float(finding.get("score", 0))
    return {
        "finding_count": sum(counts.values()),
        "severity": counts,
        "status": statuses,
        "failed_scanners": failed,
        "risk_score": round(min(100.0, total_score), 1),
    }
