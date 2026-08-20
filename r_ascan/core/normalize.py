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

# OWASP Top 10 (2021) category mapping per scanner id.
OWASP = {
    "sqli": "A03:2021-Injection",
    "command_injection": "A03:2021-Injection",
    "rce": "A03:2021-Injection",
    "ssti": "A03:2021-Injection",
    "ldap_injection": "A03:2021-Injection",
    "xss": "A03:2021-Injection",
    "lfi": "A01:2021-Broken Access Control",
    "broken_access_control": "A01:2021-Broken Access Control",
    "access_control": "A01:2021-Broken Access Control",
    "open_redirect": "A01:2021-Broken Access Control",
    "ssrf": "A10:2021-Server-Side Request Forgery",
    "http_smuggler": "A06:2021-Vulnerable and Outdated Components",
    "apache2_struts": "A06:2021-Vulnerable and Outdated Components",
    "php_unit_rce": "A06:2021-Vulnerable and Outdated Components",
    "elaina_cve_2025_32433": "A06:2021-Vulnerable and Outdated Components",
    "sensitive_files": "A05:2021-Security Misconfiguration",
    "metafiles_leak": "A05:2021-Security Misconfiguration",
    "security_headers": "A05:2021-Security Misconfiguration",
    "enumeration_directory": "A05:2021-Security Misconfiguration",
}

# Representative CVSS v3.1 base vector and score per normalized severity band.
CVSS_PROFILE = {
    "critical": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "high": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "medium": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),
    "low": ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "info": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
}

REFERENCES = {
    "sqli": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
    "command_injection": ["https://owasp.org/www-community/attacks/Command_Injection", "https://cwe.mitre.org/data/definitions/78.html"],
    "rce": ["https://cwe.mitre.org/data/definitions/94.html"],
    "lfi": ["https://owasp.org/www-community/attacks/Path_Traversal", "https://cwe.mitre.org/data/definitions/22.html"],
    "xss": ["https://owasp.org/www-community/attacks/xss/", "https://cwe.mitre.org/data/definitions/79.html"],
    "ssrf": ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/", "https://cwe.mitre.org/data/definitions/918.html"],
    "ssti": ["https://owasp.org/www-project-web-security-testing-guide/", "https://cwe.mitre.org/data/definitions/1336.html"],
    "open_redirect": ["https://cwe.mitre.org/data/definitions/601.html"],
    "ldap_injection": ["https://owasp.org/www-community/attacks/LDAP_Injection", "https://cwe.mitre.org/data/definitions/90.html"],
    "broken_access_control": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/", "https://cwe.mitre.org/data/definitions/284.html"],
    "access_control": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/", "https://cwe.mitre.org/data/definitions/284.html"],
    "http_smuggler": ["https://portswigger.net/web-security/request-smuggling", "https://cwe.mitre.org/data/definitions/444.html"],
    "sensitive_files": ["https://owasp.org/www-project-web-security-testing-guide/", "https://cwe.mitre.org/data/definitions/200.html"],
    "metafiles_leak": ["https://cwe.mitre.org/data/definitions/200.html"],
    "security_headers": ["https://owasp.org/www-project-secure-headers/", "https://cwe.mitre.org/data/definitions/693.html"],
}


def _cve_from_scanner(scanner_id: str, item: Any) -> str | None:
    if isinstance(item, dict):
        candidate = item.get("cve") or item.get("CVE")
        if candidate:
            return str(candidate)
    known = {
        "elaina_cve_2025_32433": "CVE-2025-32433",
    }
    return known.get(scanner_id)


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
        cvss_vector, cvss_score = CVSS_PROFILE.get(severity, CVSS_PROFILE["info"])
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
            cve=_cve_from_scanner(metadata.id, item),
            owasp=OWASP.get(metadata.id),
            references=list(REFERENCES.get(metadata.id, [])),
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
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
                cvss_vector, cvss_score = CVSS_PROFILE.get(severity, CVSS_PROFILE["info"])
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
                    owasp=OWASP.get(metadata.id),
                    references=list(REFERENCES.get(metadata.id, [])),
                    cvss_vector=cvss_vector,
                    cvss_score=cvss_score,
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
