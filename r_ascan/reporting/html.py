from __future__ import annotations

import html
import json
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from r_ascan.config import HTML_REPORT_TEMPLATE


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _load_template() -> str:
    return Path(HTML_REPORT_TEMPLATE).read_text(encoding="utf-8")


def _apply_template(template: str, values: dict[str, Any]) -> str:
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace("{{" + key + "}}", str(value))
    return rendered


def _finding_cwe_cve(finding: dict[str, Any]) -> str:
    values = []
    if finding.get("cwe"):
        values.append(str(finding["cwe"]))
    cve = finding.get("cve") or finding.get("CVE")
    if cve:
        values.append(str(cve))
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        details = evidence.get("details")
        if isinstance(details, dict):
            detail_cve = details.get("cve") or details.get("CVE")
            if detail_cve:
                values.append(str(detail_cve))
    return " / ".join(dict.fromkeys(values)) or "-"


def _affected_host(finding: dict[str, Any]) -> str:
    endpoint = finding.get("endpoint") or "/"
    method = finding.get("method") or "GET"
    return f"{finding.get('target', '-')}{' ' + method + ' ' + endpoint if endpoint else ''}"


def _impact(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "info")).title()
    status = str(finding.get("status", "potential"))
    confidence = str(finding.get("confidence", "low"))
    return f"{severity} impact signal; status {status}, confidence {confidence}."


def _evidence_details(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        return {}
    details = evidence.get("details")
    return details if isinstance(details, dict) else {}


def _absolute_url(finding: dict[str, Any], override: str | None = None) -> str:
    raw = override or str(finding.get("endpoint") or "/")
    if raw.startswith(("http://", "https://")):
        return raw
    host = str(finding.get("target") or "").strip()
    if host.startswith(("http://", "https://")):
        base = host.rstrip("/")
    else:
        base = "https://" + host.rstrip("/")
    path = raw if raw.startswith("/") else "/" + raw
    return base + path


def _curl_poc(finding: dict[str, Any]) -> str:
    if finding.get("reproduction"):
        return str(finding["reproduction"])

    scanner_id = str(finding.get("scanner_id") or "")
    method = str(finding.get("method") or "GET").upper()
    details = _evidence_details(finding)
    details_url = details.get("url") or details.get("payload")
    if isinstance(details_url, str) and details_url.startswith(("http://", "https://")):
        url = details_url
    else:
        url = _absolute_url(finding)

    if scanner_id == "http_smuggler" and details.get("curl"):
        return str(details["curl"])
    if scanner_id == "ldap_injection":
        return (
            f"curl -skS -X POST {shlex.quote(url)} "
            f"--data-urlencode {shlex.quote('username=' + str(details.get('payload', '*')))} "
            f"--data-urlencode {shlex.quote('password=pass')}"
        )
    if scanner_id == "security_headers":
        return f"curl -skSI {shlex.quote(url)}"

    data_parts = []
    param = details.get("param") or details.get("parameter")
    payload = details.get("payload")
    if method != "GET" and param and payload is not None:
        data_parts.append(f"--data-urlencode {shlex.quote(str(param) + '=' + str(payload))}")
    elif method == "GET" and param and payload is not None and "?" not in url:
        url += "?" + urlencode({str(param): str(payload)})

    method_part = "" if method == "GET" else f" -X {shlex.quote(method)}"
    data_part = (" " + " ".join(data_parts)) if data_parts else ""
    return f"curl -skS{method_part} {shlex.quote(url)}{data_part}"


def _evidence_summary(finding: dict[str, Any]) -> str:
    details = _evidence_details(finding)
    values = []
    for key in (
        "status",
        "status_code",
        "signal",
        "match",
        "marker",
        "marker_found",
        "payload",
        "confidence",
        "validation",
        "baseline_similarity",
    ):
        if key in details and details[key] not in (None, "", []):
            values.append(f"{key}: {details[key]}")
    if values:
        return "; ".join(values)
    source = finding.get("evidence", {}).get("source") if isinstance(finding.get("evidence"), dict) else None
    return f"Evidence source: {source or 'normalized scanner output'}"


def render_html_report(report: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    target = report["scan"]["target"]
    summary = report["summary"]
    rows = []
    details = []
    for result in report["results"]:
        for finding in result["findings"]:
            poc = _curl_poc(finding)
            evidence_summary = _evidence_summary(finding)
            rows.append(
                "<tr>"
                f"<td>{_escape(finding['title'])}</td>"
                f"<td>{_escape(finding.get('score', 0))}</td>"
                f"<td>{_escape(_finding_cwe_cve(finding))}</td>"
                f"<td><code>{_escape(_affected_host(finding))}</code></td>"
                f"<td>{_escape(finding.get('description', '-'))}</td>"
                f"<td>{_escape(_impact(finding))}</td>"
                f"<td>{_escape(finding.get('remediation') or '-')}</td>"
                f"<td><code>{_escape(poc)}</code></td>"
                f"<td>{_escape(evidence_summary)}</td>"
                "</tr>"
            )
            details.append(
                "<details>"
                f"<summary>{_escape(finding['title'])} - {_escape(finding['id'])}</summary>"
                f"<p>{_escape(finding['description'])}</p>"
                f"<p><strong>CVSS v3.1 Score:</strong> {_escape(finding.get('score', 0))} "
                f"<strong>CWE/CVE:</strong> {_escape(_finding_cwe_cve(finding))}</p>"
                f"<p><strong>Affected Host:</strong> {_escape(_affected_host(finding))}</p>"
                f"<p><strong>Impact:</strong> {_escape(_impact(finding))}</p>"
                f"<p><strong>Remediation:</strong> {_escape(finding.get('remediation') or '-')}</p>"
                f"<p><strong>POC:</strong></p><pre>{_escape(poc)}</pre>"
                f"<p><strong>Evidence Summary:</strong> {_escape(evidence_summary)}</p>"
                f"<pre>{_escape(json.dumps(finding['evidence'], indent=2))}</pre>"
                "</details>"
            )
    scanner_rows = "".join(
        "<tr>"
        f"<td>{_escape(item['scanner']['id'])}</td>"
        f"<td>{_escape(item['scanner']['mode'])}</td>"
        f"<td>{_escape(item['status'])}</td>"
        f"<td>{len(item['findings'])}</td>"
        f"<td>{_escape(item['duration_ms'])} ms</td>"
        f"<td>{len(item['errors'])}</td>"
        "</tr>"
        for item in report["results"]
    )
    target_label = _escape(target["host"])
    if target.get("port"):
        target_label += ":" + _escape(target["port"])
    document = _apply_template(_load_template(), {
        "REPORT_TITLE": f"R-AScan Report - {_escape(target['host'])}",
        "TARGET_LABEL": target_label,
        "SCAN_MODE": _escape(report["scan"]["mode"]),
        "SCHEMA_VERSION": _escape(report["schema_version"]),
        "RISK_SCORE": _escape(summary["risk_score"]),
        "FINDING_COUNT": _escape(summary["finding_count"]),
        "CRITICAL_COUNT": _escape(summary["severity"]["critical"]),
        "HIGH_COUNT": _escape(summary["severity"]["high"]),
        "FAILED_SCANNERS": _escape(summary["failed_scanners"]),
        "CONFIRMED_COUNT": _escape(summary.get("status", {}).get("confirmed", 0)),
        "POTENTIAL_COUNT": _escape(summary.get("status", {}).get("potential", 0)),
        "FINDING_ROWS": "".join(rows) or '<tr><td colspan="9">No normalized findings.</td></tr>',
        "SCANNER_ROWS": scanner_rows,
        "EVIDENCE_DETAILS": "".join(details) or '<p class="muted">No finding evidence.</p>',
    })
    path.write_text(document, encoding="utf-8")
    return path


def render_json_file(json_path: str | Path, output_path: str | Path | None = None) -> Path:
    source = Path(json_path)
    report = json.loads(source.read_text(encoding="utf-8"))
    return render_html_report(report, output_path or source.with_suffix(".html"))
