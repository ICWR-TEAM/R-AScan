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


def _references_html(finding: dict[str, Any]) -> str:
    references = finding.get("references")
    if not isinstance(references, list) or not references:
        return "-"
    links = [
        f'<a href="{_escape(ref)}" rel="noreferrer">{_escape(ref)}</a>'
        for ref in references
        if isinstance(ref, str) and ref
    ]
    return "<br>".join(links) or "-"


def _cvss_label(finding: dict[str, Any]) -> str:
    score = finding.get("cvss_score")
    vector = finding.get("cvss_vector")
    if score and vector:
        return f"{score} ({vector})"
    if vector:
        return str(vector)
    return "-"


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
    scan = report.get("scan", {})
    target = scan["target"]
    summary = report["summary"]
    severity = summary.get("severity", {})
    optimization = report.get("optimization") if isinstance(report.get("optimization"), dict) else None
    rows = []
    details = []
    owasp_counter: dict[str, int] = {}
    priority_counter: dict[str, int] = {}
    for result in report["results"]:
        for finding in result["findings"]:
            poc = _curl_poc(finding)
            evidence_summary = _evidence_summary(finding)
            owasp = finding.get("owasp") or "Unmapped"
            owasp_counter[owasp] = owasp_counter.get(owasp, 0) + 1
            priority = str(finding.get("priority") or "-")
            priority_counter[priority] = priority_counter.get(priority, 0) + 1
            rows.append(
                "<tr>"
                f"<td>{_escape(finding['title'])}</td>"
                f"<td>{_escape(str(finding.get('severity', 'info')).title())}</td>"
                f"<td>{_escape(priority)}</td>"
                f"<td>{_escape(finding.get('score', 0))}</td>"
                f"<td>{_escape(_finding_cwe_cve(finding))}</td>"
                f"<td>{_escape(owasp)}</td>"
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
                f"<p><strong>Severity:</strong> {_escape(str(finding.get('severity', 'info')).title())} "
                f"<strong>Priority:</strong> {_escape(priority)} "
                f"<strong>Confidence:</strong> {_escape(finding.get('confidence', 'low'))} "
                f"<strong>Status:</strong> {_escape(finding.get('status', 'potential'))}</p>"
                f"<p><strong>CVSS v3.1 Score:</strong> {_escape(finding.get('score', 0))} "
                f"<strong>CVSS Vector:</strong> {_escape(_cvss_label(finding))} "
                f"<strong>CWE/CVE:</strong> {_escape(_finding_cwe_cve(finding))} "
                f"<strong>OWASP:</strong> {_escape(owasp)}</p>"
                f"<p><strong>Affected Host:</strong> {_escape(_affected_host(finding))}</p>"
                f"<p><strong>Impact:</strong> {_escape(_impact(finding))}</p>"
                f"<p><strong>Remediation:</strong> {_escape(finding.get('remediation') or '-')}</p>"
                f"<p><strong>References:</strong> {_references_html(finding)}</p>"
                f"<p><strong>POC:</strong></p><pre>{_escape(poc)}</pre>"
                f"<p><strong>Evidence Summary:</strong> {_escape(evidence_summary)}</p>"
                f"<pre>{_escape(json.dumps(finding['evidence'], indent=2))}</pre>"
                "</details>"
            )
    scanner_rows = "".join(
        "<tr>"
        f"<td>{_escape(item['scanner']['id'])}</td>"
        f"<td>{_escape(item['scanner'].get('category', '-'))}</td>"
        f"<td>{_escape(item['scanner']['mode'])}</td>"
        f"<td>{_escape(item['status'])}</td>"
        f"<td>{len(item['findings'])}</td>"
        f"<td>{_escape(item.get('request_count', 0))}</td>"
        f"<td>{_escape(item['duration_ms'])} ms</td>"
        f"<td>{len(item['errors'])}</td>"
        "</tr>"
        for item in report["results"]
    )
    severity_rows = "".join(
        f"<tr><td>{_escape(label.title())}</td><td>{_escape(severity.get(label, 0))}</td></tr>"
        for label in ("critical", "high", "medium", "low", "info")
    )
    owasp_rows = "".join(
        f"<tr><td>{_escape(name)}</td><td>{_escape(count)}</td></tr>"
        for name, count in sorted(owasp_counter.items(), key=lambda kv: (-kv[1], kv[0]))
    ) or '<tr><td colspan="2">No mapped findings.</td></tr>'
    priority_rows = "".join(
        f"<tr><td>{_escape(name)}</td><td>{_escape(count)}</td></tr>"
        for name, count in sorted(priority_counter.items(), key=lambda kv: (-kv[1], kv[0]))
    ) or '<tr><td colspan="2">No prioritized findings.</td></tr>'
    optimization_section = _optimization_section(optimization)
    target_label = _escape(target["host"])
    if target.get("port"):
        target_label += ":" + _escape(target["port"])
    document = _apply_template(_load_template(), {
        "REPORT_TITLE": f"R-AScan Report - {_escape(target['host'])}",
        "TARGET_LABEL": target_label,
        "SCAN_MODE": _escape(scan.get("mode", "-")),
        "SCHEMA_VERSION": _escape(report.get("schema_version", "-")),
        "GENERATED_AT": _escape(scan.get("generated_at", "-")),
        "REQUEST_COUNT": _escape(scan.get("request_count", 0)),
        "SCANNER_WORKERS": _escape(scan.get("scanner_workers", 1)),
        "RISK_SCORE": _escape(summary["risk_score"]),
        "FINDING_COUNT": _escape(summary["finding_count"]),
        "CRITICAL_COUNT": _escape(severity.get("critical", 0)),
        "HIGH_COUNT": _escape(severity.get("high", 0)),
        "MEDIUM_COUNT": _escape(severity.get("medium", 0)),
        "LOW_COUNT": _escape(severity.get("low", 0)),
        "INFO_COUNT": _escape(severity.get("info", 0)),
        "FAILED_SCANNERS": _escape(summary["failed_scanners"]),
        "CONFIRMED_COUNT": _escape(summary.get("status", {}).get("confirmed", 0)),
        "POTENTIAL_COUNT": _escape(summary.get("status", {}).get("potential", 0)),
        "SEVERITY_ROWS": severity_rows,
        "OWASP_ROWS": owasp_rows,
        "PRIORITY_ROWS": priority_rows,
        "OPTIMIZATION_SECTION": optimization_section,
        "FINDING_ROWS": "".join(rows) or '<tr><td colspan="12">No normalized findings.</td></tr>',
        "SCANNER_ROWS": scanner_rows,
        "EVIDENCE_DETAILS": "".join(details) or '<p class="muted">No finding evidence.</p>',
    })
    path.write_text(document, encoding="utf-8")
    return path


def _optimization_section(optimization: dict[str, Any] | None) -> str:
    if not optimization:
        return (
            '<p class="muted">Risk prioritization optimizer not run. '
            "Re-run with <code>--optimize</code> for a bounded aggregate risk model.</p>"
        )
    hotspots = optimization.get("hotspots") or []
    hotspot_rows = "".join(
        f"<tr><td><code>{_escape(item.get('endpoint', '-'))}</code></td>"
        f"<td>{_escape(item.get('finding_count', 0))}</td></tr>"
        for item in hotspots
    ) or '<tr><td colspan="2">No endpoint concentrations.</td></tr>'
    top = optimization.get("top_finding") or {}
    top_line = (
        f"Top finding <code>{_escape(top.get('id', '-'))}</code> "
        f"from scanner <code>{_escape(top.get('scanner_id', '-'))}</code> "
        f"(score {_escape(top.get('score', 0))}, priority {_escape(top.get('priority', '-'))})."
        if top else "No prioritized findings."
    )
    return (
        f"<p><strong>Engine:</strong> {_escape(optimization.get('engine', '-'))} "
        f"<strong>Aggregate risk:</strong> {_escape(optimization.get('risk_score', 0))}/100 "
        f"<strong>Unique findings:</strong> {_escape(optimization.get('unique_finding_count', 0))}</p>"
        f"<p>{top_line}</p>"
        "<h3>Endpoint Hotspots</h3>"
        '<div class="table-wrap"><table><thead><tr><th>Endpoint</th><th>Findings</th></tr></thead>'
        f"<tbody>{hotspot_rows}</tbody></table></div>"
    )


def render_json_file(json_path: str | Path, output_path: str | Path | None = None) -> Path:
    source = Path(json_path)
    report = json.loads(source.read_text(encoding="utf-8"))
    return render_html_report(report, output_path or source.with_suffix(".html"))
