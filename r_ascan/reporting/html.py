from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_html_report(report: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    target = report["scan"]["target"]
    summary = report["summary"]
    rows = []
    details = []
    for result in report["results"]:
        for finding in result["findings"]:
            rows.append(
                "<tr>"
                f"<td><span class='badge {_escape(finding['severity'])}'>{_escape(finding['severity'])}</span></td>"
                f"<td>{_escape(finding.get('priority', '-'))}</td>"
                f"<td>{_escape(finding['title'])}</td>"
                f"<td>{_escape(finding['scanner_id'])}</td>"
                f"<td>{_escape(finding['status'])}</td>"
                f"<td>{_escape(finding['confidence'])}</td>"
                f"<td><code>{_escape(finding['method'])} {_escape(finding['endpoint'])}</code></td>"
                f"<td>{_escape(finding.get('score', 0))}</td>"
                "</tr>"
            )
            details.append(
                "<details>"
                f"<summary>{_escape(finding['title'])} — {_escape(finding['id'])}</summary>"
                f"<p>{_escape(finding['description'])}</p>"
                f"<p><strong>CWE:</strong> {_escape(finding.get('cwe') or '-')} "
                f"<strong>OWASP:</strong> {_escape(finding.get('owasp') or '-')}</p>"
                f"<p><strong>Remediation:</strong> {_escape(finding.get('remediation') or '-')}</p>"
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
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>R-AScan Report — {_escape(target['host'])}</title>
<style>
:root{{--black:#000;--white:#fff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--white);color:var(--black);font:14px/1.5 system-ui,sans-serif}}
main{{max-width:1280px;margin:auto;padding:32px}}h1,h2{{margin:.2em 0}}.muted{{color:var(--black)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:24px 0}}
.card,details{{background:var(--white);border:1px solid var(--black);border-radius:0;padding:16px}}
.value{{font-size:28px;font-weight:700;color:var(--black)}}table{{width:100%;border-collapse:collapse;background:var(--white);margin:12px 0 28px;border:1px solid var(--black)}}
th,td{{padding:10px;border:1px solid var(--black);text-align:left;vertical-align:top}}th{{color:var(--black);background:var(--white)}}
.table-wrap{{overflow:auto}}.badge{{display:inline-block;padding:2px 7px;border:1px solid var(--black);border-radius:0;font-weight:700;background:var(--white);color:var(--black)}}
.critical,.high,.medium,.low,.info{{background:var(--white);color:var(--black)}}details{{margin:10px 0}}summary{{cursor:pointer;font-weight:700}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--white);color:var(--black);border:1px solid var(--black);padding:12px;border-radius:0}}code{{color:var(--black)}}
@media print{{body{{background:var(--white);color:var(--black)}}main{{max-width:none;padding:0}}details{{break-inside:avoid}}}}
</style>
</head>
<body><main>
<h1>R-AScan Security Report</h1>
<p class="muted">Target: {_escape(target['host'])}{':' + _escape(target['port']) if target.get('port') else ''} · Mode: {_escape(report['scan']['mode'])} · Schema: {_escape(report['schema_version'])}</p>
<section class="grid">
<div class="card"><div class="muted">Risk score</div><div class="value">{_escape(summary['risk_score'])}/100</div></div>
<div class="card"><div class="muted">Findings</div><div class="value">{_escape(summary['finding_count'])}</div></div>
<div class="card"><div class="muted">Critical / High</div><div class="value">{summary['severity']['critical']} / {summary['severity']['high']}</div></div>
<div class="card"><div class="muted">Failed scanners</div><div class="value">{_escape(summary['failed_scanners'])}</div></div>
</section>
<h2>Findings</h2><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Priority</th><th>Title</th><th>Scanner</th><th>Status</th><th>Confidence</th><th>Endpoint</th><th>Score</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="8">No normalized findings.</td></tr>'}</tbody></table></div>
<h2>Scanner execution</h2><div class="table-wrap"><table><thead><tr><th>Scanner</th><th>Mode</th><th>Status</th><th>Findings</th><th>Duration</th><th>Errors</th></tr></thead><tbody>{scanner_rows}</tbody></table></div>
<h2>Evidence</h2>{''.join(details) or '<p class="muted">No finding evidence.</p>'}
</main></body></html>"""
    path.write_text(document, encoding="utf-8")
    return path


def render_json_file(json_path: str | Path, output_path: str | Path | None = None) -> Path:
    source = Path(json_path)
    report = json.loads(source.read_text(encoding="utf-8"))
    return render_html_report(report, output_path or source.with_suffix(".html"))
