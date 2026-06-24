"""Deterministic report optimization and risk prioritization.

The historical per-scan ML model trained and predicted on the same samples.
This replacement adjusts normalized findings using explicit, auditable rules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SEVERITY_SCORE = {"info": 0.0, "low": 2.0, "medium": 5.0, "high": 8.0, "critical": 10.0}
CONFIDENCE_FACTOR = {"none": 0.0, "low": 0.45, "medium": 0.7, "high": 0.9, "confirmed": 1.0}
STATUS_FACTOR = {"informational": 0.25, "potential": 0.65, "confirmed": 1.0}


def optimize_report(report: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for result in report.get("results", []):
        for finding in result.get("findings", []):
            base = SEVERITY_SCORE.get(finding.get("severity", "info"), 0.0)
            confidence = CONFIDENCE_FACTOR.get(finding.get("confidence", "low"), 0.45)
            status = STATUS_FACTOR.get(finding.get("status", "potential"), 0.65)
            score = round(base * confidence * status, 1)
            finding["score"] = score
            finding["priority"] = (
                "urgent" if score >= 8
                else "high" if score >= 5
                else "medium" if score >= 2
                else "low"
            )
            findings.append(finding)
        result["summary"]["risk_score"] = round(
            min(100.0, sum(item.get("score", 0) for item in result.get("findings", []))),
            1,
        )

    findings.sort(key=lambda item: (-item.get("score", 0), item.get("scanner_id", ""), item.get("id", "")))
    report["optimization"] = {
        "engine": "deterministic-risk-v1",
        "finding_count": len(findings),
        "prioritized_finding_ids": [item["id"] for item in findings],
        "risk_score": round(min(100.0, sum(item.get("score", 0) for item in findings)), 1),
    }
    report["summary"]["risk_score"] = report["optimization"]["risk_score"]
    return report


def optimize_file(path: str | Path) -> dict[str, Any]:
    output_path = Path(path)
    report = json.loads(output_path.read_text(encoding="utf-8"))
    optimize_report(report)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def scan(args=None):
    path = Path(args.output) if args.output else Path(f"scan_output-{args.target}.json")
    report = optimize_file(path)
    print(
        "[*] [Optimizer] "
        f"[Engine: {report['optimization']['engine']}] "
        f"[Risk: {report['optimization']['risk_score']}/100]"
    )
    return report["optimization"]
