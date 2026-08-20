"""Deterministic report optimization and risk prioritization.

The historical per-scan ML model trained and predicted on the same samples.
This replacement adjusts normalized findings using explicit, auditable rules so
that identical input always yields identical, reproducible output.

Model: ``deterministic-risk-v2``
--------------------------------
Per-finding score:
    score = severity_base * confidence_factor * status_factor
where every factor is a fixed, documented constant. This keeps each individual
score fully explainable and stable.

Aggregate report risk uses a diminishing-returns (noisy-OR) combination instead
of a naive sum. A single medium issue no longer saturates the 0-100 scale, and
stacking many findings raises risk toward, but never beyond, 100 in a smooth,
precise way.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ENGINE = "deterministic-risk-v2"

SEVERITY_SCORE = {"info": 0.0, "low": 2.0, "medium": 5.0, "high": 8.0, "critical": 10.0}
CONFIDENCE_FACTOR = {"none": 0.0, "low": 0.45, "medium": 0.7, "high": 0.9, "confirmed": 1.0}
STATUS_FACTOR = {"informational": 0.25, "potential": 0.65, "confirmed": 1.0}

# Priority bands are derived from the precise per-finding score (0-10).
PRIORITY_BANDS = (
    (9.0, "urgent"),
    (7.0, "high"),
    (5.0, "elevated"),
    (2.5, "medium"),
    (0.0, "low"),
)


def _factor(mapping: dict[str, float], key: Any, default: float) -> float:
    return mapping.get(str(key).lower(), default)


def _finding_score(finding: dict[str, Any]) -> float:
    base = _factor(SEVERITY_SCORE, finding.get("severity", "info"), 0.0)
    confidence = _factor(CONFIDENCE_FACTOR, finding.get("confidence", "low"), 0.45)
    status = _factor(STATUS_FACTOR, finding.get("status", "potential"), 0.65)
    # Two-decimal rounding keeps the score precise without floating-point noise.
    return round(base * confidence * status, 2)


def _priority(score: float) -> str:
    for threshold, label in PRIORITY_BANDS:
        if score >= threshold:
            return label
    return "low"


def _aggregate_risk(scores: list[float]) -> float:
    """Combine per-finding scores with a bounded noisy-OR aggregation.

    Each score contributes ``score / 10`` as an independent probability of
    material risk. The combined risk is ``1 - prod(1 - p_i)`` scaled to 0-100.
    The result is monotonic, order-independent, and strictly bounded by 100.
    """
    residual = 1.0
    for score in scores:
        probability = max(0.0, min(1.0, score / 10.0))
        residual *= (1.0 - probability)
    return round((1.0 - residual) * 100.0, 2)


def optimize_report(report: dict[str, Any]) -> dict[str, Any]:
    unique: dict[str, dict[str, Any]] = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    priority_counts: dict[str, int] = {}
    hotspots: dict[str, int] = {}

    for result in report.get("results", []):
        result_findings = result.get("findings", [])
        for finding in result_findings:
            score = _finding_score(finding)
            finding["score"] = score
            finding["priority"] = _priority(score)
            # Deduplicate across scanners/results so the aggregate risk and
            # counts never double-count the same normalized finding id.
            identifier = str(finding.get("id") or id(finding))
            if identifier not in unique:
                unique[identifier] = finding
        # Per-scanner risk uses the same precise aggregation as the report.
        result.setdefault("summary", {})
        result["summary"]["risk_score"] = _aggregate_risk(
            [_finding_score(item) for item in result_findings]
        )

    prioritized = sorted(
        unique.values(),
        key=lambda item: (
            -float(item.get("score", 0.0)),
            str(item.get("scanner_id", "")),
            str(item.get("id", "")),
        ),
    )

    for finding in prioritized:
        severity = str(finding.get("severity", "info")).lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        priority_counts[finding["priority"]] = priority_counts.get(finding["priority"], 0) + 1
        endpoint = str(finding.get("endpoint") or "/")
        hotspots[endpoint] = hotspots.get(endpoint, 0) + 1

    aggregate = _aggregate_risk([float(item.get("score", 0.0)) for item in prioritized])
    top_hotspots = sorted(hotspots.items(), key=lambda kv: (-kv[1], kv[0]))[:10]

    report["optimization"] = {
        "engine": ENGINE,
        "model": {
            "severity_score": SEVERITY_SCORE,
            "confidence_factor": CONFIDENCE_FACTOR,
            "status_factor": STATUS_FACTOR,
            "aggregation": "bounded-noisy-or",
        },
        "finding_count": len(prioritized),
        "unique_finding_count": len(unique),
        "severity_counts": severity_counts,
        "priority_counts": priority_counts,
        "prioritized_finding_ids": [item["id"] for item in prioritized if item.get("id")],
        "top_finding": (
            {
                "id": prioritized[0].get("id"),
                "scanner_id": prioritized[0].get("scanner_id"),
                "score": prioritized[0].get("score"),
                "priority": prioritized[0].get("priority"),
            }
            if prioritized else None
        ),
        "hotspots": [{"endpoint": endpoint, "finding_count": count} for endpoint, count in top_hotspots],
        "risk_score": aggregate,
    }
    report.setdefault("summary", {})
    report["summary"]["risk_score"] = aggregate
    report["summary"]["priority"] = priority_counts
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
