import tempfile
import unittest
from pathlib import Path

from r_ascan.config import HTML_REPORT_TEMPLATE
from r_ascan.reporting.html import render_html_report


class HtmlReportTests(unittest.TestCase):
    def test_html_escapes_evidence(self):
        report = {
            "schema_version": "2.0",
            "scan": {"target": {"host": "example.com", "port": None}, "mode": "safe-active"},
            "summary": {
                "risk_score": 5,
                "finding_count": 1,
                "severity": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
                "status": {"confirmed": 0, "potential": 1},
                "failed_scanners": 0,
            },
            "results": [{
                "scanner": {"id": "xss", "mode": "intrusive"},
                "status": "completed",
                "findings": [{
                    "id": "one", "title": "<script>", "scanner_id": "xss",
                    "severity": "medium", "priority": "high", "status": "potential",
                    "confidence": "low", "method": "GET", "endpoint": "/",
                    "score": 2.0, "description": "test", "cwe": "CWE-79",
                    "owasp": None, "remediation": "encode",
                    "evidence": {"source": "reflected", "details": {"payload": "<b>", "signal": "payload reflected"}},
                }],
                "duration_ms": 1,
                "errors": [],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            render_html_report(report, output)
            content = output.read_text()
        self.assertIn("&lt;script&gt;", content)
        self.assertNotIn("<script>", content)
        self.assertIn("CVSS v3.1 Score", content)
        self.assertIn("CWE/CVE", content)
        self.assertIn("Affected Host", content)
        self.assertIn("Summary", content)
        self.assertIn("Impact", content)
        self.assertIn("Remediation", content)
        self.assertIn("POC", content)
        self.assertIn("Evidence", content)
        self.assertIn("curl -skS", content)
        self.assertIn("signal: payload reflected", content)
        self.assertIn("PTES-aligned technical report", content)
        self.assertIn("--black:#000;--white:#fff", content)
        self.assertIn("background:var(--white)", content)
        self.assertIn("R-AScan Web Application Penetration Test Report", Path(HTML_REPORT_TEMPLATE).read_text())
        self.assertNotIn("#0b1020", content)
        self.assertNotIn("#65d1ff", content)


if __name__ == "__main__":
    unittest.main()
