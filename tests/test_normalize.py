import unittest

from r_ascan.core.models import ScannerMetadata
from r_ascan.core.normalize import normalize_result, summarize
from r_ascan.core.target import Target


class NormalizeTests(unittest.TestCase):
    def setUp(self):
        self.target = Target.parse("example.com", 8443)

    def test_vulnerability_shape_is_general(self):
        metadata = ScannerMetadata("sqli", "SQL Injection", "injection")
        findings, observations, errors = normalize_result(
            metadata,
            self.target,
            {"vulnerable": True, "url": "https://example.com:8443/?id=1", "payload": "'"},
        )
        self.assertEqual(len(findings), 1)
        value = findings[0].as_dict()
        self.assertEqual(value["scanner_id"], "sqli")
        self.assertEqual(value["severity"], "high")
        self.assertEqual(value["endpoint"], "/?id=1")
        self.assertEqual(errors, [])
        self.assertEqual(len(observations), 1)

    def test_security_headers_become_findings(self):
        metadata = ScannerMetadata("security_headers", "Security Headers", "configuration")
        findings, _, _ = normalize_result(
            metadata,
            self.target,
            {"missing": ["Content-Security-Policy", "Strict-Transport-Security"]},
        )
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(item.severity == "low" for item in findings))

    def test_summary(self):
        result = {
            "status": "completed",
            "findings": [
                {"severity": "high", "status": "confirmed", "score": 8.0},
                {"severity": "low", "status": "potential", "score": 2.0},
            ],
        }
        value = summarize([result])
        self.assertEqual(value["finding_count"], 2)
        self.assertEqual(value["risk_score"], 10.0)


if __name__ == "__main__":
    unittest.main()
