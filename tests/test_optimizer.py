import unittest

from r_ascan.module.ml_optimizer import optimize_report


class OptimizerTests(unittest.TestCase):
    def test_deterministic_scoring(self):
        report = {
            "summary": {"risk_score": 0},
            "results": [{
                "summary": {"risk_score": 0},
                "findings": [{
                    "id": "a",
                    "scanner_id": "sqli",
                    "severity": "high",
                    "confidence": "high",
                    "status": "confirmed",
                }],
            }],
        }
        optimize_report(report)
        finding = report["results"][0]["findings"][0]
        self.assertEqual(finding["score"], 7.2)
        self.assertEqual(finding["priority"], "high")
        self.assertEqual(report["optimization"]["engine"], "deterministic-risk-v2")
        # Bounded noisy-OR aggregation: 1 - (1 - 7.2/10) = 0.72 -> 72.0.
        self.assertEqual(report["optimization"]["risk_score"], 72.0)
        self.assertEqual(report["summary"]["risk_score"], 72.0)
        self.assertEqual(report["optimization"]["unique_finding_count"], 1)

    def test_aggregate_is_bounded_and_deduplicated(self):
        finding = {
            "id": "dup",
            "scanner_id": "sqli",
            "severity": "critical",
            "confidence": "confirmed",
            "status": "confirmed",
            "endpoint": "/x",
        }
        report = {
            "summary": {},
            "results": [
                {"summary": {}, "findings": [dict(finding)]},
                {"summary": {}, "findings": [dict(finding)]},
            ],
        }
        optimize_report(report)
        # Same finding id across results must be counted once.
        self.assertEqual(report["optimization"]["unique_finding_count"], 1)
        self.assertLessEqual(report["optimization"]["risk_score"], 100.0)
        self.assertEqual(report["optimization"]["top_finding"]["id"], "dup")


if __name__ == "__main__":
    unittest.main()
