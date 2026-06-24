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
        self.assertEqual(report["results"][0]["findings"][0]["score"], 7.2)
        self.assertEqual(report["optimization"]["engine"], "deterministic-risk-v1")


if __name__ == "__main__":
    unittest.main()
