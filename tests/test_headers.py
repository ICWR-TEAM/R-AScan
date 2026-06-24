import argparse
import unittest
from unittest.mock import patch

from r_ascan.app import RAScan, build_parser, merge_headers, parse_headers
from r_ascan.config import HTTP_HEADERS


class HeaderTests(unittest.TestCase):
    def test_repeatable_cli_headers(self):
        args = build_parser().parse_args([
            "-x", "example.com",
            "-H", "X-API-Key: one",
            "--headers", "Accept: application/json",
            "-H", "x-api-key: two",
        ])
        self.assertEqual(
            args.headers,
            [
                "X-API-Key: one",
                "Accept: application/json",
                "x-api-key: two",
            ],
        )

    def test_duplicate_header_last_value_wins_case_insensitively(self):
        headers = parse_headers([
            "X-API-Key: one",
            "x-api-key: two",
            "Cookie: session=abc",
        ])
        self.assertEqual(headers["x-api-key"], "two")
        self.assertNotIn("X-API-Key", headers)

    def test_merge_replaces_default_case_insensitively(self):
        headers = merge_headers(
            {"User-Agent": "default", "Accept": "*/*"},
            {"user-agent": "custom"},
        )
        self.assertEqual(headers["user-agent"], "custom")
        self.assertNotIn("User-Agent", headers)
        self.assertEqual(headers["Accept"], "*/*")

    def test_rejects_malformed_or_injected_header(self):
        with self.assertRaisesRegex(ValueError, "expected"):
            parse_headers(["Invalid"])
        with self.assertRaisesRegex(ValueError, "CR or LF"):
            parse_headers(["X-Test: safe\r\nInjected: true"])

    def test_headers_propagate_to_legacy_dictionary(self):
        args = argparse.Namespace(
            target="example.com",
            port=None,
            path="/",
            threads=1,
            max_requests=1,
            timeout=1,
            insecure=False,
            mode="passive",
            verbose=False,
            proxy=None,
            headers=["X-Test: first", "x-test: final"],
            authorization=None,
            cookie=None,
        )
        original = dict(HTTP_HEADERS)
        try:
            with patch("r_ascan.app.ScanContext.create"):
                RAScan(args)
            self.assertEqual(HTTP_HEADERS["x-test"], "final")
        finally:
            HTTP_HEADERS.clear()
            HTTP_HEADERS.update(original)


if __name__ == "__main__":
    unittest.main()
