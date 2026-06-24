import unittest

from r_ascan.app import build_parser


class DefaultBehaviorTests(unittest.TestCase):
    def test_all_scanners_and_html_are_default(self):
        args = build_parser().parse_args(["-x", "example.com"])
        self.assertEqual(args.mode, "exploit")
        self.assertFalse(args.no_html)

    def test_safe_mode_and_no_html_are_available(self):
        args = build_parser().parse_args([
            "-x", "example.com",
            "--mode", "safe-active",
            "--no-html",
        ])
        self.assertEqual(args.mode, "safe-active")
        self.assertTrue(args.no_html)


if __name__ == "__main__":
    unittest.main()
