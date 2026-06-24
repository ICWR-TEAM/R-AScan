import unittest
from pathlib import Path

from r_ascan.core.registry import inferred_metadata, selected


class RegistryTests(unittest.TestCase):
    def test_exploit_path_is_not_safe_active(self):
        metadata = inferred_metadata(Path("scanners/exploits/example.py"))
        self.assertEqual(metadata.mode, "exploit")
        self.assertFalse(
            selected(
                metadata,
                max_mode="safe-active",
                include=set(),
                exclude=set(),
                categories=set(),
            )
        )

    def test_explicit_include_and_exclude(self):
        metadata = inferred_metadata(Path("scanners/sqli.py"))
        self.assertTrue(
            selected(
                metadata,
                max_mode="safe-active",
                include={"sqli"},
                exclude=set(),
                categories=set(),
            )
        )
        self.assertFalse(
            selected(
                metadata,
                max_mode="safe-active",
                include={"sqli"},
                exclude={"sqli"},
                categories=set(),
            )
        )


if __name__ == "__main__":
    unittest.main()
