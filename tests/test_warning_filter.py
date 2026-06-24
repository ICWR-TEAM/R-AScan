import unittest
import warnings

from urllib3.exceptions import InsecureRequestWarning

import r_ascan.app  # noqa: F401


class WarningFilterTests(unittest.TestCase):
    def test_insecure_request_warning_is_hidden_globally(self):
        matching = [
            entry
            for entry in warnings.filters
            if entry[0] == "ignore" and entry[2] is InsecureRequestWarning
        ]
        self.assertTrue(matching)

    def test_other_warnings_remain_visible(self):
        with warnings.catch_warnings(record=True) as captured:
            warnings.warn("visible", RuntimeWarning)
        self.assertEqual(len(captured), 1)
        self.assertIs(captured[0].category, RuntimeWarning)


if __name__ == "__main__":
    unittest.main()
