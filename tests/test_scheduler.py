import unittest

from r_ascan.core.scheduler import RequestBudget


class RequestBudgetTests(unittest.TestCase):
    def test_request_limit(self):
        budget = RequestBudget(concurrency=1, maximum=1)
        budget.acquire()
        budget.release()
        with self.assertRaisesRegex(RuntimeError, "budget exhausted"):
            budget.acquire()

    def test_cancel(self):
        budget = RequestBudget(concurrency=1, maximum=2)
        budget.cancel()
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            budget.acquire()


if __name__ == "__main__":
    unittest.main()
