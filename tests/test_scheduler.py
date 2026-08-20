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

    def test_per_thread_scope_counting(self):
        budget = RequestBudget(concurrency=2, maximum=10)
        budget.begin_scope()
        budget.acquire()
        budget.release()
        budget.acquire()
        budget.release()
        self.assertEqual(budget.scope_count(), 2)
        self.assertEqual(budget.count, 2)

    def test_scope_is_isolated_between_threads(self):
        import threading

        budget = RequestBudget(concurrency=4, maximum=100)
        budget.begin_scope()
        budget.acquire()
        budget.release()
        other_scope = {}

        def worker():
            budget.begin_scope()
            for _ in range(3):
                budget.acquire()
                budget.release()
            other_scope["count"] = budget.scope_count()

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

        # Each thread tracks only its own requests; the global count is shared.
        self.assertEqual(budget.scope_count(), 1)
        self.assertEqual(other_scope["count"], 3)
        self.assertEqual(budget.count, 4)


if __name__ == "__main__":
    unittest.main()
