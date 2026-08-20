import threading
import time
import unittest
from pathlib import Path

from r_ascan.app import RAScan, build_parser
from r_ascan.core.models import ScannerMetadata


def _args(target="example.com", **overrides):
    parser = build_parser()
    argv = ["--target", target, "--no-html"]
    namespace = parser.parse_args(argv)
    for key, value in overrides.items():
        setattr(namespace, key, value)
    return namespace


class _FakeModule:
    def __init__(self, sink, delay=0.0):
        self._sink = sink
        self._delay = delay

    def scan(self, args):
        self._sink.append(threading.current_thread().name)
        if self._delay:
            time.sleep(self._delay)
        return {}


class ParallelRunnerTests(unittest.TestCase):
    def _runnable(self, count, sink, delay=0.0):
        items = []
        for index in range(count):
            metadata = ScannerMetadata(f"scanner_{index}", f"Scanner {index}", "general")
            items.append((Path(f"scanner_{index}.py"), _FakeModule(sink, delay), metadata))
        return items

    def test_worker_count_auto_scales_with_threads(self):
        scanner = RAScan(_args(threads=8, scanner_workers=0))
        self.assertEqual(scanner._scanner_worker_count(20), 8)
        self.assertEqual(scanner._scanner_worker_count(3), 3)
        self.assertEqual(scanner._scanner_worker_count(0), 1)

    def test_explicit_worker_count_is_respected(self):
        scanner = RAScan(_args(threads=2, scanner_workers=6))
        self.assertEqual(scanner._scanner_worker_count(20), 6)

    def test_results_preserve_discovery_order(self):
        sink = []
        scanner = RAScan(_args(threads=4, scanner_workers=4))
        runnable = self._runnable(6, sink)
        results = scanner._run_scanners(runnable, workers=4)
        ids = [result["scanner"]["id"] for result in results]
        self.assertEqual(ids, [f"scanner_{i}" for i in range(6)])

    def test_scanners_execute_concurrently(self):
        sink = []
        scanner = RAScan(_args(threads=4, scanner_workers=4))
        runnable = self._runnable(4, sink, delay=0.2)
        start = time.monotonic()
        scanner._run_scanners(runnable, workers=4)
        elapsed = time.monotonic() - start
        # Four 0.2s scanners run in parallel finish well under the 0.8s serial sum.
        self.assertLess(elapsed, 0.6)
        self.assertTrue(any(name.startswith("rascan-scanner") for name in sink))


if __name__ == "__main__":
    unittest.main()
