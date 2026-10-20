import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from feishu_probe import ProbeError
from workflow_store import Conflict, Store, writer_gate


class ReadScopeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = patch("workflow_store.ROOT", Path(temporary.name))
        root.start()
        self.addCleanup(root.stop)
        self.store = Store(None, {"tables": {"operations": "test"}})
        self.calls = 0
        self.version = 1
        def listing(path):
            self.calls += 1
            return [{"fields": {"version": self.version}}]
        self.store.list_path = listing

    def test_no_reuse_outside_scope_or_across_requests(self):
        self.store.records("operations")
        self.store.records("operations")
        for _ in range(2):
            with writer_gate(), self.store.read_scope():
                self.store.records("operations")
                self.store.records("operations")
        self.assertEqual(self.calls, 4)

    def test_nested_scope_copies_returned_rows(self):
        with writer_gate(), self.store.read_scope():
            self.store.records("operations")[0]["fields"]["version"] = 99
            with self.store.read_scope():
                self.assertEqual(self.store.records("operations")[0]["fields"]["version"], 1)
        self.assertEqual(self.calls, 1)

    def test_uncertain_write_cannot_leave_cached_state(self):
        class FailingClient:
            def request(inner, *args):
                self.version = 2
                raise ProbeError("response lost")
        self.store.client = FailingClient()
        with writer_gate(), self.store.read_scope():
            self.store.records("operations")
            with self.assertRaises(ProbeError):
                self.store.update("operations", "row", {})
            self.assertEqual(self.store.records("operations")[0]["fields"]["version"], 2)
        self.assertEqual(self.calls, 2)

    def test_scope_requires_lock_and_exception_clears_cache(self):
        with self.assertRaises(Conflict):
            with self.store.read_scope():
                pass
        with self.assertRaises(ValueError):
            with writer_gate(), self.store.read_scope():
                self.store.records("operations")
                raise ValueError("stop")
        self.assertIsNone(self.store._reads.cache)


if __name__ == "__main__":
    unittest.main()
