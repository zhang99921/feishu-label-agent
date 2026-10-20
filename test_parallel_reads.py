import copy
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from feishu_probe import ProbeError
from pallet_codes import Allocator
from workflow_store import Conflict, Store, TestPrincipal, Workflow, writer_gate


class ParallelReadTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = patch("workflow_store.ROOT", Path(tmp.name))
        root.start()
        self.addCleanup(root.stop)
        self.store = Store(type("ClientFixture", (), {"supports_parallel_reads": True})(),
                           {"tables": {k:k for k in ("units", "operations", "codes")}})

    def test_reads_overlap_and_results_are_copied(self):
        barrier = threading.Barrier(3)
        def listing(path):
            barrier.wait(timeout=3)
            return [{"field": path}]
        self.store.list_path = listing
        with writer_gate(), self.store.read_scope():
            self.store.prefetch(("units", "operations", "codes"))
            result = self.store.records("units")
            result[0]["field"] = "changed"
            self.assertNotEqual(self.store.records("units"), result)

    def test_one_failed_read_joins_all_and_publishes_no_partial_snapshot(self):
        barrier = threading.Barrier(3)
        finished = set()
        def listing(path):
            key = path.split("/")[-2]
            barrier.wait(timeout=3)
            if key == "operations":
                raise ProbeError("offline")
            finished.add(key)
            return []
        self.store.list_path = listing
        with writer_gate(), self.store.read_scope():
            with self.assertRaises(ProbeError):
                self.store.prefetch(("units", "operations", "codes"))
            self.assertEqual(finished, {"units", "codes"})
            self.assertEqual(self.store._reads.cache, {})

    def fixtures(self):
        data = {
            "units": [{"record_id": "u", "fields": {"货物ID": "test", "批次": ["b"], "当前库位": ["a"],
                        "状态": "在区", "记录版本": 1, "最近操作ID": "op"}}],
            "operations": [{"fields": {"货物": ["u"], "阶段": "PREPARED"}}],
            "codes": [{"record_id": "c", "fields": {"库位码": "A1", "绑定托盘": ["u"],
                        "状态": "占用", "记录版本": 1, "冷却截止": 0}}]}
        self.store.list_path = lambda path: copy.deepcopy(data[path.split("/")[-2]])
        return data

    def test_query_matches_serial_and_preserves_pending_status(self):
        self.fixtures()
        workflow = Workflow(self.store, Allocator(self.store))
        principal = TestPrincipal("test", "query", "b")
        parallel = workflow.query("test", principal)
        workflow.parallel_queries = False
        self.assertEqual(workflow.query("test", principal), parallel)
        self.assertEqual(parallel["status"], "PENDING_RECONCILIATION")

    def test_prefetch_does_not_skip_duplicate_or_scope_guards(self):
        data = self.fixtures()
        workflow = Workflow(self.store, Allocator(self.store))
        with self.assertRaises(PermissionError):
            workflow.query("test", TestPrincipal("test", "query", "other"))
        data["units"].append(copy.deepcopy(data["units"][0]))
        with self.assertRaises(Conflict):
            workflow.query("test", TestPrincipal("test", "query", "b"))

    def test_role_rejected_before_any_reads(self):
        self.store.list_path = lambda path: self.fail("unauthorized read")
        with self.assertRaises(PermissionError):
            Workflow(self.store).query("test", TestPrincipal("test", "denied", "b"))


if __name__ == "__main__":
    unittest.main()
