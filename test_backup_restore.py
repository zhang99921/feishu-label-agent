import json
import unittest
import tempfile
import uuid
from pathlib import Path

from backup_restore_test import remap, writable
from workflow_store import Conflict, Store, TestPrincipal, Workflow


class BackupTests(unittest.TestCase):
    def test_remap_exact_ids_preserves_other_text(self):
        value = {"owner": ["rec-old"], "note": "prefix-rec-old", "version": 3}
        self.assertEqual(remap(value, {"rec-old": "rec-new"}),
                         {"owner": ["rec-new"], "note": "prefix-rec-old", "version": 3})

    def test_restore_link_requires_mapped_record(self):
        schema = [{"field_name": "批次", "type": 18}]
        with self.assertRaises(Conflict):
            writable({"批次": ["rec-missing"]}, schema, {})

    def test_remaps_json_resource_history(self):
        schema = [{"field_name": "资源变更JSON", "type": 1}]
        value = {"资源变更JSON": json.dumps([{"id": "code-old", "after": {"owner": ["unit-old"]}}])}
        result = writable(value, schema, {"code-old": "code-new", "unit-old": "unit-new"})
        self.assertEqual(json.loads(result["资源变更JSON"]),
                         [{"id": "code-new", "after": {"owner": ["unit-new"]}}])

    def test_preserves_zero_and_false_fields(self):
        schema = [{"field_name": "启用", "type": 7}, {"field_name": "版本", "type": 2}]
        self.assertEqual(writable({"启用": False, "版本": "0"}, schema), {"启用": False, "版本": 0})

    def test_empty_association_omitted_on_both_sides(self):
        schema = [{"field_name": "库位", "type": 18}]
        self.assertEqual(writable({"库位": [{"type": "text", "text_arr": []}]}, schema), {})
        self.assertEqual(writable({}, schema), {})

    def test_restored_writer_uses_its_own_manifest_and_tables(self):
        class ClientFixture:
            called_path = None
            def request(self, method, path, body, query):
                self.called_path = path
                return {"data": {"record": {"record_id": "rec-clone"}}}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "clone.json"
            manifest = {"run_id": str(uuid.uuid4()), "tables": {"units": "tbl-clone"}}
            path.write_text(json.dumps(manifest), encoding="utf-8")
            client = ClientFixture()
            store = Store(client, manifest, manifest_path=path)
            store.create("units", "one", {"货物ID": "test"})
            self.assertTrue(client.called_path.endswith('/tbl-clone/records'))
            self.assertIn("units:one", json.loads(path.read_text(encoding="utf-8"))["request_tokens"])

    def test_restore_alias_cannot_cross_principal_scope(self):
        workflow = Workflow(None, restored_batch_aliases={"old": "restored-batch"})
        request = dict(unit="test", action="IN", expected_version=0, batch="old", location="test")
        with self.assertRaises(PermissionError):
            workflow.submit("one", request, TestPrincipal("actor", "operator", "other-batch"))


if __name__ == "__main__":
    unittest.main()
