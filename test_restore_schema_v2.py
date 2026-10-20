import copy
import tempfile
import unittest
from pathlib import Path

from feishu_probe import ProbeError
from restore_schema_v2 import ORDER, checksum, restore, schema_field, skeleton
from workflow_store import Conflict


class MemoryDestination:
    def __init__(self):
        self.path = "/tables"
        self.manifest = {"tables": {key: "source-" + key for key in ORDER}}
        self.config = {"table_id": "product"}
        self.client = self
        self.tables = {}
        self.fail_after_write = False

    def list_path(self, path):
        if path == self.path:
            return [{"table_id": key, "name": value["name"]} for key,value in self.tables.items()]
        _, table_id, kind = path.rsplit("/", 2)
        return copy.deepcopy(self.tables[table_id][kind])

    def request(self, method, path, body=None, query=None):
        if path == self.path:
            value = body["table"]
            table_id = "target-" + str(len(self.tables))
            self.tables[table_id] = {"name": value["name"], "fields": copy.deepcopy(value["fields"]), "records": []}
            return {"data": {"table_id": table_id}}
        parts = path.split("/")
        table_id, kind = parts[2:4]
        if kind == "fields":
            self.tables[table_id][kind].append(copy.deepcopy(body))
            return {"data": {}}
        rows = self.tables[table_id]["records"]
        if method == "POST":
            row = {"record_id": table_id + "-row-" + str(len(rows)), "fields": copy.deepcopy(body["fields"])}
            rows.append(row)
            return {"data": {"record": copy.deepcopy(row)}}
        row = next(r for r in rows if r["record_id"] == parts[4])
        row["fields"].update(copy.deepcopy(body["fields"]))
        if self.fail_after_write:
            self.fail_after_write = False
            raise ProbeError("write succeeded but response lost")
        return {"data": {"record": copy.deepcopy(row)}}


def snapshot():
    tables = {}
    for key in ORDER:
        tables[key] = {"table_id": "source-" + key,
                       "schema": [{"field_name": "ID", "type": 1}], "records": []}
    tables["operations"]["schema"] += [
        {"field_name": "关联原操作", "type": 18, "property": {"table_id": "source-operations", "multiple": False}},
        {"field_name": "变更后JSON", "type": 1}]
    tables["operations"]["records"] = [
        {"record_id": "old-1", "fields": {"ID": "one", "关联原操作": ["old-2"], "变更后JSON": '{"unit":"old-2"}'}},
        {"record_id": "old-2", "fields": {"ID": "two"}}]
    return {"run_id": "test-run", "tables": tables}


class RestoreV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "state.json"
        self.store = MemoryDestination()
        self.state = {"tables": {}, "records": {}, "request_tokens": {}, "verified": {}}

    def test_forward_self_link_and_json_remap(self):
        value = snapshot()
        restore(self.store, value, self.state, self.path)
        target = self.state["tables"]["operations"]
        rows = self.store.tables[target]["records"]
        self.assertEqual(rows[0]["fields"]["关联原操作"], [rows[1]["record_id"]])
        self.assertIn(rows[1]["record_id"], rows[0]["fields"]["变更后JSON"])
        link_spec = next(s for s in self.store.tables[target]["fields"] if s["type"] == 18)
        self.assertEqual(link_spec["property"]["table_id"], target)

    def test_write_reply_loss_resumes_without_duplicate_records(self):
        self.store.fail_after_write = True
        with self.assertRaises(ProbeError):
            restore(self.store, snapshot(), self.state, self.path)
        restore(self.store, snapshot(), self.state, self.path)
        self.assertEqual(len(self.store.tables[self.state["tables"]["operations"]]["records"]), 2)

    def test_completed_destination_edit_is_not_overwritten(self):
        restore(self.store, snapshot(), self.state, self.path)
        rows = self.store.tables[self.state["tables"]["operations"]]["records"]
        rows[0]["fields"]["关联原操作"] = []
        with self.assertRaises(Conflict):
            restore(self.store, snapshot(), self.state, self.path)
        self.assertEqual(rows[0]["fields"]["关联原操作"], [])

    def test_skeleton_omits_source_links_and_embedded_json(self):
        source = snapshot()["tables"]["operations"]
        self.assertEqual(skeleton(source["records"][0]["fields"], source["schema"]), {"ID": "one"})

    def test_missing_schema_dependency_fails_closed(self):
        spec = snapshot()["tables"]["operations"]["schema"][1]
        with self.assertRaises(Conflict):
            schema_field(spec, {})

    def test_checksum_detects_table_content_changes(self):
        value = snapshot()
        initial = checksum(value)
        value["tables"]["operations"]["records"][0]["fields"]["ID"] = "changed"
        self.assertNotEqual(checksum(value), initial)


if __name__ == "__main__":
    unittest.main()
