"""Transport-independent contract tests; these do not prove Feishu behavior."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from io import BytesIO

from feishu_probe import Client, DEMO, ProbeError, make_fields, run


def schema():
    return [{"field_name": name, "type": field_type, "property": prop}
            for name, field_type, prop in [
                ("FNSKU", 1, {}), ("商品名称", 1, {}), ("商品信息", 1, {}),
                ("箱规数量", 2, {}),
                ("国家站点", 3, {"options": [{"name": "美国"}]}),
                ("商品标签", 3, {"options": [{"name": "常规"}]})]]


class StubClient:
    def __init__(self):
        self.saved = None
        self.calls = []
        self.fail_create_once = False

    def login(self):
        pass

    def fields(self):
        return schema()

    def create(self, key, fields):
        self.calls.append((key, copy.deepcopy(fields)))
        if self.saved is None:
            self.saved = {"record_id": "rec-test", "fields": copy.deepcopy(fields)}
        if self.fail_create_once:
            self.fail_create_once = False
            raise ProbeError("Injected lost response")
        return copy.deepcopy(self.saved)

    def get(self, record_id):
        return copy.deepcopy(self.saved)

    def update(self, record_id, fields):
        self.saved["fields"].update(fields)
        return copy.deepcopy(self.saved)


class ProbeTests(unittest.TestCase):
    def test_non_demo_target_rejected(self):
        with self.assertRaises(ProbeError):
            Client({"app_token": "real-production", "table_id": DEMO[1]})

    def test_missing_field_fails_before_write(self):
        with self.assertRaises(ProbeError):
            make_fields(schema()[:-1], "key")

    def test_selection_does_not_create_new_option(self):
        fields = schema()
        fields[-1]["property"]["options"] = []
        with self.assertRaises(ProbeError):
            make_fields(fields, "key")

    def test_quantity_matches_field_type(self):
        fields = schema()
        self.assertEqual(make_fields(fields, "key")["箱规数量"], 50)
        fields[3]["type"] = 1
        self.assertEqual(make_fields(fields, "key")["箱规数量"], "50")

    def test_read_only_mode_does_not_create(self):
        with tempfile.TemporaryDirectory() as folder:
            client = StubClient()
            report = run(client, Path(folder), False)
            self.assertEqual(report["tests"]["read_schema"], "PASS")
            self.assertEqual(client.calls, [])
            self.assertFalse((Path(folder) / "probe_state.local.json").exists())

    def test_lost_response_reuses_durable_key_and_payload(self):
        with tempfile.TemporaryDirectory() as folder:
            client = StubClient()
            client.fail_create_once = True
            first = run(client, Path(folder), True)
            self.assertIn("error", first)
            self.assertTrue((Path(folder) / "probe_state.local.json").exists())
            second = run(client, Path(folder), True)
            self.assertNotIn("error", second)
            self.assertEqual(len(client.calls), 3)
            self.assertTrue(all(call == client.calls[0] for call in client.calls))
            self.assertEqual(second["test_record_id"], "rec-test")

    def test_changed_record_id_stops_before_update(self):
        with tempfile.TemporaryDirectory() as folder:
            client = StubClient()
            run(client, Path(folder), True)
            client.saved["record_id"] = "different"
            result = run(client, Path(folder), True)
            self.assertIn("error", result)

    def test_http_error_does_not_print_secret(self):
        client = Client({"app_token": DEMO[0], "table_id": DEMO[1], "app_secret": "test-secret"})
        response = BytesIO(json.dumps({"code": 91403, "msg": "test-secret"}).encode())
        error = HTTPError("https://open.feishu.cn", 403, "Forbidden", {}, response)
        with patch.object(client.opener, "open", side_effect=error):
            with self.assertRaises(ProbeError) as caught:
                client.request("GET", "/example")
        self.assertIn("91403", str(caught.exception))
        self.assertNotIn("test-secret", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
