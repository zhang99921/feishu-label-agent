import unittest
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from feishu_probe import Client, DEMO, ProbeError
from pallet_codes import Allocator
from workflow_store import Conflict


def code(until=600000, owner=None, state="冷却", enabled=True):
    return {"record_id": "code-1", "fields": {"库位码": "A001", "仓库": ["warehouse-a"],
            "绑定托盘": owner or [], "状态": state, "冷却截止": until,
            "记录版本": 1, "启用": enabled}}


class AllocatorTests(unittest.TestCase):
    def test_cooldown_exact_boundary(self):
        row = code()
        self.assertFalse(Allocator.eligible(row, ["warehouse-a"], 599999))
        self.assertTrue(Allocator.eligible(row, ["warehouse-a"], 600000))

    def test_cannot_allocate_bound_disabled_or_other_warehouse(self):
        self.assertFalse(Allocator.eligible(code(owner=["one"], state="占用"), ["warehouse-a"], 999999))
        self.assertFalse(Allocator.eligible(code(enabled=False), ["warehouse-a"], 999999))
        self.assertFalse(Allocator.eligible(code(), ["warehouse-b"], 999999))

    def test_duplicate_names_or_owners_fail_closed(self):
        for rows in [[code(), code()], [code(owner=["one"], state="占用"),
                    {"record_id": "code-2", "fields": dict(code(owner=["one"], state="占用")["fields"], 库位码="A002")}],
                    [code(owner=["one", "two"], state="冷却")]]:
            with self.subTest(rows=rows):
                with patch.object(Allocator, "__init__", lambda self, store: setattr(self, "store", store)):
                    class Fixture:
                        def records(self, _):
                            return rows
                    with self.assertRaises(Conflict):
                        Allocator(Fixture()).records()


class TransportFailureTests(unittest.TestCase):
    def client(self):
        return Client({"app_token": DEMO[0], "table_id": DEMO[1]})

    def test_offline_failure_has_no_success_and_no_automatic_retry(self):
        client = self.client()
        with patch.object(client.opener, "open", side_effect=URLError("offline")) as call:
            with self.assertRaises(ProbeError):
                client.request("POST", "/test", {"fields": {}})
            self.assertEqual(call.call_count, 1)

    def test_rate_limit_failure_has_no_success_and_no_automatic_retry(self):
        client = self.client()
        error = HTTPError("https://open.feishu.cn", 429, "Too Many Requests", {},
                          BytesIO(b'{"code":99991400,"msg":"rate limited"}'))
        with patch.object(client.opener, "open", side_effect=error) as call:
            with self.assertRaises(ProbeError) as caught:
                client.request("POST", "/test", {"fields": {}})
            self.assertIn("429", str(caught.exception))
            self.assertEqual(call.call_count, 1)

    def test_invalid_json_not_interpreted_as_success(self):
        client = self.client()
        with patch.object(client.opener, "open", return_value=BytesIO(b'upstream unavailable')):
            with self.assertRaises(ProbeError):
                client.request("GET", "/test")

    def test_wrong_response_shape_not_interpreted_as_success(self):
        client = self.client()
        with patch.object(client.opener, "open", return_value=BytesIO(b'[]')):
            with self.assertRaises(ProbeError):
                client.request("GET", "/test")


if __name__ == "__main__":
    unittest.main()
