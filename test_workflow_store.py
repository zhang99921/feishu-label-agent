import unittest
from feishu_probe import ProbeError
from workflow_store import Workflow, TestPrincipal, links


class ContractTests(unittest.TestCase):
    def test_empty_link_from_actual_list_response(self):
        self.assertEqual(links([{"table_id": "tbl-test", "text_arr": [], "type": "text"}]), [])

    def test_link_formats(self):
        self.assertEqual(links(["rec-one"]), ["rec-one"])
        self.assertEqual(links([{"record_ids": ["rec-one"], "text": "batch"}]), ["rec-one"])

    def test_text_does_not_substitute_for_record_id(self):
        with self.assertRaises(ProbeError):
            links([{"type": "text", "text_arr": ["batch-name"]}])

    def test_role_checked_before_storage_access(self):
        with self.assertRaises(PermissionError):
            Workflow(None).submit("key", {}, TestPrincipal("viewer", "query", "batch"))

    def test_idempotency_fingerprint_includes_actor_and_scope(self):
        request = {"unit": "one"}
        digest = Workflow.fingerprint(request, TestPrincipal("a", "operator", "batch"))
        self.assertNotEqual(digest, Workflow.fingerprint(request, TestPrincipal("b", "operator", "batch")))
        self.assertNotEqual(digest, Workflow.fingerprint(request, TestPrincipal("a", "operator", "other")))


if __name__ == "__main__":
    unittest.main()
