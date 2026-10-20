import unittest

from audit_demo_roles import inspect_role
from set_demo_query_readonly import canonical_role


class RoleAuditTests(unittest.TestCase):
    def test_role_table_order_does_not_hide_or_invent_permission_changes(self):
        first = {"role_id":"r","table_roles":[{"table_id":"b","table_perm":2},{"table_id":"a","table_perm":1}]}
        reordered = {**first,"table_roles":list(reversed(first["table_roles"]))}
        self.assertEqual(canonical_role(first),canonical_role(reordered))
        changed = {**reordered,"table_roles":[{"table_id":"a","table_perm":2},{"table_id":"b","table_perm":2}]}
        self.assertNotEqual(canonical_role(first),canonical_role(changed))

    def check_role(self, business_role, permission=2, members=()):
        tables = {key:key for key in ("batches","locations","units","codes","operations","audits")}
        native = {"role_name":"test", "table_roles":[
            {"table_id":key,"table_perm":permission,"allow_delete_record":True} for key in tables]}
        return inspect_role(native,members,{"role_id":"roltest","expected_name":"test","business_role":business_role},tables)

    def test_query_business_allowlist_never_inherits_native_edit(self):
        result = self.check_role("query")
        self.assertEqual([a for a,v in result["business_capability_matrix"].items() if v],["QUERY"])
        self.assertIn("QUERY_ROLE_CAN_EDIT_TEST_BUSINESS_TABLES_DIRECTLY",result["issues"])

    def test_operator_cannot_correct_or_undo_even_with_native_manage(self):
        result = self.check_role("operator",4)
        self.assertFalse(result["business_capability_matrix"]["CORRECT"])
        self.assertFalse(result["business_capability_matrix"]["UNDO"])
        self.assertTrue(result["business_capability_matrix"]["PARTIAL_OUT"])

    def test_named_admin_with_no_members_does_not_prove_login_authorization(self):
        result = self.check_role("admin")
        self.assertTrue(result["business_capability_matrix"]["CORRECT"])
        self.assertEqual(result["explicit_member_count"],0)
        self.assertIn("NO_EXPLICIT_ROLE_MEMBERS",result["issues"])
        self.assertFalse(result["query_native_field_gate_satisfied"])

    def test_read_only_native_permissions_do_not_report_direct_edit(self):
        result = self.check_role("query",1)
        self.assertNotIn("QUERY_ROLE_CAN_EDIT_TEST_BUSINESS_TABLES_DIRECTLY",result["issues"])


if __name__ == "__main__":
    unittest.main()
