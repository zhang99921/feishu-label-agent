import unittest
from unittest.mock import Mock

from finding_assistant.adapters.feishu.document_access import DocumentAccessDirectory
from finding_assistant.security.errors import AuthorizationUnavailable
from finding_assistant.security.permissions import TableRequirement,assess_requirements
from feishu_probe import ProbeError


class DocumentAccessTests(unittest.TestCase):
    def lookup(self,items):
        client = Mock()
        client.request.return_value = {"data":{"items":items}}
        return DocumentAccessDirectory(client).direct_permission("verified-user")

    def test_exact_user_document_manager_is_distinct_from_default_role(self):
        self.assertEqual(self.lookup([{"member_type":"openid","member_id":"verified-user","perm":"full_access"}]),"full_access")

    def test_app_group_or_other_identity_never_impersonates_user(self):
        for kind in ("appid","openchat","opendepartmentid","userid"):
            self.assertIsNone(self.lookup([{"member_type":kind,"member_id":"verified-user","perm":"full_access"}]))
        self.assertIsNone(self.lookup([{"member_type":"openid","member_id":"other-user","perm":"full_access"}]))

    def test_missing_direct_membership_is_unresolved_not_a_deny_or_default_grant(self):
        self.assertIsNone(self.lookup([]))

    def test_duplicate_or_invalid_permissions_fail_closed(self):
        item={"member_type":"openid","member_id":"verified-user","perm":"edit"}
        with self.assertRaises(AuthorizationUnavailable):
            self.lookup([item,item])
        with self.assertRaises(AuthorizationUnavailable):
            self.lookup([{**item,"perm":"owner-guessed"}])

    def test_incomplete_or_unavailable_api_does_not_infer_identity(self):
        client=Mock()
        client.request.return_value={"data":{"items":None}}
        with self.assertRaises(AuthorizationUnavailable):
            DocumentAccessDirectory(client).direct_permission("user")
        client.request.side_effect=ProbeError("failure")
        with self.assertRaises(AuthorizationUnavailable):
            DocumentAccessDirectory(client).direct_permission("user")

    def test_readonly_write_denial_and_unresolved_read_are_distinguishable(self):
        role={"table_roles":[{"table_id":"units","table_perm":1}]}
        read=assess_requirements(role,(TableRequirement("units",frozenset({"状态"})),))
        write=assess_requirements(role,(TableRequirement("units",frozenset({"状态"}),True),))
        self.assertFalse(read.allowed)
        self.assertEqual(read.reason,"field_permissions_unresolved")
        self.assertFalse(write.allowed)
        self.assertEqual(write.reason,"table_permission_denied")

    def test_explicit_field_read_allows_query_without_allowing_write(self):
        role={"table_roles":[{"table_id":"units","table_perm":1,"field_perm":{"状态":1}}]}
        self.assertTrue(assess_requirements(role,(TableRequirement("units",frozenset({"状态"})),)).allowed)
        self.assertFalse(assess_requirements(role,(TableRequirement("units",frozenset({"状态"}),True),)).allowed)
