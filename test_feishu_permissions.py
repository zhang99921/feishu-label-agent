import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from feishu_login import AuthenticationError, UserSession
from feishu_permissions import AccessDenied, AuthenticatedWorkflow, AuthorizationUnavailable
from feishu_permissions import Binding, PermissionGate, RoleDirectory, TableRequirement, meets_requirements
from feishu_probe import ProbeError


def role(permission=2, field_permission=3):
    return {"role_id":"roltest", "role_name":"untrusted-name", "table_roles":[
        {"table_id":"units", "table_perm":permission, "field_perm":{"状态":field_permission}}]}


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.login = Mock()
        self.login.session.return_value = UserSession("open-one", "tenant-one", 1000, "token")
        self.directory = Mock()
        self.directory.direct_roles.return_value = [role()]
        self.requirements = {"QUERY":(TableRequirement("units", frozenset({"状态"})),),
            "OUT":(TableRequirement("units", frozenset({"状态"}), True),),
            "CORRECT":(TableRequirement("units", frozenset({"状态"}), True),)}
        self.gate = PermissionGate(self.login, self.directory, "tenant-one",
            [Binding("roltest", "operator", frozenset({"batch-one"}))], self.requirements)

    def test_identity_role_and_scope_come_from_verified_server_context(self):
        principal = self.gate.authorize("opaque-session", "OUT", "batch-one")
        self.assertEqual((principal.actor,principal.role,principal.batch), ("feishu:open-one","operator","batch-one"))
        self.directory.direct_roles.assert_called_once_with("open-one")

    def test_role_revocation_and_downgrade_apply_on_next_request(self):
        self.gate.authorize("sid", "OUT", "batch-one")
        self.directory.direct_roles.return_value = []
        with self.assertRaises(AccessDenied):
            self.gate.authorize("sid", "OUT", "batch-one")
        self.directory.direct_roles.return_value = [role(1,1)]
        with self.assertRaises(AccessDenied):
            self.gate.authorize("sid", "OUT", "batch-one")
        self.gate.authorize("sid", "QUERY", "batch-one")

    def test_wrong_tenant_and_batch_never_grant_access(self):
        with self.assertRaises(AccessDenied):
            self.gate.authorize("sid", "OUT", "another-batch")
        self.login.session.return_value = UserSession("open-one","other-tenant",1000,"token")
        with self.assertRaises(AccessDenied):
            self.gate.authorize("sid", "OUT", "batch-one")

    def test_table_manage_does_not_implicitly_grant_business_admin(self):
        self.directory.direct_roles.return_value = [role(4)]
        with self.assertRaises(AccessDenied):
            self.gate.authorize("sid", "CORRECT", "batch-one")

    def test_explicit_native_admin_binding_is_required(self):
        self.gate.bindings = (Binding("roltest","admin",frozenset({"batch-one"})),)
        self.assertEqual(self.gate.authorize("sid","CORRECT","batch-one").role,"admin")

    def test_role_names_and_wrong_role_ids_do_not_grant(self):
        native = role()
        native.update(role_id="rolother",role_name="管理员")
        self.directory.direct_roles.return_value = [native]
        with self.assertRaises(AccessDenied):
            self.gate.authorize("sid","OUT","batch-one")

    def test_native_row_and_view_restrictions_are_not_silently_dropped(self):
        for key in ("rec_rule","other_rec_rule","view_rules"):
            native = role()
            native["table_roles"][0][key] = {"unsupported":"rule"}
            self.assertFalse(meets_requirements(native,self.requirements["OUT"]))

    def test_v2_add_field_permission_is_not_edit_or_read_permission(self):
        for action in ("QUERY","OUT"):
            self.assertFalse(meets_requirements(role(2,2),self.requirements[action]))

    def test_missing_field_or_table_denies_instead_of_using_app_access(self):
        native = role()
        native["table_roles"][0]["field_perm"] = {}
        self.assertFalse(meets_requirements(native,self.requirements["OUT"]))
        self.assertFalse(meets_requirements({"table_roles":[]},self.requirements["OUT"]))

    def test_unavailable_role_service_and_expired_identity_do_not_fall_back(self):
        self.directory.direct_roles.side_effect = AuthorizationUnavailable("offline")
        with self.assertRaises(AccessDenied):
            self.gate.authorize("sid","OUT","batch-one")
        self.login.session.side_effect = AuthenticationError("expired")
        with self.assertRaises(AuthenticationError):
            self.gate.authorize("sid","OUT","batch-one")

    def test_unconfigured_tenant_or_action_denies(self):
        self.gate.tenant_key = ""
        with self.assertRaises(AccessDenied):
            self.gate.authorize("sid","OUT","batch-one")
        self.gate.tenant_key = "tenant-one"
        for action in ("DROP",None,[]):
            with self.assertRaises(AccessDenied):
                self.gate.authorize("sid",action,"batch-one")

    def test_caller_cannot_supply_role_or_actor_to_guarded_boundary(self):
        workflow = Mock()
        guarded = AuthenticatedWorkflow(workflow,self.gate)
        for field in ("role","actor","open_id","tenant_key"):
            with self.assertRaises(AccessDenied):
                guarded.submit("sid","key",{"action":"OUT","batch":"batch-one",field:"admin"})
        workflow.submit.assert_not_called()

    def test_denied_permission_does_not_reach_business_mutation(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        workflow = Mock()
        with patch("workflow_store.ROOT",Path(temporary.name)), self.assertRaises(AccessDenied):
            AuthenticatedWorkflow(workflow,self.gate).submit("sid","key",{"action":"CORRECT","batch":"batch-one"})
        workflow.submit.assert_not_called()


class DirectoryTests(unittest.TestCase):
    def test_live_empty_member_response_grants_no_membership(self):
        client = Mock()
        client.request.side_effect = [{"data":{"app":{"is_advanced":True}}},
            {"data":{"items":[role()],"has_more":False}},
            {"data":{"items":None,"has_more":False,"total":0}}]
        self.assertEqual(RoleDirectory(client).direct_roles("open-one"), [])

    def test_null_or_missing_pages_cannot_hide_members_or_more_pages(self):
        for data in ({"items":None,"has_more":False,"total":1},
                     {"items":None,"has_more":True,"total":0},
                     {"has_more":False,"total":0},
                     {"items":None,"has_more":False,"total":False}):
            client = Mock()
            client.request.return_value = {"data":data}
            with self.assertRaises(AuthorizationUnavailable):
                RoleDirectory(client)._pages("/members")

    def test_no_advanced_permissions_blocks_before_role_lookup(self):
        client = Mock()
        client.request.return_value = {"data":{"app":{"is_advanced":False}}}
        with self.assertRaises(AuthorizationUnavailable):
            RoleDirectory(client).direct_roles("open-one")
        self.assertEqual(client.request.call_count,1)

    def test_only_direct_verified_user_membership_is_supported(self):
        for member, expected in (({"member_type":"user","open_id":"open-one"},True),
                                 ({"member_type":"user","open_id":"other"},False),
                                 ({"member_type":"chat","open_id":"open-one"},False),
                                 ({"member_type":"department","open_id":"open-one"},False)):
            client = Mock()
            client.request.side_effect = [{"data":{"app":{"is_advanced":True}}},
                {"data":{"items":[role()],"has_more":False}},
                {"data":{"items":[member],"has_more":False}}]
            self.assertEqual(bool(RoleDirectory(client).direct_roles("open-one")),expected)

    def test_incomplete_pagination_and_access_error_block(self):
        client = Mock()
        client.request.return_value = {"data":{"items":[],"has_more":True,"page_token":"same"}}
        with self.assertRaises(AuthorizationUnavailable):
            RoleDirectory(client)._pages("/role-path")
        client.request.side_effect = ProbeError("forbidden")
        with self.assertRaises(AuthorizationUnavailable):
            RoleDirectory(client).direct_roles("user")


if __name__ == "__main__":
    unittest.main()
