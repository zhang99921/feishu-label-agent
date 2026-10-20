import asyncio
import importlib
import unittest
from unittest.mock import Mock

from finding_assistant.servers import admin, operations, query
from finding_assistant.servers.contracts import RequestIdentity, ServerRuntime
from finding_assistant.security.errors import AccessDenied
from finding_assistant.security.login import AuthenticationError


class Registry:
    def __init__(self,name):
        self.name,self.tools = name,{}

    def tool(self,*,name,description):
        def register(function):
            if name in self.tools:
                raise AssertionError("duplicate tool")
            self.tools[name] = function
            return function
        return register


class McpBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.workflow = Mock()
        self.resolve = Mock(return_value=RequestIdentity("server-session"))
        self.runtime = ServerRuntime(self.workflow,self.resolve)

    def server(self,module):
        return module.create_server(self.runtime,server_factory=Registry)

    def test_business_servers_register_disjoint_tools(self):
        servers = [self.server(module) for module in (query,operations,admin)]
        names = [set(server.tools) for server in servers]
        self.assertEqual([len(s) for s in names],[1,5,2])
        self.assertTrue(all(not names[i]&names[j] for i in range(3) for j in range(i+1,3)))
        self.assertNotIn("undo_operation",servers[1].tools)

    def test_each_movement_and_admin_tool_keeps_its_fixed_action_and_idempotency_key(self):
        for module in (operations,admin):
            server = self.server(module)
            for spec in module.TOOLS:
                request = {"unit":"pallet","batch":"batch","expected_version":4,"location":None}
                server.tools[spec.name]("stable-key",request)
                self.workflow.submit.assert_called_with("server-session","stable-key",{**request,"action":spec.action})
                self.assertNotIn("action",request)
        self.assertEqual(self.resolve.call_count,7)

    def test_query_only_calls_guarded_query_with_current_transport_identity(self):
        self.server(query).tools["query_inventory"]("pallet","batch")
        self.workflow.query.assert_called_once_with("server-session","pallet","batch")
        self.workflow.submit.assert_not_called()

    def test_tool_cannot_inject_identity_or_change_action(self):
        invoke = self.server(operations).tools["receive_pallet"]
        for key in ("action","role","actor","open_id","tenant_key","session_id"):
            with self.assertRaises(AccessDenied):
                invoke("key",{key:"override"})
        self.workflow.submit.assert_not_called()

    def test_missing_trusted_identity_never_reaches_workflow(self):
        for identity in (None,RequestIdentity(""),"a-model-supplied-session"):
            self.resolve.return_value = identity
            with self.assertRaises(AuthenticationError):
                self.server(query).tools["query_inventory"]("pallet","batch")
        self.workflow.query.assert_not_called()

    def test_concurrent_contexts_resolve_identity_per_call_without_global_actor(self):
        from contextvars import ContextVar
        identity = ContextVar("identity")
        runtime = ServerRuntime(self.workflow,identity.get)
        server = query.create_server(runtime,server_factory=Registry)
        async def run_user(user):
            identity.set(RequestIdentity(user))
            await asyncio.sleep(0)
            server.tools["query_inventory"]("pallet","batch")
        async def run():
            await asyncio.gather(run_user("user-one"),run_user("user-two"))
        asyncio.run(run())
        self.assertEqual([c.args[0] for c in self.workflow.query.call_args_list],["user-one","user-two"])

    def test_denials_propagate_and_do_not_become_success(self):
        self.workflow.submit.side_effect = AccessDenied("denied by live role gate")
        with self.assertRaises(AccessDenied):
            self.server(admin).tools["undo_operation"]("key",{})

    def test_invalid_key_does_not_reach_workflow(self):
        for key in (None,"","x"*101):
            with self.assertRaises(ValueError):
                self.server(operations).tools["receive_pallet"](key,{})
        self.workflow.submit.assert_not_called()

    def test_legacy_imports_are_same_module_not_copied_state(self):
        pairs = {"workflow_store":"finding_assistant.application.workflow",
            "feishu_permissions":"finding_assistant.security.permissions",
            "quantity_rules":"finding_assistant.domain.quantity_rules",
            "feishu_probe":"finding_assistant.adapters.feishu.client"}
        for old,new in pairs.items():
            self.assertIs(importlib.import_module(old),importlib.import_module(new))
