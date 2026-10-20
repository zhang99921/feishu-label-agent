"""HTTP integration with an explicit business spy, no Feishu login or writes."""
import asyncio
import unittest
from unittest.mock import Mock

import httpx

from finding_assistant.adapters.feishu.client import ProbeError
from finding_assistant.application.workflow import Conflict
from finding_assistant.domain.quantity_rules import RuleError
from finding_assistant.interfaces.http.app import create_app
from finding_assistant.security.errors import AccessDenied,AuthorizationUnavailable
from finding_assistant.security.login import AuthenticationError

BASE={"unit":"pallet-one","batch":"batch-one","expected_version":1}
HEADERS={"Authorization":"Bearer fixture-session","Idempotency-Key":"stable-key:1"}


class HttpApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_routes_and_wrong_methods_use_standard_error_envelope(self):
        for method,path,status,code in (("GET","/missing",404,"NOT_FOUND"),
            ("POST","/health/live",405,"METHOD_NOT_ALLOWED")):
            result=await self.client.request(method,path)
            self.assertEqual(result.status_code,status)
            self.assertEqual(result.json()["error"]["code"],code)
            self.assertEqual(result.json()["error"]["request_id"],result.headers["x-request-id"])

    async def test_duplicate_session_or_idempotency_headers_are_rejected(self):
        result=await self.client.get("/api/v1/inventory/pallet",params={"batch":"batch"},
            headers=[("Authorization","Bearer fixture-one"),("Authorization","Bearer fixture-two")])
        self.assertEqual(result.status_code,401)
        result=await self.client.post("/api/v1/movements/outbound",json=BASE,
            headers=[("Authorization","Bearer fixture-session"),("Idempotency-Key","one"),("Idempotency-Key","two")])
        self.assertEqual(result.status_code,422)
        self.backend.query.assert_not_called()
        self.backend.submit.assert_not_called()

    async def asyncSetUp(self):
        self.backend=Mock()
        self.backend.query.return_value={"status":"CONFIRMED"}
        self.backend.submit.return_value={"status":"DONE"}
        self.app=create_app(self.backend)
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app,raise_app_exceptions=False),base_url="http://test")

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_default_application_alive_but_business_not_ready(self):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()),base_url="http://test") as client:
            self.assertEqual((await client.get("/health/live")).status_code,200)
            self.assertEqual((await client.get("/health/ready")).status_code,503)
            result=await client.get("/api/v1/inventory/pallet",params={"batch":"batch"},headers=HEADERS)
            self.assertEqual(result.status_code,503)
            self.assertEqual(result.json()["error"]["code"],"BACKEND_NOT_READY")

    async def test_missing_or_malformed_login_never_reaches_backend(self):
        for value in (None,"Basic token","Bearer ","Bearer two tokens","Bearer "+"x"*513):
            headers={} if value is None else {"Authorization":value}
            result=await self.client.get("/api/v1/inventory/pallet",params={"batch":"batch"},headers=headers)
            self.assertEqual(result.status_code,401)
            self.assertEqual(result.headers["www-authenticate"],"Bearer")
        self.backend.query.assert_not_called()

    async def test_query_forwards_opaque_session_without_accepting_caller_role(self):
        result=await self.client.get("/api/v1/inventory/pallet-one",params={"batch":"batch-one"},headers=HEADERS)
        self.assertEqual(result.status_code,200)
        self.backend.query.assert_called_once_with("fixture-session","pallet-one","batch-one")
        self.backend.reset_mock()
        result=await self.client.get("/api/v1/inventory/pallet-one",params={"batch":"batch-one","role":"admin"},headers=HEADERS)
        self.assertEqual(result.status_code,422)
        self.backend.query.assert_not_called()

    async def test_all_seven_command_routes_keep_fixed_actions(self):
        commands=(
            ("movements/inbound","IN",{"location":"TEST-A"}),
            ("movements/outbound","OUT",{}),
            ("movements/transfer","MOVE",{"location":"TEST-B"}),
            ("movements/partial-outbound","PARTIAL_OUT",{"boxes":2}),
            ("movements/reentry","REENTER",{"location":"TEST-A","boxes":3,"confirmed":True}),
            ("administration/corrections","CORRECT",{"boxes":3,"reference":"original","reason":"checked","confirmed":True}),
            ("administration/undo","UNDO",{"reference":"original","reason":"checked","confirmed":True}),
        )
        for route,action,extra in commands:
            payload={**BASE,**extra}
            result=await self.client.post("/api/v1/"+route,json=payload,headers=HEADERS)
            self.assertEqual(result.status_code,200,result.text)
            expected={**payload,"action":action}
            expected.setdefault("location",None)
            self.backend.submit.assert_called_with("fixture-session","stable-key:1",expected)
            self.assertNotIn("action",payload)

    async def test_actor_role_and_action_injection_are_rejected(self):
        for key in ("actor","role","action","open_id","tenant_key","session_id"):
            result=await self.client.post("/api/v1/movements/outbound",json={**BASE,key:"override"},headers=HEADERS)
            self.assertEqual(result.status_code,422)
        self.backend.submit.assert_not_called()

    async def test_versions_are_strict_nonnegative_integers(self):
        for version in (True,-1,1.5,"1",None):
            result=await self.client.post("/api/v1/movements/outbound",json={**BASE,"expected_version":version},headers=HEADERS)
            self.assertEqual(result.status_code,422)
        self.backend.submit.assert_not_called()

    async def test_partial_quantities_cannot_be_coerced_or_nonpositive(self):
        for boxes in (True,0,-1,1.2,"2",None):
            result=await self.client.post("/api/v1/movements/partial-outbound",json={**BASE,"boxes":boxes},headers=HEADERS)
            self.assertEqual(result.status_code,422)
        self.backend.submit.assert_not_called()

    async def test_admin_reason_and_real_boolean_confirmation_required(self):
        valid={**BASE,"reference":"original","reason":"checked","confirmed":True}
        for patch in ({"reason":" "},{"confirmed":False},{"confirmed":"true"},{"confirmed":1},{"reference":""}):
            result=await self.client.post("/api/v1/administration/undo",json={**valid,**patch},headers=HEADERS)
            self.assertEqual(result.status_code,422)
        self.backend.submit.assert_not_called()

    async def test_reentry_requires_explicit_box_count_and_confirmation(self):
        valid={**BASE,"location":"TEST-A","boxes":3,"confirmed":True}
        for field in ("boxes","confirmed"):
            payload={k:v for k,v in valid.items() if k!=field}
            result=await self.client.post("/api/v1/movements/reentry",json=payload,headers=HEADERS)
            self.assertEqual(result.status_code,422)
        self.backend.submit.assert_not_called()

    async def test_idempotency_header_required_bounded_and_preserved(self):
        for value in (None," ","x"*101):
            headers={"Authorization":"Bearer fixture-session"}
            if value is not None:
                headers["Idempotency-Key"]=value
            result=await self.client.post("/api/v1/movements/outbound",json=BASE,headers=headers)
            self.assertEqual(result.status_code,422)
        self.backend.submit.assert_not_called()
        for _ in range(2):
            result=await self.client.post("/api/v1/movements/outbound",json=BASE,headers=HEADERS)
            self.assertEqual(result.status_code,200)
        self.assertEqual([c.args[1] for c in self.backend.submit.call_args_list],["stable-key:1"]*2)

    async def test_expected_errors_have_stable_status_without_raw_details(self):
        cases=((AuthenticationError,401,"AUTHENTICATION_REQUIRED"),
            (AuthorizationUnavailable,503,"AUTHORIZATION_UNAVAILABLE"),
            (AccessDenied,403,"ACCESS_DENIED"),(Conflict,409,"OPERATION_CONFLICT"),
            (RuleError,422,"BUSINESS_RULE_REJECTED"),(ProbeError,503,"UPSTREAM_UNAVAILABLE"))
        for exception,status,code in cases:
            self.backend.query.side_effect=exception("fixture-secret must not leak")
            result=await self.client.get("/api/v1/inventory/pallet",params={"batch":"batch"},headers=HEADERS)
            self.assertEqual(result.status_code,status,result.text)
            self.assertEqual(result.json()["error"]["code"],code)
            self.assertNotIn("fixture-secret",result.text)
            self.assertEqual(result.json()["error"]["request_id"],result.headers["x-request-id"])

    async def test_unexpected_errors_and_access_logs_do_not_echo_tokens_or_input(self):
        self.backend.query.side_effect=RuntimeError("fixture-secret")
        with self.assertLogs("finding_assistant.http",level="INFO") as logs:
            result=await self.client.get("/api/v1/inventory/fixture-secret",params={"batch":"fixture-private-batch"},headers=HEADERS)
        self.assertEqual(result.status_code,500)
        self.assertNotIn("fixture-secret",result.text)
        for sensitive in ("fixture-secret","fixture-private-batch","fixture-session"):
            self.assertNotIn(sensitive," ".join(logs.output))

    async def test_validation_does_not_echo_rejected_values(self):
        result=await self.client.post("/api/v1/movements/outbound",json={**BASE,"role":"fixture-secret"},headers=HEADERS)
        self.assertEqual(result.status_code,422)
        self.assertNotIn("fixture-secret",result.text)
        self.assertEqual(result.json()["error"]["fields"][0]["path"],"body.role")

    async def test_docs_are_opt_in_and_schemas_exclude_identity_fields(self):
        self.assertEqual((await self.client.get("/openapi.json")).status_code,404)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(expose_docs=True)),base_url="http://test") as client:
            schema=(await client.get("/openapi.json")).json()
            self.assertEqual(len([p for p in schema["paths"] if p.startswith("/api/")]),8)
            fields=schema["components"]["schemas"]["Movement"]["properties"]
            self.assertEqual(set(fields),{"unit","batch","expected_version"})

    async def test_parallel_requests_keep_each_session_local_to_the_request(self):
        self.backend.query.side_effect=lambda sid,unit,batch: {"status":"CONFIRMED","unit":unit}
        async def query_one(number):
            return await self.client.get("/api/v1/inventory/pallet-"+number,params={"batch":"batch"},
                headers={"Authorization":"Bearer fixture-"+number})
        results=await asyncio.gather(query_one("one"),query_one("two"))
        self.assertTrue(all(r.status_code==200 for r in results))
        self.assertEqual({(c.args[0],c.args[1]) for c in self.backend.query.call_args_list},
            {("fixture-one","pallet-one"),("fixture-two","pallet-two")})

    async def test_lifespan_closes_injected_resources_once(self):
        close=Mock()
        app=create_app(on_shutdown=close)
        async with app.router.lifespan_context(app):
            close.assert_not_called()
        close.assert_called_once_with()

    async def test_pending_result_is_not_relabelled_success(self):
        self.backend.query.return_value={"status":"PENDING_RECONCILIATION"}
        result=await self.client.get("/api/v1/inventory/pallet",params={"batch":"batch"},headers=HEADERS)
        self.assertEqual(result.json()["data"]["status"],"PENDING_RECONCILIATION")

    async def test_request_ids_are_server_generated_and_responses_not_cached(self):
        first=await self.client.get("/health/live",headers={"X-Request-ID":"client-chosen"})
        second=await self.client.get("/health/live")
        self.assertNotEqual(first.headers["x-request-id"],"client-chosen")
        self.assertNotEqual(first.headers["x-request-id"],second.headers["x-request-id"])
        self.assertEqual(first.headers["cache-control"],"no-store")

    async def test_malformed_json_and_blank_identifiers_do_not_reach_backend(self):
        result=await self.client.post("/api/v1/movements/outbound",content="{broken",headers={**HEADERS,"Content-Type":"application/json"})
        self.assertEqual(result.status_code,422)
        result=await self.client.get("/api/v1/inventory/%20",params={"batch":"batch"},headers=HEADERS)
        self.assertEqual(result.status_code,422)
        self.backend.query.assert_not_called()
        self.backend.submit.assert_not_called()
