"""Actual HTTP + gates + workflow + allocator + audit, with local storage/identity.

The in-memory Feishu client assumes immediate consistency. These tests do not
establish native Feishu permissions, network behavior, durability or server load.
"""
import asyncio
import copy
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx

from administration import Audit,AuditedWorkflow
from feishu_probe import DEMO,ProbeError
from feishu_permissions import AuthenticatedWorkflow,Binding,PermissionGate,TableRequirement
from finding_assistant.interfaces.http.app import create_app
from feishu_login import AuthenticationError
from pallet_codes import Allocator
from workflow_store import Store


class MemoryFeishu:
    """Only fixture record endpoints; no sockets, credentials or production IDs."""
    supports_parallel_reads=False

    def __init__(self):
        self.config={"app_secret":"fixture-secret"}
        self.token="fixture-app-token"
        self.rows={key:{} for key in ("units","codes","locations","batches","operations","audits")}
        self.next_id=0
        self.fail_unit_update_after_commit=False
        self.fail_audit_create=False
        self.creations={}
        self.add("batches","batch-one",{"批次ID":"fixture-batch"})
        for key,label in (("warehouse-a","TEST-A"),("warehouse-b","TEST-B")):
            self.add("locations",key,{"库位码":label,"启用":True})
        for unit in ("pallet-one","pallet-two"):
            self.add("units",unit,{"货物ID":unit,"批次":["batch-one"],"状态":"未入区",
                "记录版本":0,"当前库位":[],"最近操作ID":"","剩余箱数":10,"计量单位":"箱","数量已核实":True})
        for code,warehouse in (("A001","warehouse-a"),("B001","warehouse-b")):
            self.add("codes",code,{"库位码":code,"仓库":[warehouse],"绑定托盘":[],
                "状态":"可用","冷却截止":0,"记录版本":0,"最近操作ID":"","启用":True})

    def add(self,table,identifier,fields):
        self.rows[table][identifier]={"record_id":identifier,"fields":copy.deepcopy(fields)}

    def request(self,method,path,body=None,query=None):
        parts=path.strip("/").split("/")
        assert parts[:5]==["bitable","v1","apps",DEMO[0],"tables"]
        assert parts[5].startswith("fixture-") and parts[6]=="records"
        table=parts[5].removeprefix("fixture-")
        if method=="GET":
            if len(parts)==7:
                return {"data":{"items":copy.deepcopy(list(self.rows[table].values())),"has_more":False}}
            return {"data":{"record":copy.deepcopy(self.rows[table][parts[7]])}}
        if method=="POST":
            if table=="audits" and self.fail_audit_create:
                raise ProbeError("fixture audit delivery unavailable")
            token=query["client_token"]
            if token not in self.creations:
                self.next_id+=1
                identifier="fixture-record-"+str(self.next_id)
                self.add(table,identifier,body["fields"])
                self.creations[token]=(table,identifier)
            stored_table,identifier=self.creations[token]
            assert stored_table==table
            return {"data":{"record":copy.deepcopy(self.rows[table][identifier])}}
        if method=="PUT":
            self.rows[table][parts[7]]["fields"].update(copy.deepcopy(body["fields"]))
            if table=="units" and self.fail_unit_update_after_commit:
                self.fail_unit_update_after_commit=False
                raise ProbeError("fixture response lost after committed unit update")
            return {"data":{"record":copy.deepcopy(self.rows[table][parts[7]])}}
        raise AssertionError("fixture does not allow this request")


class HttpWorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def test_audit_outbox_survives_delivery_failure_and_blocks_new_writes(self):
        self.remote.fail_audit_create=True
        result=await self.post("inbound","bad",unit="not-registered",location="TEST-A")
        self.assertEqual(result.status_code,503)
        queued=json.loads((Path(self.tmp.name)/"audit.json").read_text(encoding="utf-8"))
        self.assertEqual(len(queued),1)
        self.assertEqual((await self.post("inbound","good",location="TEST-A")).status_code,503)
        self.assertEqual((self.state()["version"],len(self.remote.rows["operations"])),(0,0))
        self.remote.fail_audit_create=False
        self.assertEqual((await self.post("inbound","good",location="TEST-A")).status_code,200)
        self.assertEqual(json.loads((Path(self.tmp.name)/"audit.json").read_text(encoding="utf-8")),[])
        self.assertEqual((len(self.remote.rows["audits"]),len(self.remote.rows["operations"])),(1,1))

    async def test_expired_session_cannot_replay_prior_success(self):
        await self.post("inbound","in",location="TEST-A")
        before=copy.deepcopy(self.remote.rows)
        del self.sessions["operator-session"]
        result=await self.post("inbound","in",location="TEST-A")
        self.assertEqual(result.status_code,401)
        self.assertEqual(self.remote.rows,before)

    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="finding-business-test-")
        root=Path(self.tmp.name)
        self.root_patch=patch("workflow_store.ROOT",root)
        self.root_patch.start()
        self.remote=MemoryFeishu()
        manifest={"run_id":str(uuid.uuid4()),"tables":{key:"fixture-"+key for key in self.remote.rows}}
        path=root/"manifest.json"
        path.write_text(json.dumps(manifest),encoding="utf-8")
        self.store=Store(self.remote,manifest,manifest_path=path)
        self.workflow=AuditedWorkflow(self.store,allocator=Allocator(self.store),audit=Audit(self.store,path=root/"audit.json"))
        self.sessions={name+"-session":SimpleNamespace(open_id=name,tenant_key="fixture-tenant") for name in ("operator","query","admin")}
        self.native_roles={name:[{"role_id":"rol"+name,"table_roles":[{"table_id":t,"table_perm":4} for t in manifest["tables"].values()]}] for name in ("operator","query","admin")}
        def session(sid):
            if sid not in self.sessions:
                raise AuthenticationError("fixture session expired")
            return self.sessions[sid]
        requirements={action:tuple(TableRequirement(manifest["tables"][t],frozenset({"fixture-field"}),action!="QUERY")
            for t in ("units","codes","operations")) for action in ("QUERY","IN","OUT","MOVE","PARTIAL_OUT","REENTER","CORRECT","UNDO")}
        gate=PermissionGate(SimpleNamespace(session=session),SimpleNamespace(direct_roles=lambda uid:self.native_roles[uid]),
            "fixture-tenant",[Binding("rol"+name,name,frozenset({"batch-one"})) for name in ("operator","query","admin")],requirements)
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(AuthenticatedWorkflow(self.workflow,gate))),base_url="http://fixture")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.root_patch.stop()
        self.tmp.cleanup()

    async def post(self,route,key,version=0,*,user="operator",unit="pallet-one",batch="batch-one",**extra):
        group="administration" if route in ("corrections","undo") else "movements"
        return await self.client.post("/api/v1/"+group+"/"+route,
            json={"unit":unit,"batch":batch,"expected_version":version,**extra},
            headers={"Authorization":"Bearer "+user+"-session","Idempotency-Key":key})

    async def query(self,unit="pallet-one",*,user="query",batch="batch-one"):
        return await self.client.get("/api/v1/inventory/"+unit,params={"batch":batch},headers={"Authorization":"Bearer "+user+"-session"})

    def state(self,unit="pallet-one"):
        return self.store.snapshot(self.remote.rows["units"][unit])

    async def test_inbound_query_transfer_partial_and_final_release(self):
        self.assertEqual((await self.post("inbound","in",location="TEST-A")).status_code,200)
        self.assertEqual((await self.query()).json()["data"]["observed_codes"][0]["code"],"A001")
        self.assertEqual((await self.post("transfer","move",1,location="TEST-B")).status_code,200)
        self.assertEqual((await self.post("partial-outbound","partial",2,boxes=3)).status_code,200)
        current=(await self.query()).json()["data"]
        self.assertEqual(current["observed_state"]["remaining_boxes"],7)
        self.assertEqual(current["observed_codes"][0]["code"],"B001")
        self.assertEqual((await self.post("partial-outbound","last",3,boxes=7)).status_code,200)
        self.assertEqual((self.state()["state"],self.state()["remaining_boxes"],self.state()["version"]),("已出区",0,4))
        self.assertEqual((await self.query()).json()["data"]["observed_codes"],[])
        self.assertEqual(len(self.remote.rows["operations"]),4)
        self.assertEqual(self.remote.rows["codes"]["B001"]["fields"]["状态"],"冷却")

    async def test_same_request_replays_without_duplicate_operation_or_version(self):
        first=await self.post("inbound","same",location="TEST-A")
        second=await self.post("inbound","same",location="TEST-A")
        self.assertEqual((first.status_code,second.status_code),(200,200))
        self.assertEqual(first.json(),second.json())
        self.assertEqual((len(self.remote.rows["operations"]),self.state()["version"]),(1,1))

    async def test_old_success_replay_preserves_newer_state(self):
        first=await self.post("inbound","in",location="TEST-A")
        await self.post("transfer","move",1,location="TEST-B")
        before=copy.deepcopy(self.remote.rows["units"])
        replay=await self.post("inbound","in",location="TEST-A")
        self.assertEqual(replay.json(),first.json())
        self.assertEqual(self.remote.rows["units"],before)
        self.assertEqual(self.state()["location"],["warehouse-b"])

    async def test_same_key_different_payload_or_actor_conflicts(self):
        await self.post("inbound","in",location="TEST-A")
        self.assertEqual((await self.post("inbound","in",location="TEST-B")).status_code,409)
        self.assertEqual((await self.post("inbound","in",user="admin",location="TEST-A")).status_code,409)
        self.assertEqual((len(self.remote.rows["operations"]),self.state()["version"]),(1,1))

    async def test_two_old_version_requests_have_one_winner(self):
        responses=await asyncio.gather(self.post("inbound","race-one",location="TEST-A"),self.post("inbound","race-two",location="TEST-A"))
        self.assertEqual(sorted(r.status_code for r in responses),[200,409])
        self.assertEqual((len(self.remote.rows["operations"]),self.state()["version"]),(1,1))

    async def test_code_cannot_be_bound_to_two_pallets(self):
        responses=await asyncio.gather(self.post("inbound","pallet-one",location="TEST-A"),
            self.post("inbound","pallet-two",unit="pallet-two",location="TEST-A"))
        self.assertEqual(sorted(r.status_code for r in responses),[200,409])
        self.assertEqual(sorted(self.state(u)["version"] for u in ("pallet-one","pallet-two")),[0,1])
        self.assertEqual(len(self.remote.rows["codes"]["A001"]["fields"]["绑定托盘"]),1)

    async def test_cooldown_blocks_reentry_until_ten_minute_boundary(self):
        with patch("workflow_store.time.time",return_value=1700000000):
            await self.post("inbound","in",location="TEST-A")
            self.assertEqual((await self.post("outbound","out",1)).status_code,200)
            result=await self.post("reentry","reenter",2,location="TEST-A",boxes=4,confirmed=True)
            self.assertEqual(result.status_code,409)
        with patch("workflow_store.time.time",return_value=1700000600):
            result=await self.post("reentry","reenter-after",2,location="TEST-A",boxes=4,confirmed=True)
            self.assertEqual(result.status_code,200,result.text)
        self.assertEqual((self.state()["remaining_boxes"],self.state()["version"]),(4,3))

    async def test_query_role_and_cross_batch_requests_cannot_change_inventory(self):
        before=copy.deepcopy(self.remote.rows)
        self.assertEqual((await self.post("inbound","viewer",user="query",location="TEST-A")).status_code,403)
        self.assertEqual((await self.post("inbound","other",batch="other-batch",location="TEST-A")).status_code,403)
        self.assertEqual((await self.query(batch="other-batch")).status_code,403)
        self.assertEqual(self.remote.rows,before)

    async def test_role_revocation_is_checked_before_replaying_old_success(self):
        await self.post("inbound","in",location="TEST-A")
        before=copy.deepcopy(self.remote.rows)
        self.native_roles["operator"]=[]
        self.assertEqual((await self.post("inbound","in",location="TEST-A")).status_code,403)
        self.assertEqual(self.remote.rows,before)

    async def test_admin_correction_and_undo_preserve_code_and_append_history(self):
        original=(await self.post("inbound","in",location="TEST-A")).json()["data"]["operation"]
        self.assertEqual((await self.post("corrections","forbidden",1,reference=original,reason="checked",confirmed=True,boxes=7)).status_code,403)
        correction=await self.post("corrections","correct",1,user="admin",reference=original,reason="checked",confirmed=True,boxes=7)
        self.assertEqual(correction.status_code,200,correction.text)
        self.assertEqual(self.state()["remaining_boxes"],7)
        result=await self.post("undo","undo",2,user="admin",reference=correction.json()["data"]["operation"],reason="recount",confirmed=True)
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual((self.state()["remaining_boxes"],self.state()["version"]),(10,3))
        self.assertEqual(len(self.remote.rows["operations"]),3)
        self.assertEqual((await self.query()).json()["data"]["observed_codes"][0]["code"],"A001")

    async def test_later_movement_blocks_undo_of_old_operation(self):
        original=(await self.post("inbound","in",location="TEST-A")).json()["data"]["operation"]
        await self.post("transfer","move",1,location="TEST-B")
        result=await self.post("undo","undo",2,user="admin",reference=original,reason="checked",confirmed=True)
        self.assertEqual(result.status_code,409)
        self.assertEqual((self.state()["version"],self.state()["location"]),(2,["warehouse-b"]))

    async def test_uncertain_commit_remains_pending_then_same_key_recovers_once(self):
        self.remote.fail_unit_update_after_commit=True
        first=await self.post("inbound","recover",location="TEST-A")
        self.assertEqual(first.status_code,503,first.text)
        self.assertEqual((await self.query()).json()["data"]["status"],"PENDING_RECONCILIATION")
        recovered=await self.post("inbound","recover",location="TEST-A")
        self.assertEqual(recovered.status_code,200,recovered.text)
        self.assertEqual((len(self.remote.rows["operations"]),self.state()["version"]),(1,1))
        self.assertEqual((await self.query()).json()["data"]["status"],"CONFIRMED")

    async def test_unknown_barcode_does_not_create_identity(self):
        result=await self.post("inbound","unknown",unit="not-registered",location="TEST-A")
        self.assertEqual(result.status_code,409)
        self.assertEqual((len(self.remote.rows["units"]),len(self.remote.rows["operations"])),(2,0))
