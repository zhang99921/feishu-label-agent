"""User-approved narrowing of the Demo query role on six V2 test tables only.

Uses the documented incremental v1 endpoint with existing bitable:app scope;
no application scope expansion, member changes, inventory writes or retries.
"""
import json

from feishu_permissions import RoleDirectory
from feishu_probe import DEMO, save
from workflow_store import ROOT, connect

ROLE = "rolSji8mSN"
EXPECTED_TABLES = frozenset({"tblHpNQIyQnbnyJC","tblYqLx4eWfBZH5C","tbljOHVpdpw9ttJJ",
    "tblTGV0nWWcOR34e","tblJ1KwTxT0uy5M4","tbl7K1KdxfMT94Uf"})


def canonical_role(role):
    return {**role,"table_roles":sorted(role["table_roles"],key=lambda table:table["table_id"])}


def run():
    tables = set(json.loads((ROOT / "restored_v2_workflow.local.json").read_text(encoding="utf-8"))["tables"].values())
    assert tables == EXPECTED_TABLES
    with connect() as client:
        directory = RoleDirectory(client)
        def roles():
            return {r["role_id"]:r for r in directory._pages("/base/v2/apps/"+DEMO[0]+"/roles")}
        journal = ROOT / "auth_query_permission_change.local.json"
        recovery = journal.exists()
        prepared = json.loads(journal.read_text(encoding="utf-8")) if recovery else None
        if prepared:
            assert prepared["base"] == DEMO[0] and prepared["role_id"] == ROLE
        before = prepared["before"] if prepared else roles()
        role = before[ROLE]
        assert role["role_name"] == "查询员"
        old = {r["table_id"]:r for r in role["table_roles"]}
        assert tables.issubset(old)
        assert all(old[t]["table_perm"] in (1,2) for t in tables)
        payload = {"role_name":role["role_name"],"table_roles":[
            {"table_id":t,"table_perm":1} for t in sorted(tables)]}
        if prepared:
            assert prepared["requested"] == payload
        if not recovery:
            save(journal,{
                "base":DEMO[0],"role_id":ROLE,"before":before,"requested":payload,
                "status":"PREPARED_DO_NOT_BLINDLY_RETRY"})
            if any(old[t]["table_perm"] != 1 for t in tables):
                client.request("PUT","/bitable/v1/apps/"+DEMO[0]+"/roles/"+ROLE,payload)
        after = roles()
        assert set(after) == set(before)
        assert all(canonical_role(after[r]) == canonical_role(before[r]) for r in before if r != ROLE)
        current = {r["table_id"]:r for r in after[ROLE]["table_roles"]}
        assert set(current) == set(old)
        assert all(current[t] == old[t] for t in old if t not in tables)
        assert all(current[t]["table_perm"] == 1 for t in tables)
        assert {k:v for k,v in role.items() if k != "table_roles"} == {
            k:v for k,v in after[ROLE].items() if k != "table_roles"}
        evidence = {"verified_date":"2026-10-19","status":"PASS_QUERY_ROLE_NARROWED",
            "base":DEMO[0],"role_id":ROLE,"test_tables_read_only":sorted(tables),
            "other_role_configurations_unchanged":True,"other_tables_unchanged":True,
            "new_api_scopes_enabled":False,"inventory_mutations":0,"member_changes":0}
        (ROOT / "query_readonly_results.json").write_text(
            json.dumps(evidence,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
        print(json.dumps(evidence,ensure_ascii=False,indent=2))


if __name__ == "__main__":
    run()
