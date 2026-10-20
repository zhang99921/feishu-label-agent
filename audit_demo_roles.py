"""Read real roles and members; never assign users or mutate permissions/inventory.

This audits configuration and proposed business capabilities. A role name does
not establish user identity, membership, field access or batch scope.
"""
import json

from feishu_permissions import ROLE_ACTIONS, RoleDirectory, TableRequirement, meets_requirements
from feishu_probe import DEMO
from workflow_store import ROOT, connect


def inspect_role(native, members, binding, tables):
    by_table = {item["table_id"]:item for item in native.get("table_roles", [])}
    table_summary = {}
    for key, table_id in tables.items():
        item = by_table.get(table_id, {})
        table_summary[key] = {
            "table_perm":item.get("table_perm"),
            "explicit_field_permissions":isinstance(item.get("field_perm"), dict),
            "allow_add_record":item.get("allow_add_record"),
            "allow_delete_record":item.get("allow_delete_record"),
        }
    # All fields accessed by query's inventory snapshot must be interpretable.
    query_requirements = (
        TableRequirement(tables["units"],frozenset({"货物ID","批次","状态","记录版本","当前库位","最近操作ID","剩余箱数","计量单位","数量已核实"})),
        TableRequirement(tables["operations"],frozenset({"货物","阶段"})),
        TableRequirement(tables["codes"],frozenset({"库位码","绑定托盘","状态","冷却截止","记录版本","最近操作ID"})),
    )
    issues = []
    if not members:
        issues.append("NO_EXPLICIT_ROLE_MEMBERS")
    if any(v["table_perm"] in (1,2) and not v["explicit_field_permissions"] for v in table_summary.values()):
        issues.append("FIELD_PERMISSIONS_NOT_RETURNED_NO_GRANT_IN_CONSERVATIVE_GATE")
    if binding["business_role"] == "query" and any(v["table_perm"] in (2,4) for v in table_summary.values()):
        issues.append("QUERY_ROLE_CAN_EDIT_TEST_BUSINESS_TABLES_DIRECTLY")
    if binding["business_role"] == "operator" and any(v["allow_delete_record"] is True for v in table_summary.values()):
        issues.append("OPERATOR_CAN_DELETE_TEST_BUSINESS_RECORDS_DIRECTLY")
    return {
        "role_id":binding["role_id"], "role_name":native.get("role_name"),
        "business_role":binding["business_role"],
        "role_name_matches_reviewed_mapping":native.get("role_name") == binding["expected_name"],
        "explicit_member_count":len(members),
        "business_capability_matrix":{action:action in ROLE_ACTIONS[binding["business_role"]]
            for action in ("QUERY","IN","OUT","MOVE","PARTIAL_OUT","REENTER","CORRECT","UNDO")},
        "query_native_field_gate_satisfied":meets_requirements(native,query_requirements),
        "native_test_table_permissions":table_summary,
        "issues":issues,
    }


def run():
    policy = json.loads((ROOT / "demo_role_policy.json").read_text(encoding="utf-8"))
    assert policy["base_token"] == DEMO[0]
    tables = json.loads((ROOT / "restored_v2_workflow.local.json").read_text(encoding="utf-8"))["tables"]
    results = []
    with connect() as client:
        directory = RoleDirectory(client)
        app = client.request("GET","/bitable/v1/apps/"+DEMO[0])["data"]["app"]
        assert app.get("is_advanced") is True
        roles = directory._pages("/base/v2/apps/"+DEMO[0]+"/roles")
        by_id = {role["role_id"]:role for role in roles}
        for binding in policy["roles"]:
            native = by_id[binding["role_id"]]
            members = directory._pages("/bitable/v1/apps/"+DEMO[0]+"/roles/"+binding["role_id"]+"/members")
            results.append(inspect_role(native,members,binding,tables))
    report = {"verified_date":"2026-10-19", "read_only_live_api_audit":True,
        "real_roles_found":len(results), "inventory_mutations":0, "permission_changes":0,
        "batch_bindings_configured":bool(policy["batch_bindings"]),
        "inventory_authorization_enabled":False,
        "real_multi_account_action_acceptance_completed":False,
        "roles":results,
        "note":"Business capability matrix is a server policy proposal; it is not evidence of successful real-user authorization.",
        "official_field_permission_reference":"https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/bitable-v1/advanced-permission/base-v2/app-role/list"}
    (ROOT / "role_configuration_results.json").write_text(
        json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps({"roles":[{"name":r["role_name"],"members":r["explicit_member_count"],"issues":r["issues"]} for r in results],
        "real_multi_account_acceptance":False},ensure_ascii=False,indent=2))
    return report


if __name__ == "__main__":
    run()
