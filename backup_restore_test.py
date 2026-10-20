"""Snapshot only CODEX_TEST workflow tables, restore into new CODEX_RESTORE tables.

Never overwrites or deletes source records. This verifies a controlled test-data
round trip, not production disaster recovery, retention, encryption or RPO/RTO.
"""
import hashlib
import json
import time
import uuid

from feishu_probe import ProbeError, save, text
from workflow_store import ROOT, Conflict, Store, connect, links, writer_gate

ORDER = ["batches", "locations", "units", "codes", "operations"]
JSON_FIELDS = {"变更前JSON", "变更后JSON", "结果JSON", "资源变更JSON"}


def remap(value, mapping):
    if isinstance(value, str):
        return mapping.get(value, value)
    if isinstance(value, list):
        return [remap(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: remap(item, mapping) for key, item in value.items()}
    return value


def writable(fields, schema, id_map=None):
    result = {}
    for spec in schema:
        name, kind = spec["field_name"], spec["type"]
        value = fields.get(name)
        if kind == 18:
            value = links(value)
            if id_map is not None:
                if any(item not in id_map for item in value):
                    raise Conflict("restore link target not mapped")
                value = [id_map[item] for item in value]
        elif kind in (1, 3):
            value = text(value or "")
            if name in JSON_FIELDS and value:
                parsed = json.loads(value)
                value = json.dumps(remap(parsed, id_map or {}), ensure_ascii=False, sort_keys=True)
        elif kind in (2, 5):
            value = int(float(value)) if value not in (None, "") else None
        elif kind == 7:
            value = bool(value)
        else:
            raise ProbeError("backup contains unsupported field type")
        if value not in (None, "", []):
            result[name] = value
    return result


def capture(store):
    with writer_gate():
        if any(text(r["fields"].get("阶段")) != "DONE" for r in store.records("operations")):
            raise Conflict("refuse to back up an unfinished operation")
        snapshot = {"base": store.manifest["base"], "run_id": store.manifest["run_id"],
                    "captured_ms": int(time.time() * 1000), "tables": {}}
        for key in ORDER:
            table_id = store.table(key)
            schema = store.list_path(store.path + "/" + table_id + "/fields")
            records = store.records(key)
            snapshot["tables"][key] = {"table_id": table_id, "schema": schema,
                "records": [{"record_id": row["record_id"], "fields": writable(row["fields"], schema)} for row in records]}
        encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True).encode()
        snapshot["sha256"] = hashlib.sha256(encoded).hexdigest()
        save(ROOT / "backup.local.json", snapshot)
        return snapshot


def run():
    client = connect()
    manifest = json.loads((ROOT / "workflow_state.local.json").read_text(encoding="utf-8"))
    store = Store(client, manifest)
    backup_path = ROOT / "backup.local.json"
    snapshot = json.loads(backup_path.read_text(encoding="utf-8")) if backup_path.exists() else capture(store)
    expected_hash = snapshot["sha256"]
    if hashlib.sha256(json.dumps({k:v for k,v in snapshot.items() if k != "sha256"}, ensure_ascii=False,
                               sort_keys=True).encode()).hexdigest() != expected_hash:
        raise Conflict("backup checksum mismatch")
    restore_path = ROOT / "restore_state.local.json"
    state = json.loads(restore_path.read_text(encoding="utf-8")) if restore_path.exists() else {
        "source_hash": expected_hash, "tables": {}, "records": {}, "request_tokens": {}}
    if state["source_hash"] != expected_hash:
        raise Conflict("restore state points to a different snapshot")
    save(restore_path, state)
    report = {"status": "RUNNING", "snapshot_sha256": expected_hash, "source_records_deleted": 0,
              "source_records_modified_by_restore": 0, "tables": {},
              "limitations": ["test-only snapshot in same Demo", "not production DR/RPO/RTO acceptance"]}
    previous_path = ROOT / "restore_results.local.json"
    if previous_path.exists():
        previous_report = json.loads(previous_path.read_text(encoding="utf-8"))
        report["prior_attempt_errors"] = list(previous_report.get("prior_attempt_errors", []))
        if previous_report.get("error"):
            report["prior_attempt_errors"].append(previous_report["error"])
    save(ROOT / "restore_results.local.json", report)
    try:
        for key in ORDER:
            source = snapshot["tables"][key]
            name = "CODEX_RESTORE_" + key + "_" + manifest["run_id"][:6]
            found = [row for row in store.list_path(store.path) if row["name"] == name]
            if len(found) > 1:
                raise Conflict("duplicate restore tables")
            if found:
                target_id = found[0]["table_id"]
                if state["tables"].get(key, target_id) != target_id:
                    raise Conflict("restored table identity changed")
            else:
                if key in state["tables"]:
                    raise Conflict("restore table disappeared")
                fields = []
                for spec in source["schema"]:
                    item = {"field_name": spec["field_name"], "type": spec["type"]}
                    prop = dict(spec.get("property") or {})
                    if item["type"] == 3:
                        prop = {"options": [{"name": option["name"]} for option in prop.get("options", [])]}
                    elif item["type"] == 18:
                        table_map = {snapshot["tables"][k]["table_id"]: v for k, v in state["tables"].items()}
                        if prop["table_id"] not in table_map:
                            raise Conflict("restore schema link dependency not created")
                        prop = {"table_id": table_map[prop["table_id"]], "multiple": prop.get("multiple", False)}
                    elif item["type"] == 5:
                        prop = {k:v for k,v in prop.items() if k in ("date_formatter", "auto_fill")}
                    elif item["type"] == 2:
                        prop = {k:v for k,v in prop.items() if k == "formatter"}
                    else:
                        prop = {}
                    if prop:
                        item["property"] = prop
                    fields.append(item)
                target_id = client.request("POST", store.path, {"table": {
                    "name": name, "default_view_name": "恢复验证", "fields": fields}})["data"]["table_id"]
            if target_id in [value["table_id"] for value in snapshot["tables"].values()] or target_id == store.client.config["table_id"]:
                raise Conflict("restore destination overlaps source or product table")
            state["tables"][key] = target_id
            save(restore_path, state)
            records_path = store.path + "/" + target_id + "/records"
            existing = store.list_path(records_path)
            primary = source["schema"][0]["field_name"]
            for row in source["records"]:
                matches = [target for target in existing if text(target["fields"].get(primary)) == text(row["fields"].get(primary))]
                if len(matches) > 1:
                    raise Conflict("duplicate identity in restored table")
                fields = writable(row["fields"], source["schema"], state["records"])
                if matches:
                    restored = matches[0]
                else:
                    token = state["request_tokens"].setdefault(row["record_id"], str(uuid.uuid4()))
                    save(restore_path, state)
                    restored = client.request("POST", records_path, {"fields": fields},
                        {"client_token": token, "ignore_consistency_check": "false"})["data"]["record"]
                state["records"][row["record_id"]] = restored["record_id"]
                save(restore_path, state)
                fresh = client.request("GET", records_path + "/" + restored["record_id"])["data"]["record"]
                if writable(fresh["fields"], source["schema"]) != fields:
                    raise Conflict("restored record differs from mapped backup")
            actual = store.list_path(records_path)
            if len(actual) != len(source["records"]):
                raise Conflict("restored record count differs from snapshot")
            report["tables"][key] = {"target_id": target_id, "records": len(actual), "field_values": "MATCH"}
            save(ROOT / "restore_results.local.json", report)
            print("RESTORE_PASS " + key + " records=" + str(len(actual)), flush=True)
        # Cross-check restored operation resource IDs/links and terminal unit states.
        operations = store.list_path(store.path + "/" + state["tables"]["operations"] + "/records")
        units = store.list_path(store.path + "/" + state["tables"]["units"] + "/records")
        for unit in units:
            chain = [op for op in operations if links(op["fields"].get("货物")) == [unit["record_id"]]]
            chain.sort(key=lambda row: json.loads(text(row["fields"]["变更后JSON"]))["version"])
            if chain:
                if json.loads(text(chain[-1]["fields"]["变更后JSON"])) != store.snapshot(unit):
                    raise Conflict("restored terminal state differs from history")
        report["restored_state_matches_history"] = True
        report["status"] = "PASS_TEST_SNAPSHOT_RESTORE"
    except Exception as error:
        report["status"] = "STOPPED_REQUIRES_REVIEW"
        report["error"] = str(error)
    save(ROOT / "restore_results.local.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0 if report["status"] == "PASS_TEST_SNAPSHOT_RESTORE" else 1


if __name__ == "__main__":
    raise SystemExit(run())
