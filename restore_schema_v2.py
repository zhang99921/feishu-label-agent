"""Six-table snapshot and two-pass restore into separate CODEX_RESTORE_V2 tables.

All table identities and record mappings are persisted before continuing. Source
records are read only; completed destination rows cannot be overwritten on rerun.
The separate older restore and its continuity experiment are left untouched.
"""
import hashlib
import json
import time
import uuid

from administration import Audit
from backup_restore_test import JSON_FIELDS, writable
from feishu_probe import ProbeError, save, text
from workflow_store import ROOT, Conflict, Store, connect, links, writer_gate

ORDER = ["batches", "locations", "units", "codes", "operations", "audits"]


def checksum(snapshot):
    value = {k:v for k,v in snapshot.items() if k != "sha256"}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def skeleton(fields, schema):
    scalar = [s for s in schema if s["type"] != 18 and s["field_name"] not in JSON_FIELDS]
    return writable(fields, scalar)


def schema_field(spec, tables=None):
    item = {"field_name": spec["field_name"], "type": spec["type"]}
    prop = spec.get("property") or {}
    if item["type"] == 18:
        if not tables or prop["table_id"] not in tables:
            raise Conflict("restore schema association target not mapped")
        prop = {"table_id": tables[prop["table_id"]], "multiple": prop.get("multiple", False)}
    elif item["type"] == 3:
        prop = {"options": [{"name": v["name"]} for v in prop.get("options", [])]}
    elif item["type"] == 5:
        prop = {k:v for k,v in prop.items() if k in ("date_formatter", "auto_fill")}
    elif item["type"] == 2:
        prop = {k:v for k,v in prop.items() if k == "formatter"}
    elif item["type"] in (1, 7):
        prop = {}
    else:
        raise ProbeError("unsupported restore field type")
    if prop:
        item["property"] = prop
    return item


def capture(store):
    with writer_gate():
        if Audit(store).queued():
            raise Conflict("flush pending failure audits before snapshot")
        if any(text(r["fields"].get("阶段")) != "DONE" for r in store.records("operations")):
            raise Conflict("unfinished operation blocks snapshot")
        snapshot = {"base": store.manifest["base"], "run_id": store.manifest["run_id"],
                    "captured_ms": int(time.time() * 1000), "tables": {}}
        for key in ORDER:
            table_id = store.table(key)
            schema = store.list_path(store.path + "/" + table_id + "/fields")
            rows = store.records(key)
            snapshot["tables"][key] = {"table_id": table_id, "schema": schema,
                "records": [{"record_id": r["record_id"], "fields": writable(r["fields"], schema)} for r in rows]}
        snapshot["sha256"] = checksum(snapshot)
        save(ROOT / "backup_v2.local.json", snapshot)
        return snapshot


def restore(store, snapshot, state, state_path):
    def persist():
        save(state_path, state)
    # Create ALL tables before adding associations (including self/cyclic links).
    for key in ORDER:
        source = snapshot["tables"][key]
        name = "CODEX_RESTORE_V2_" + key + "_" + snapshot["run_id"][:6]
        found = [r for r in store.list_path(store.path) if r["name"] == name]
        if len(found) > 1:
            raise Conflict("duplicate restore destination")
        if found:
            target = found[0]["table_id"]
            if state["tables"].get(key, target) != target:
                raise Conflict("restore destination identity changed")
        else:
            if key in state["tables"]:
                raise Conflict("previous restore destination disappeared")
            fields = [schema_field(s) for s in source["schema"] if s["type"] != 18]
            target = store.client.request("POST", store.path, {"table": {
                "name": name, "default_view_name": "新结构恢复验证", "fields": fields}})["data"]["table_id"]
        forbidden = set(store.manifest["tables"].values()) | {store.client.config["table_id"]}
        if target in forbidden:
            raise Conflict("restore target overlaps source or product data")
        state["tables"][key] = target
        persist()
        print("TABLE_READY " + key, flush=True)
    table_map = {snapshot["tables"][k]["table_id"]: state["tables"][k] for k in ORDER}
    for key in ORDER:
        path = store.path + "/" + state["tables"][key] + "/fields"
        existing = {s["field_name"]: s for s in store.list_path(path)}
        for spec in snapshot["tables"][key]["schema"]:
            target_spec = schema_field(spec, table_map)
            name = spec["field_name"]
            if name not in existing:
                store.client.request("POST", path, target_spec)
            else:
                current = existing[name]
                if current["type"] != spec["type"]:
                    raise Conflict("destination schema type changed")
                if spec["type"] == 18:
                    prop = current.get("property") or {}
                    if any(prop.get(k) != v for k,v in target_spec["property"].items()):
                        raise Conflict("destination association schema changed")
    # Create record identities without source associations or source JSON IDs.
    for key in ORDER:
        source = snapshot["tables"][key]
        path = store.path + "/" + state["tables"][key] + "/records"
        existing = store.list_path(path)
        primary = source["schema"][0]["field_name"]
        for row in source["records"]:
            identity = text(row["fields"].get(primary))
            matches = [r for r in existing if text(r["fields"].get(primary)) == identity]
            if len(matches) > 1:
                raise Conflict("duplicate restored record identity")
            scalar = skeleton(row["fields"], source["schema"])
            if matches:
                target = matches[0]
                if skeleton(target["fields"], source["schema"]) != scalar:
                    raise Conflict("restored scalar fields changed; refuse overwrite")
            else:
                if row["record_id"] in state["records"]:
                    raise Conflict("previous restored record disappeared")
                token = state["request_tokens"].setdefault(row["record_id"], str(uuid.uuid4()))
                persist()
                target = store.client.request("POST", path, {"fields": scalar},
                    {"client_token": token, "ignore_consistency_check": "false"})["data"]["record"]
                existing.append(target)
            previous = state["records"].get(row["record_id"])
            if previous and previous != target["record_id"]:
                raise Conflict("restored record identity changed")
            state["records"][row["record_id"]] = target["record_id"]
            persist()
        if len(existing) != len(source["records"]):
            raise Conflict("unexpected destination record count")
        print("IDENTITIES_READY " + key + " " + str(len(existing)), flush=True)
    # With every record ID known, restore links and embedded JSON references.
    for key in ORDER:
        source = snapshot["tables"][key]
        path = store.path + "/" + state["tables"][key] + "/records"
        current = {r["record_id"]: r for r in store.list_path(path)}
        for row in source["records"]:
            old_id = row["record_id"]
            new_id = state["records"][old_id]
            expected = writable(row["fields"], source["schema"], state["records"])
            actual = writable(current[new_id]["fields"], source["schema"])
            if actual != expected:
                if old_id in state["verified"]:
                    raise Conflict("completed restore record changed; refuse overwrite")
                initial = skeleton(row["fields"], source["schema"])
                if actual != initial:
                    raise Conflict("destination is neither skeleton nor full mapped record")
                state["hydrating"] = old_id
                persist()
                store.client.request("PUT", path + "/" + new_id, {"fields": expected})
            state["verified"][old_id] = True
            state.pop("hydrating", None)
            persist()
        actual = store.list_path(path)
        indexed = {r["record_id"]: r for r in actual}
        if len(actual) != len(source["records"]):
            raise Conflict("restored count mismatch")
        for row in source["records"]:
            expected = writable(row["fields"], source["schema"], state["records"])
            if writable(indexed[state["records"][row["record_id"]]]["fields"], source["schema"]) != expected:
                raise Conflict("restored field readback mismatch")
        print("RESTORE_V2_PASS " + key + " " + str(len(actual)), flush=True)
    return table_map


def run():
    store = Store(connect(), json.loads((ROOT / "workflow_state.local.json").read_text(encoding="utf-8")))
    backup_path, state_path = ROOT / "backup_v2.local.json", ROOT / "restore_v2_state.local.json"
    snapshot = json.loads(backup_path.read_text(encoding="utf-8")) if backup_path.exists() else capture(store)
    if checksum(snapshot) != snapshot["sha256"] or set(snapshot["tables"]) != set(ORDER):
        raise Conflict("snapshot checksum or table set mismatch")
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {
        "source_hash": snapshot["sha256"], "tables": {}, "records": {}, "request_tokens": {}, "verified": {}}
    if state["source_hash"] != snapshot["sha256"]:
        raise Conflict("restore state belongs to another snapshot")
    save(state_path, state)
    report = {"status": "RUNNING", "snapshot_sha256": snapshot["sha256"],
              "source_records_modified": 0, "source_records_deleted": 0,
              "limitations": ["same Demo only; not production DR/RPO/RTO", "single cooperating writer host"]}
    report_path = ROOT / "restore_v2_results.local.json"
    save(report_path, report)
    try:
        with writer_gate():
            restore(store, snapshot, state, state_path)
            clone = Store(store.client, {"tables": state["tables"]})
            operations = clone.records("operations")
            units = clone.records("units")
            for unit in units:
                chain = [r for r in operations if links(r["fields"].get("货物")) == [unit["record_id"]]]
                chain.sort(key=lambda r: json.loads(text(r["fields"]["变更后JSON"]))["version"])
                if chain and json.loads(text(chain[-1]["fields"]["变更后JSON"])) != clone.snapshot(unit):
                    raise Conflict("restored unit differs from terminal history")
            self_links = sum(bool(links(r["fields"].get("关联原操作"))) for r in operations)
            if self_links < 1:
                raise Conflict("no self association exercised")
            # Verify source content remains equal to the snapshot after the restore.
            for key in ORDER:
                spec = snapshot["tables"][key]
                before = {r["record_id"]: r["fields"] for r in spec["records"]}
                after = {r["record_id"]: writable(r["fields"], spec["schema"]) for r in store.records(key)}
                if before != after:
                    raise Conflict("source changed during controlled restore")
            report.update(status="PASS_SIX_TABLE_RESTORE", self_associations_verified=self_links,
                terminal_history_matches=True, source_content_unchanged=True,
                tables={k:{"target_id": state["tables"][k], "records": len(snapshot["tables"][k]["records"]),
                           "field_values": "MATCH"} for k in ORDER})
    except Exception as error:
        report.update(status="STOPPED_REQUIRES_REVIEW", error=str(error))
    save(report_path, report)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0 if report["status"] == "PASS_SIX_TABLE_RESTORE" else 1


if __name__ == "__main__":
    raise SystemExit(run())
