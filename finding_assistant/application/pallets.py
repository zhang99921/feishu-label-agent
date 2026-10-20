"""Prototype allocator: whole-pallet moves, server-clock 600-second cooldown.

Requires the same local writer gate as Workflow. Does not implement partial
pallet splitting, real identity, multi-host locking, or prevent direct UI edits.
"""
import json

from finding_assistant.adapters.feishu.client import ProbeError, save, text
from finding_assistant.application.workflow import ROOT, Conflict, choice, field, links, writer_gate

COOLDOWN_MS = 600_000


def setup_codes(store):
    with writer_gate():
        name = "CODEX_TEST_托盘库位码_" + store.manifest["run_id"][:6]
        matches = [r for r in store.list_path(store.path) if r["name"] == name]
        if len(matches) > 1:
            raise Conflict("duplicate code tables")
        if matches:
            table_id = matches[0]["table_id"]
        else:
            if "codes" in store.manifest["tables"]:
                raise Conflict("code table missing; do not recreate")
            spec = [field("库位码"), field("仓库", 18, table_id=store.table("locations"), multiple=False),
                    field("绑定托盘", 18, table_id=store.table("units"), multiple=False),
                    choice("状态", "可用", "占用", "冷却"),
                    field("冷却截止", 5, date_formatter="yyyy-MM-dd HH:mm", auto_fill=False),
                    field("记录版本", 2), field("最近操作ID"), field("启用", 7)]
            table_id = store.client.request("POST", store.path, {"table": {
                "name": name, "default_view_name": "托盘码验证", "fields": spec}})["data"]["table_id"]
        previous = store.manifest["tables"].get("codes")
        if previous and previous != table_id:
            raise Conflict("code table identity changed")
        store.manifest["tables"]["codes"] = table_id
        save(ROOT / "workflow_state.local.json", store.manifest)
        code_fields_path = store.path + "/" + table_id + "/fields"
        expiry = [r for r in store.list_path(code_fields_path) if r["field_name"] == "冷却截止"][0]
        if expiry.get("property", {}).get("date_formatter") != "yyyy-MM-dd HH:mm":
            store.client.request("PUT", code_fields_path + "/" + expiry["field_id"],
                                 field("冷却截止", 5, date_formatter="yyyy-MM-dd HH:mm", auto_fill=False))
        fields_path = store.path + "/" + store.table("operations") + "/fields"
        existing = [r for r in store.list_path(fields_path) if r["field_name"] == "资源变更JSON"]
        if not existing:
            store.client.request("POST", fields_path, field("资源变更JSON"))
        elif existing[0]["type"] != 1:
            raise Conflict("incompatible resource journal field")


class Allocator:
    def __init__(self, store):
        self.store = store

    @staticmethod
    def snapshot(record):
        f = record["fields"]
        return {"owner": links(f.get("绑定托盘")), "state": text(f.get("状态")),
                "until": int(f.get("冷却截止") or 0), "version": int(f.get("记录版本", 0)),
                "last_operation": text(f.get("最近操作ID", ""))}

    @staticmethod
    def eligible(record, warehouse, now):
        f = record["fields"]
        value = Allocator.snapshot(record)
        return (f.get("启用") is True and links(f.get("仓库")) == warehouse
                and not value["owner"] and value["state"] in ("可用", "冷却")
                and now >= value["until"])

    def records(self):
        rows = self.store.records("codes")
        names = [text(row["fields"]["库位码"]) for row in rows]
        if len(names) != len(set(names)):
            raise Conflict("duplicate location codes require reconciliation")
        owners = [owner for row in rows for owner in self.snapshot(row)["owner"]]
        if len(owners) != len(set(owners)):
            raise Conflict("a pallet has multiple active codes")
        for row in rows:
            value = self.snapshot(row)
            if len(value["owner"]) > 1 or (value["state"] == "占用") != (len(value["owner"]) == 1):
                raise Conflict("code state and pallet binding disagree")
        return rows

    def for_unit(self, unit_id):
        return [{"record_id": row["record_id"], "code": text(row["fields"]["库位码"]),
                 **self.snapshot(row)} for row in self.records() if self.snapshot(row)["owner"] == [unit_id]]

    def plan(self, unit_id, before, after, operation_id, now):
        rows = self.records()
        active = [row for row in rows if self.snapshot(row)["owner"] == [unit_id]]
        if before["state"] == "在区":
            if len(active) != 1 or links(active[0]["fields"].get("仓库")) != before["location"]:
                raise Conflict("in-stock pallet must have exactly one code in its warehouse")
        elif active:
            raise Conflict("outside pallet cannot retain an active code")
        if before["state"] == after["state"] == "在区" and before["location"] == after["location"]:
            # User-confirmed partial outbound/correction retains the same pallet code.
            return []
        changes = []
        # A warehouse transfer releases the old code and allocates a destination code.
        for row in active:
            old = self.snapshot(row)
            changes.append({"id": row["record_id"], "before": old,
                            "after": dict(old, owner=[], state="冷却", until=now + COOLDOWN_MS,
                                          version=old["version"] + 1, last_operation=operation_id)})
        if after["state"] == "在区":
            candidates = [row for row in rows if self.eligible(row, after["location"], now)]
            candidates.sort(key=lambda row: text(row["fields"]["库位码"]))
            if not candidates:
                raise Conflict("no available code in the selected warehouse; retry later")
            row = candidates[0]
            old = self.snapshot(row)
            changes.append({"id": row["record_id"], "before": old,
                            "after": dict(old, owner=[unit_id], state="占用", until=0,
                                          version=old["version"] + 1, last_operation=operation_id)})
        return changes

    def recover(self, changes):
        # Check every resource first, then apply only recognized before->after changes.
        observed = {}
        for change in changes:
            value = self.snapshot(self.store.get("codes", change["id"]))
            if value != change["before"] and value != change["after"]:
                raise Conflict("code pool drift blocks recovery; do not overwrite")
            observed[change["id"]] = value
        for change in changes:
            value = change["after"]
            if observed[change["id"]] == change["before"]:
                self.store.update("codes", change["id"], {"绑定托盘": value["owner"],
                    "状态": value["state"], "冷却截止": value["until"] or None,
                    "记录版本": value["version"], "最近操作ID": value["last_operation"]})
            if self.snapshot(self.store.get("codes", change["id"])) != value:
                raise ProbeError("code lease update is not confirmed")
