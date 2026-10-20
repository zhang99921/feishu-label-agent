"""Controlled real-Feishu workflow experiment, NOT a deployable inventory system.

All inventory and operation data lives in CODEX_TEST tables in Demo.
The local manifest contains table/run IDs and request UUIDs, not inventory. One Windows host, one cooperating
writer at a time; the OS lock does not coordinate other hosts or direct UI edits.
Test principals are fixtures, not a production login integration.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from finding_assistant.adapters.feishu.client import Client, DEMO, ProbeError, save, text
from finding_assistant.domain.quantity_rules import RuleError, stored_boxes, require_verified, whole_boxes
from finding_assistant.domain.quantity_rules import partial as partial_boxes, correction as correct_boxes, undo as undo_transition

from finding_assistant.infrastructure.paths import STATE_DIR
from finding_assistant.infrastructure import local_lock

ROOT = STATE_DIR
GATE = threading.RLock()
_GATE_LOCAL = threading.local()


class Conflict(Exception):
    pass


class Interrupted(Exception):
    """Injected process boundary exception after an actual remote write."""


def interrupt(message):
    if os.environ.get("CODEX_TEST_HARD_EXIT") == "1":
        os._exit(71)  # Only the controlled test subprocess enables this.
    raise Interrupted(message)


@dataclass(frozen=True)
class TestPrincipal:
    actor: str
    role: str
    batch: str


@contextmanager
def writer_gate():
    with GATE:
        if getattr(_GATE_LOCAL, "held", False):
            yield
            return
        with (ROOT / ".writer.lock").open("a+b") as stream:
            stream.seek(0, 2)
            if stream.tell() == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            try:
                local_lock.acquire(stream)
            except OSError:
                raise Conflict("another local writer is active") from None
            _GATE_LOCAL.held = True
            try:
                yield
            finally:
                _GATE_LOCAL.held = False
                stream.seek(0)
                local_lock.release(stream)


def field(name, kind=1, **prop):
    value = {"field_name": name, "type": kind}
    if prop:
        value["property"] = prop
    return value


def choice(name, *values):
    return field(name, 3, options=[{"name": value} for value in values])


def links(value):
    """Normalize documented association response forms without guessing IDs."""
    if value is None:
        return []
    result = []
    for item in value:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict) and "record_ids" in item:
            result.extend(item["record_ids"])
        elif isinstance(item, dict) and "record_id" in item:
            result.append(item["record_id"])
        elif isinstance(item, dict) and item.get("type") == "text" and item.get("text_arr") == []:
            # Observed Feishu list response for an explicitly empty link field.
            continue
        else:
            raise ProbeError("Unexpected association field format")
    return result


class Store:
    def __init__(self, client, manifest, manifest_path=None):
        self.client, self.manifest = client, manifest
        self.manifest_path = manifest_path or ROOT / "workflow_state.local.json"
        self.path = f"/bitable/v1/apps/{DEMO[0]}/tables"
        self.cache_reads = True
        self._reads = threading.local()

    @contextmanager
    def read_scope(self):
        """Reuse complete lists only inside one serialized request; never across requests."""
        if not getattr(_GATE_LOCAL, "held", False):
            raise Conflict("read reuse requires the cooperating writer lock")
        if getattr(self._reads, "cache", None) is not None:
            yield
            return
        self._reads.cache = {} if self.cache_reads else None
        try:
            yield
        finally:
            self._reads.cache = None

    def invalidate_reads(self):
        cache = getattr(self._reads, "cache", None)
        if cache is not None:
            cache.clear()

    def prefetch(self, keys):
        """Join independent reads before publishing any reusable request snapshot."""
        cache = getattr(self._reads, "cache", None)
        if cache is None or not getattr(_GATE_LOCAL, "held", False):
            raise Conflict("prefetch requires a serialized read scope")
        if not getattr(self.client, "supports_parallel_reads", False):
            raise Conflict("transport has not enabled safe parallel reads")
        keys = tuple(dict.fromkeys(keys))
        with ThreadPoolExecutor(max_workers=min(3, len(keys))) as pool:
            futures = {key: pool.submit(self.list_path, self.path + "/" + self.table(key) + "/records") for key in keys}
            # On error the executor joins every read before the outer lock exits.
            rows = {key: future.result() for key, future in futures.items()}
        cache.update(deepcopy(rows))

    def table(self, key):
        value = self.manifest["tables"][key]
        if value == DEMO[1]:
            raise ProbeError("Existing product table must not be modified by workflow tests")
        return value

    def list_path(self, path):
        result, token = [], None
        while True:
            query = {"page_size": 100}
            if token:
                query["page_token"] = token
            data = self.client.request("GET", path, query=query)["data"]
            result.extend(data.get("items", []))
            if not data.get("has_more"):
                return result
            new_token = data.get("page_token")
            if not new_token or new_token == token:
                raise ProbeError("Invalid pagination")
            token = new_token

    def records(self, key):
        cache = getattr(self._reads, "cache", None)
        if cache is not None and key in cache:
            return deepcopy(cache[key])
        rows = self.list_path(self.path + "/" + self.table(key) + "/records")
        if cache is not None:
            cache[key] = deepcopy(rows)
        return rows

    def get(self, key, record_id):
        return self.client.request("GET", self.path + "/" + self.table(key) +
                                   "/records/" + record_id)["data"]["record"]

    def update(self, key, record_id, fields):
        # Invalidate before sending: a timeout may follow a successful remote write.
        self.invalidate_reads()
        return self.client.request("PUT", self.path + "/" + self.table(key) +
                                   "/records/" + record_id, {"fields": fields})["data"]["record"]

    def create(self, key, operation_key, fields):
        self.invalidate_reads()
        # Immediate UUID replay has been verified separately; this does not promise
        # an unlimited remote deduplication window. Durable lookup precedes replay.
        manifest_path = self.manifest_path
        self.manifest.update(json.loads(manifest_path.read_text(encoding="utf-8")))
        tokens = self.manifest.setdefault("request_tokens", {})
        token_name = key + ":" + operation_key
        if token_name not in tokens:
            tokens[token_name] = str(uuid.uuid4())  # API requires UUIDv4, not UUIDv5.
            save(manifest_path, self.manifest)
        token = tokens[token_name]
        return self.client.request("POST", self.path + "/" + self.table(key) + "/records",
                                   {"fields": fields}, {"client_token": token,
                                   "ignore_consistency_check": "false"})["data"]["record"]

    def named(self, key, name_field, name):
        found = [row for row in self.records(key) if text(row["fields"].get(name_field)) == name]
        if len(found) > 1:
            raise Conflict("duplicate remote identity requires reconciliation")
        return found[0] if found else None

    def seed(self, key, name_field, name, fields):
        return self.named(key, name_field, name) or self.create(key, "seed:" + name, fields)

    def snapshot(self, unit):
        fields = unit["fields"]
        value = {"state": text(fields.get("状态")), "version": int(fields.get("记录版本", 0)),
                "location": links(fields.get("当前库位")), "batch": links(fields.get("批次")),
                "last_operation": text(fields.get("最近操作ID", ""))}
        if text(fields.get("计量单位") or ""):
            value.update(remaining_boxes=stored_boxes(fields.get("剩余箱数")),
                         quantity_unit=text(fields["计量单位"]), quantity_verified=fields.get("数量已核实") is True)
        return value

    def apply_snapshot(self, record_id, value, actor, recorded_at):
        fields = {"状态": value["state"], "记录版本": value["version"],
                    "当前库位": value["location"], "最近操作ID": value["last_operation"],
                    "操作人": actor, "更新时间": recorded_at}
        if "quantity_unit" in value:
            fields.update(剩余箱数=value["remaining_boxes"], 计量单位=value["quantity_unit"], 数量已核实=value["quantity_verified"])
        self.update("units", record_id, fields)


def bootstrap(client):
    """Reconcile table names before creation; never blindly recreate after timeout."""
    manifest_path = ROOT / "workflow_state.local.json"
    with writer_gate():
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest["base"] != DEMO[0]:
                raise ProbeError("Wrong manifest target")
        else:
            manifest = {"base": DEMO[0], "run_id": str(uuid.uuid4()), "tables": {}}
            save(manifest_path, manifest)
        store = Store(client, manifest)
        tag = manifest["run_id"][:6]
        specs = [
            ("batches", "订单批次", lambda: [field("批次ID"), field("订单号"), field("说明")]),
            ("locations", "库位", lambda: [field("库位码"), field("仓库区域"), field("启用", 7)]),
            ("units", "货物单元", lambda: [field("货物ID"), field("条码"),
                field("批次", 18, table_id=store.table("batches"), multiple=False),
                field("当前库位", 18, table_id=store.table("locations"), multiple=False),
                choice("状态", "未入区", "在区", "已出区"), field("记录版本", 2),
                field("最近操作ID"), field("操作人"), field("更新时间", 5)]),
            ("operations", "流转流水", lambda: [field("操作ID"), field("请求幂等键"),
                field("请求摘要"), field("货物", 18, table_id=store.table("units"), multiple=False),
                choice("类型", "IN", "MOVE", "OUT", "REENTER"),
                choice("阶段", "PREPARED", "DONE"), field("变更前JSON"), field("变更后JSON"),
                field("操作人"), field("准备时间", 5), field("完成时间", 5), field("结果JSON")])]
        for key, label, fields in specs:
            name = f"CODEX_TEST_{label}_{tag}"
            found = [table for table in store.list_path(store.path) if table["name"] == name]
            if len(found) > 1:
                raise Conflict("duplicate test tables require reconciliation")
            if found:
                table_id = found[0]["table_id"]
                if key in manifest["tables"] and table_id != manifest["tables"][key]:
                    raise Conflict("table identity changed")
            else:
                if key in manifest["tables"]:
                    raise Conflict("previously created table is missing; do not recreate")
                data = client.request("POST", store.path, {"table": {
                    "name": name, "default_view_name": "验证数据", "fields": fields()}})["data"]
                table_id = data["table_id"]
            manifest["tables"][key] = table_id
            save(manifest_path, manifest)
        return store


class Workflow:
    def __init__(self, store, allocator=None, restored_batch_aliases=None):
        self.store = store
        self.allocator = allocator
        # Trusted server-side restore metadata only. Never read this mapping from a request.
        self.restored_batch_aliases = restored_batch_aliases or {}
        self.parallel_queries = True

    @staticmethod
    def fingerprint(payload, principal):
        return hashlib.sha256(json.dumps({"request": payload, "actor": principal.actor,
                "scope": principal.batch}, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def _recover(self, operation, fail_at=None):
        fields = operation["fields"]
        if text(fields["阶段"]) == "DONE":
            return json.loads(text(fields["结果JSON"]))
        unit_id = links(fields["货物"])[0]
        before = json.loads(text(fields["变更前JSON"]))
        after = json.loads(text(fields["变更后JSON"]))
        current = self.store.snapshot(self.store.get("units", unit_id))
        if current != before and current != after:
            raise Conflict("manual or uncoordinated changes block recovery")
        resources = json.loads(text(fields.get("资源变更JSON") or "[]") or "[]")
        if resources:
            if not self.allocator:
                raise Conflict("this operation requires the pallet-code recovery handler")
            self.allocator.recover(resources)
            if fail_at == "after_resources":
                interrupt("injected stop after code lease updates")
        if current == before:
            self.store.apply_snapshot(unit_id, after, text(fields["操作人"]), fields["准备时间"])
        elif current != after:
            raise Conflict("manual or uncoordinated changes block recovery")
        if self.store.snapshot(self.store.get("units", unit_id)) != after:
            raise ProbeError("unit write not confirmed; remain pending")
        if fail_at == "after_unit":
            interrupt("injected stop after remote unit update")
        result = {"status": "DONE", "operation": text(fields["操作ID"]),
                  "unit": unit_id, "after": after}
        self.store.update("operations", operation["record_id"], {
            "阶段": "DONE", "完成时间": int(time.time() * 1000),
            "结果JSON": json.dumps(result, ensure_ascii=False)})
        verified = self.store.get("operations", operation["record_id"])
        if text(verified["fields"].get("阶段")) != "DONE":
            raise ProbeError("operation completion not visible")
        if fail_at == "response_lost":
            interrupt("injected response loss after completed remote operation")
        return result

    def submit(self, key, payload, principal, fail_at=None):
        if not isinstance(payload, dict):
            raise Conflict("invalid request shape")
        action = payload.get("action")
        if action in ("CORRECT", "UNDO") and principal.role != "admin":
            raise PermissionError("only the test administrator can correct or undo")
        if principal.role not in ("operator", "admin"):
            raise PermissionError("test principal cannot write")
        if not key or len(key) > 100:
            raise Conflict("invalid idempotency key")
        required = {"unit", "action", "expected_version", "batch", "location"}
        if action == "PARTIAL_OUT":
            required |= {"boxes"}
        elif action in ("CORRECT", "UNDO"):
            required |= {"reason", "confirmed", "reference"}
            if action == "CORRECT":
                required.add("boxes")
        elif action == "REENTER" and "boxes" in payload:
            required |= {"boxes", "confirmed"}
        if set(payload) != required or type(payload["expected_version"]) is not int:
            raise Conflict("invalid request shape")
        resolved_batch = self.restored_batch_aliases.get(payload["batch"], payload["batch"])
        if resolved_batch != principal.batch:
            raise PermissionError("request is outside the test principal scope")
        with writer_gate():
            unit = self.store.named("units", "货物ID", payload["unit"])
            if not unit:
                raise Conflict("unknown barcode; register identity first")
            if links(unit["fields"].get("批次")) != [principal.batch]:
                raise PermissionError("unit is outside the test principal scope")
            # Preserve the original request bytes/scope for idempotency after a
            # physical Feishu record-ID remap, while checking the mapped live scope.
            digest_principal = TestPrincipal(principal.actor, principal.role, payload["batch"])
            digest = self.fingerprint(payload, digest_principal)
            previous = self.store.named("operations", "请求幂等键", key)
            if previous:
                if text(previous["fields"]["请求摘要"]) != digest:
                    raise Conflict("idempotency key reused with a different request or actor")
                return self._recover(previous)
            # Pending remote work must be reconciled before any new transition.
            for pending in self.store.records("operations"):
                if text(pending["fields"].get("阶段")) != "DONE":
                    self._recover(pending)
            before = self.store.snapshot(self.store.get("units", unit["record_id"]))
            if before["version"] != payload["expected_version"]:
                raise Conflict("stale version; refresh before confirming")
            location = payload["location"]
            if action in ("IN", "MOVE", "REENTER"):
                target = self.store.named("locations", "库位码", location)
                if not target or target["fields"].get("启用") is not True:
                    raise Conflict("unknown or disabled destination")
                target_ids = [target["record_id"]]
            elif action in ("OUT", "PARTIAL_OUT", "CORRECT", "UNDO") and location is None:
                target_ids = []
            else:
                raise Conflict("invalid action or outbound destination")
            expected_state = {"IN": "未入区", "REENTER": "已出区", "MOVE": "在区", "OUT": "在区", "PARTIAL_OUT": "在区"}.get(action)
            if expected_state and before["state"] != expected_state:
                raise Conflict("invalid transition; reentry must be explicit")
            if action == "MOVE" and before["location"] == target_ids:
                raise Conflict("destination equals current location")
            operation_id = str(uuid.uuid5(uuid.UUID(self.store.manifest["run_id"]), "operation:" + key))
            reference = None
            try:
                if action == "PARTIAL_OUT":
                    after = partial_boxes(before, payload["boxes"])
                elif action in ("CORRECT", "UNDO"):
                    reference = self.store.named("operations", "操作ID", payload["reference"])
                    if not reference or links(reference["fields"].get("货物")) != [unit["record_id"]] or text(reference["fields"].get("阶段")) != "DONE":
                        raise Conflict("correction must reference a completed movement of this unit")
                    original = {k: json.loads(text(reference["fields"][name])) for k,name in
                                [("before", "变更前JSON"), ("after", "变更后JSON")]}
                    if action == "UNDO":
                        after = undo_transition(before, original, payload["reason"], payload["confirmed"])
                    else:
                        after = correct_boxes(before, payload["boxes"], payload["reason"], payload["confirmed"])
                else:
                    after = dict(before, state="已出区" if action == "OUT" else "在区", location=target_ids)
                    if "remaining_boxes" in before:
                        if action == "OUT":
                            require_verified(before)
                            after["remaining_boxes"] = 0
                        elif action == "REENTER":
                            if payload.get("confirmed") is not True:
                                raise RuleError("confirm new box count for explicit reentry")
                            after.update(remaining_boxes=whole_boxes(payload.get("boxes")), quantity_verified=True)
                        elif before.get("remaining_boxes") in (None, 0):
                            raise RuleError("confirm a positive registered box count")
            except RuleError as error:
                raise Conflict(str(error)) from None
            after.update(version=before["version"] + 1, last_operation=operation_id)
            prepared_at = int(time.time() * 1000)
            operation_fields = {
                "操作ID": operation_id, "请求幂等键": key, "请求摘要": digest,
                "货物": [unit["record_id"]], "类型": action, "阶段": "PREPARED",
                "变更前JSON": json.dumps(before, ensure_ascii=False),
                "变更后JSON": json.dumps(after, ensure_ascii=False), "操作人": principal.actor,
                "准备时间": prepared_at}
            if reference:
                operation_fields.update(关联原操作=[reference["record_id"]], 更正原因=payload["reason"], 管理员已核实=True)
            if self.allocator:
                resources = self.allocator.plan(unit["record_id"], before, after, operation_id, prepared_at)
                operation_fields["资源变更JSON"] = json.dumps(resources, ensure_ascii=False)
            operation = self.store.create("operations", key, operation_fields)
            if fail_at == "after_prepare":
                interrupt("injected stop after durable remote preparation")
            return self._recover(operation, fail_at)

    def query(self, unit_name, principal):
        if principal.role not in ("operator", "query", "admin"):
            raise PermissionError("test principal cannot query")
        with writer_gate(), self.store.read_scope():
            if self.parallel_queries and self.store.cache_reads and getattr(self.store.client, "supports_parallel_reads", False):
                self.store.prefetch(("units", "operations", "codes") if self.allocator else ("units", "operations"))
            unit = self.store.named("units", "货物ID", unit_name)
            if not unit:
                return {"status": "NOT_FOUND"}
            if links(unit["fields"].get("批次")) != [principal.batch]:
                raise PermissionError("unit is outside the test principal scope")
            pending = [row for row in self.store.records("operations")
                       if links(row["fields"].get("货物")) == [unit["record_id"]]
                       and text(row["fields"].get("阶段")) != "DONE"]
            result = {"status": "PENDING_RECONCILIATION" if pending else "CONFIRMED",
                      "observed_state": self.store.snapshot(unit)}
            if self.allocator:
                result["observed_codes"] = self.allocator.for_unit(unit["record_id"])
            return result


def connect(*, pooled=True):
    config = json.loads((ROOT / "config.local.json").read_text(encoding="utf-8-sig"))
    if pooled:
        from finding_assistant.adapters.feishu.pooled_client import PooledClient
        client = PooledClient(config)
    else:
        client = Client(config)  # Explicit diagnostic baseline; never an automatic write retry.
    client.login()
    return client


if __name__ == "__main__":
    store = bootstrap(connect())
    print(json.dumps(store.manifest, ensure_ascii=False, indent=2))
