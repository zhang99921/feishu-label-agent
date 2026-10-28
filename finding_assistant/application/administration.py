# 失败审计与管理操作辅助：成功流转由 operations 表记录；失败或待核实事件写入 audits。
# 本地 outbox 是待投递审计队列，不是第二份库存数据库。
"""Test-only failure audit sink and quantity administration schema.

Principals remain fixtures. This does not configure Feishu user permissions.
Outbox holds audit delivery metadata only; authoritative inventory stays Feishu.
"""
import hashlib
import json
import time
import uuid
from contextlib import nullcontext

from finding_assistant.adapters.feishu.client import ProbeError, save, text
from finding_assistant.application.workflow import ROOT, Conflict, Workflow, choice, field, writer_gate
from finding_assistant.domain.quantity_rules import RuleError


# 仅为验证表补充数量、更正、撤销及审计字段，避免误初始化生产或恢复表。
def setup_administration(store):
    if store.manifest_path != ROOT / "workflow_state.local.json":
        raise Conflict("administration experiment must not bootstrap restored or production tables")
    with writer_gate():
        specs = {"units": [field("剩余箱数", 2), field("标示箱数", 2), field("计量单位"), field("数量已核实", 7)],
                 "operations": [field("关联原操作", 18, table_id=store.table("operations"), multiple=False),
                                field("更正原因"), field("管理员已核实", 7)]}
        for key, definitions in specs.items():
            path = store.path + "/" + store.table(key) + "/fields"
            existing = {row["field_name"]: row for row in store.list_path(path)}
            for definition in definitions:
                if definition["field_name"] not in existing:
                    store.client.request("POST", path, definition)
                elif existing[definition["field_name"]]["type"] != definition["type"]:
                    raise Conflict("incompatible quantity/admin field")
        path = store.path + "/" + store.table("operations") + "/fields"
        action = next(row for row in store.list_path(path) if row["field_name"] == "类型")
        options = list(action["property"]["options"])
        missing = [name for name in ("PARTIAL_OUT", "CORRECT", "UNDO") if name not in [row["name"] for row in options]]
        if missing:
            store.client.request("PUT", path + "/" + action["field_id"],
                field("类型", 3, options=options + [{"name": name} for name in missing]))
        name = "CODEX_TEST_失败审计_" + store.manifest["run_id"][:6]
        tables = [row for row in store.list_path(store.path) if row["name"] == name]
        if len(tables) > 1:
            raise Conflict("duplicate audit table")
        if tables:
            table_id = tables[0]["table_id"]
        else:
            if "audits" in store.manifest["tables"]:
                raise Conflict("audit table missing; do not recreate")
            fields = [field("审计ID"), field("请求幂等键"), field("请求摘要"), field("操作人"), field("角色"),
                      choice("结果", "REJECTED", "PENDING_RECONCILIATION"), field("错误类型"), field("说明"),
                      field("记录时间", 5, date_formatter="yyyy-MM-dd HH:mm", auto_fill=False)]
            table_id = store.client.request("POST", store.path, {"table": {
                "name": name, "default_view_name": "失败与待核实", "fields": fields}})["data"]["table_id"]
        if store.manifest["tables"].get("audits", table_id) != table_id:
            raise Conflict("audit table identity changed")
        store.manifest["tables"]["audits"] = table_id
        save(store.manifest_path, store.manifest)


# 先保存失败审计到本地，再投递飞书；远端确认后才移除队列项。
class Audit:
    def __init__(self, store, path=None):
        self.store = store
        self.path = path or ROOT / "audit_outbox.local.json"

    def queued(self):
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else []

    # 按审计ID识别已写入事件；响应丢失后重试不会盲目新建第二份相同事件。
    def _deliver(self, event):
        existing = self.store.named("audits", "审计ID", event["审计ID"])
        if existing:
            if text(existing["fields"].get("请求摘要")) != event["请求摘要"]:
                raise Conflict("audit identity collision")
            return existing
        return self.store.create("audits", event["审计ID"], event)

    # 按队列顺序逐条投递并回读确认；失败时保留当前及后续条目。
    def _flush_locked(self):
        queued = self.queued()
        while queued:
            event = queued[0]
            result = self._deliver(event)
            persisted = self.store.get("audits", result["record_id"])
            if text(persisted["fields"].get("审计ID")) != event["审计ID"]:
                raise ProbeError("audit delivery not confirmed")
            queued.pop(0)
            save(self.path, queued)

    def flush(self):
        with writer_gate():
            self._flush_locked()

    # 区分明确拒绝和结果待核实；记录请求摘要及身份，对错误中的令牌/密钥做脱敏。
    def record_failure(self, key, payload, principal, error):
        with writer_gate():
            pending = isinstance(error, (ProbeError, RuleError))
            if isinstance(error, Conflict):
                try:
                    operation = self.store.named("operations", "请求幂等键", key)
                    pending = bool(operation and text(operation["fields"].get("阶段")) != "DONE")
                except ProbeError:
                    pending = True  # Queue the audit even when reconciliation lookup is unavailable.
            digest = hashlib.sha256(json.dumps({"request": payload, "actor": principal.actor,
                  "scope": principal.batch}, sort_keys=True, default=str, ensure_ascii=False).encode()).hexdigest()
            # 不能假定异常只包含已知应用密钥；用户令牌、DSN和业务数据同样可能被上游回显。
            message = 'OPERATION_UNCONFIRMED' if pending else 'OPERATION_REJECTED'
            event = {"审计ID": str(uuid.uuid4()), "请求幂等键": str(key)[:100], "请求摘要": digest,
                     "操作人": principal.actor, "角色": principal.role,
                     "结果": "PENDING_RECONCILIATION" if pending else "REJECTED",
                     "错误类型": ('CONFLICT' if isinstance(error, Conflict) else
                                  'RULE_REJECTED' if isinstance(error, RuleError) else
                                  'UPSTREAM_UNCONFIRMED' if isinstance(error, ProbeError) else 'OPERATION_ERROR'),
                     "说明": message, "记录时间": int(time.time() * 1000)}
            queued = self.queued()
            queued.append(event)
            save(self.path, queued)  # durable BEFORE attempting a remote audit write
            self._flush_locked()


# 在 Workflow 外增加审计保障，不替代真实账号的 PermissionGate。
class AuditedWorkflow(Workflow):
    def __init__(self, store, allocator=None, audit=None, restored_batch_aliases=None):
        super().__init__(store, allocator, restored_batch_aliases)
        self.audit = audit or Audit(store)

    # 先补投遗留审计，再执行业务；失败审计仍无法送达时阻止新的变更，防止审计丢失。
    def submit(self, key, payload, principal, fail_at=None):
        # Unsent audit entries block new mutations; do not silently lose them.
        with writer_gate(), self.store.read_scope() if self.store else nullcontext():
            self.audit.flush()
            try:
                return super().submit(key, payload, principal, fail_at)
            except (Conflict, PermissionError, ProbeError, RuleError) as error:
                try:
                    self.audit.record_failure(key, payload, principal, error)
                except (Conflict, ProbeError):
                    raise ProbeError("request not successful; failure audit queued for delivery") from None
                raise
