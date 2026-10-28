"""现有一表三单的输入协议；不修改飞书字段，不把接收任务等同于业务过账。"""
from dataclasses import asdict, dataclass
import hashlib
import json
import re


EVENTS = {"入库": "IN", "出库": "OUT", "转仓": "MOVE"}
FINAL_STATUSES = frozenset({"已入账", "已出账", "已转仓"})


def field_text(value):
    """兼容 API 富文本、条码、普通文本；未知形状拒绝，不擅自转成字符串。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list) and all(
        isinstance(item, dict) and isinstance(item.get("text"), str) for item in value
    ):
        return "".join(item["text"] for item in value).strip()
    raise ValueError("INVALID_TEXT_FIELD")


def creator_id(value):
    # 自动创建人仅作为来源凭据。是否有业务权限仍须执行前单独核实。
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if isinstance(value, dict):
        value = value.get("open_id") or value.get("id")
    return value if isinstance(value, str) and value.strip() else None


@dataclass(frozen=True)
class ScanSubmission:
    source_key: str
    source_record_id: str
    action: str
    boxes: tuple[str, ...]
    location: str
    source_location: str
    source_creator: str | None
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    fingerprint: str
    position_code: str = ''

    def payload(self):
        return asdict(self)


def normalize_record(base_token, table_id, record, *, include_blank_status=False):
    """返回待登记任务；已处理、异常或未经确认的空状态记录不自动重放。

    一个流水 record_id 是一次提交的身份，不使用会重号的事务号或时间戳。
    同单重复箱号保留第一次出现的位置；后续仍需业务层检查重复入库/出库。
    """
    rid = record.get("record_id")
    fields = record.get("fields")
    if not isinstance(rid, str) or not rid or not isinstance(fields, dict):
        raise ValueError("INVALID_SOURCE_RECORD")
    status = field_text(fields.get("处理状态"))
    if status in FINAL_STATUSES or status == "异常":
        return None
    if status != "待处理" and not (include_blank_status and status == ""):
        return None
    errors, warnings = [], []
    if any(re.fullmatch(r"箱号\d+", name) and name not in {f"箱号{i}" for i in range(1, 37)}
           and value not in (None, "", []) for name, value in fields.items()):
        errors.append("UNSUPPORTED_BOX_SLOT")

    def text(name):
        try:
            return field_text(fields.get(name))
        except ValueError:
            errors.append("INVALID_FIELD:" + name)
            return ""

    event = text("事件类型")
    action = EVENTS.get(event, "")
    if not action:
        errors.append("UNSUPPORTED_EVENT")
    raw_boxes = [text(f"箱号{i}") for i in range(1, 37)]
    boxes = tuple(dict.fromkeys(code for code in raw_boxes if code))
    if not boxes:
        errors.append("BOX_REQUIRED")
    if len(boxes) != sum(bool(code) for code in raw_boxes):
        warnings.append("DUPLICATE_BOX_IN_SUBMISSION")
    row = text("行码")
    target = text("目标区域")
    source = text("来源区域")
    position = text('位置码')
    if position:
        from .positions import position_number
        try:
            position_number(position)
        except ValueError:
            errors.append('INVALID_POSITION_CODE')
    if action == "IN" and not row:
        errors.append("LOCATION_REQUIRED")
    if action == "MOVE" and not target:
        errors.append("DESTINATION_REQUIRED")
    # 出库表单隐藏行码；保留历史非空来源信息，不把它当目标仓。
    location = row if action == "IN" else target if action == "MOVE" else ""
    source_location = source if action == "MOVE" else row if action == "OUT" else ""
    actor = creator_id(fields.get("操作人"))
    if actor is None:
        warnings.append("SOURCE_CREATOR_UNRESOLVED")
    # 摘要保留原始业务输入；换箱序、修改无关已隐藏的业务字段也不得静默替换旧任务。
    input_names = ["事件类型", "行码", "目标区域", "来源区域", "目标托盘号", "数量(套)", "原因"]
    input_names += [f"箱号{i}" for i in range(1, 37)]
    # 旧记录空位置不改变原摘要；一旦绑定，位置修改必须进入输入漂移隔离。
    if position or 'INVALID_FIELD:位置码' in errors:
        input_names.append('位置码')
    input_names += [name for name in fields if re.fullmatch(r"箱号\d+", name) and name not in input_names]
    original = {"fields": {name: fields.get(name) for name in input_names}, "creator": actor}
    fingerprint = hashlib.sha256(json.dumps(
        original, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    return ScanSubmission(f"{base_token}:{table_id}:{rid}", rid, action, boxes,
                          location, source_location, actor, tuple(dict.fromkeys(errors)),
                          tuple(warnings), fingerprint, position)
