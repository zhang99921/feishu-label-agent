# 纯业务规则：只计算/验证快照，不访问 HTTP、飞书或文件，便于独立测试。
"""Pure whole-box rules for the user-confirmed keep-pallet partial outbound model."""
from decimal import Decimal, InvalidOperation


class RuleError(Exception):
    pass


# 请求箱数必须是正整数；使用精确类型检查，拒绝 Python 中也属于整数的布尔值。
def whole_boxes(value):
    if type(value) is not int or value <= 0:
        raise RuleError("box quantity must be a positive integer")
    return value


# 兼容飞书数字字段的表示方式；缺失代表未知，不能静默转换成零库存。
def stored_boxes(value):
    if value in (None, ""):
        return None
    try:
        number = Decimal(str(value))
        if not number.is_finite() or number < 0 or number != int(number):
            raise ValueError
        return int(number)
    except (ValueError, InvalidOperation):
        raise RuleError("stored box quantity requires reconciliation") from None


# 扣减前必须明确按“箱”计量且已核实数量，避免把件数或未知数量当箱数使用。
def require_verified(before):
    if before.get("quantity_unit") != "箱" or before.get("quantity_verified") is not True:
        raise RuleError("confirm box unit and physical quantity before subtracting")
    if before.get("remaining_boxes") is None:
        raise RuleError("remaining box quantity is unknown")


# 计算部分出库后的快照；剩余为零才清除仓库关联，否则保留原仓。
def partial(before, boxes):
    require_verified(before)
    whole_boxes(boxes)
    if before["state"] != "在区" or boxes > before["remaining_boxes"]:
        raise RuleError("outside pallet or outbound quantity exceeds remaining boxes")
    remaining = before["remaining_boxes"] - boxes
    return dict(before, remaining_boxes=remaining, state="在区" if remaining else "已出区",
                location=list(before["location"]) if remaining else [])


# 数量纠错不能顺带改变在库状态；入库/出库必须走明确的流转动作。
def correction(before, boxes, reason, confirmed):
    if before.get("quantity_unit") != "箱" or confirmed is not True or not isinstance(reason, str) or not reason.strip():
        raise RuleError("administrator must confirm physical box count and give a reason")
    if type(boxes) is not int or boxes < 0:
        raise RuleError("corrected box quantity must be a nonnegative integer")
    if (before["state"] == "在区" and boxes == 0) or (before["state"] != "在区" and boxes != 0):
        raise RuleError("quantity correction cannot silently enter or exit a pallet")
    return dict(before, remaining_boxes=boxes, quantity_verified=True)


# 只有当前快照仍等于原操作的 after 才允许撤销；版本与新操作ID由 Workflow 统一更新。
def undo(before, original, reason, confirmed):
    if confirmed is not True or not isinstance(reason, str) or not reason.strip():
        raise RuleError("administrator must confirm physical state and give an undo reason")
    if before != original["after"]:
        raise RuleError("later movement exists; simple undo is forbidden")
    return dict(original["before"])
