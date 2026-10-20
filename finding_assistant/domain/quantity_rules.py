"""Pure whole-box rules for the user-confirmed keep-pallet partial outbound model."""
from decimal import Decimal, InvalidOperation


class RuleError(Exception):
    pass


def whole_boxes(value):
    if type(value) is not int or value <= 0:
        raise RuleError("box quantity must be a positive integer")
    return value


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


def require_verified(before):
    if before.get("quantity_unit") != "箱" or before.get("quantity_verified") is not True:
        raise RuleError("confirm box unit and physical quantity before subtracting")
    if before.get("remaining_boxes") is None:
        raise RuleError("remaining box quantity is unknown")


def partial(before, boxes):
    require_verified(before)
    whole_boxes(boxes)
    if before["state"] != "在区" or boxes > before["remaining_boxes"]:
        raise RuleError("outside pallet or outbound quantity exceeds remaining boxes")
    remaining = before["remaining_boxes"] - boxes
    return dict(before, remaining_boxes=remaining, state="在区" if remaining else "已出区",
                location=list(before["location"]) if remaining else [])


def correction(before, boxes, reason, confirmed):
    if before.get("quantity_unit") != "箱" or confirmed is not True or not isinstance(reason, str) or not reason.strip():
        raise RuleError("administrator must confirm physical box count and give a reason")
    if type(boxes) is not int or boxes < 0:
        raise RuleError("corrected box quantity must be a nonnegative integer")
    if (before["state"] == "在区" and boxes == 0) or (before["state"] != "在区" and boxes != 0):
        raise RuleError("quantity correction cannot silently enter or exit a pallet")
    return dict(before, remaining_boxes=boxes, quantity_verified=True)


def undo(before, original, reason, confirmed):
    if confirmed is not True or not isinstance(reason, str) or not reason.strip():
        raise RuleError("administrator must confirm physical state and give an undo reason")
    if before != original["after"]:
        raise RuleError("later movement exists; simple undo is forbidden")
    return dict(original["before"])
