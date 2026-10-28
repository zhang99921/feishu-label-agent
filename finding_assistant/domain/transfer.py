"""转仓来源及候选行码判断；不修改库存，来源必须来自箱表当前关联。"""
from collections import Counter
from dataclasses import dataclass

from .inbound_rules import LocationRecord

WAREHOUSES = frozenset({'优福斯仓', '欣源仓'})


class TransferRejected(Exception):
    def __init__(self, code, message, box_code=None):
        super().__init__(code)
        self.code, self.message, self.box_code = code, message, box_code


@dataclass(frozen=True)
class TransferDraft:
    source_location_code: str
    target_warehouse: str
    candidates: tuple[LocationRecord, ...]


def plan_transfer(box_codes, warehouse, boxes, locations, expected_source=None):
    if warehouse not in WAREHOUSES:
        raise ValueError('UNSUPPORTED_TARGET_WAREHOUSE')
    by_code, by_row = {}, {}
    for box in boxes:
        by_code.setdefault(box.box_code, []).append(box)
    for row in locations:
        by_row.setdefault(row.record_id, []).append(row)
    code_counts = Counter(row.location_code for row in locations)
    sources = set()
    for code in box_codes:
        matched = by_code.get(code, [])
        if len(matched) != 1:
            raise TransferRejected('BOX_NOT_UNIQUE', '箱号不存在或档案不唯一，本批暂停转仓', code)
        box = matched[0]
        if box.status not in {'在库', '在托'}:
            raise TransferRejected('BOX_STATUS_NOT_ALLOWED', '仅在库、在托的箱子允许转仓', code)
        if len(box.location_record_ids) != 1:
            raise TransferRejected('SOURCE_LOCATION_UNCONFIRMED', '箱子的来源位置未能唯一核实', code)
        rows = by_row.get(box.location_record_ids[0], [])
        if len(rows) != 1 or not rows[0].location_code or code_counts[rows[0].location_code] != 1:
            raise TransferRejected('SOURCE_LOCATION_UNCONFIRMED', '来源行码缺失或不唯一，本批暂停转仓', code)
        sources.add(rows[0].location_code)
    if len(sources) != 1:
        raise TransferRejected('MIXED_SOURCE_LOCATIONS', '同一转仓流水的箱子来源行码不一致，请核对本批箱子')
    source = next(iter(sources))
    if expected_source is not None and expected_source != source:
        raise TransferRejected('SOURCE_LOCATION_MISMATCH', '填写的来源区域与箱表当前行码不一致')
    # 有关联箱子的行码均先视为占用；不因箱子状态异常就自动释放其位置。
    occupied = {rid for box in boxes for rid in box.location_record_ids}
    targets = [row for row in locations if row.warehouse == warehouse]
    if any(not row.location_code or code_counts[row.location_code] != 1 for row in targets):
        raise TransferRejected('TARGET_LOCATION_NOT_UNIQUE', '目标仓库存在缺失或重复行码，需先核对行表')
    candidates = tuple(sorted((row for row in targets if row.record_id not in occupied
                               and row.location_code != source), key=lambda row: row.location_code))
    if not candidates:
        raise TransferRejected('NO_AVAILABLE_LOCATION', '目标仓库没有已核实的空闲行码')
    return TransferDraft(source, warehouse, candidates)
