"""组合位置的纯业务判断；位置表示区域内的批次归属，不是精确物理格位。"""
from collections import Counter
from dataclasses import dataclass
import re

from .inbound_rules import BoxRecord, LocationRecord
from .transfer import WAREHOUSES


class PositionRejected(Exception):
    def __init__(self, code, message, box_code=None):
        super().__init__(code)
        self.code, self.message, self.box_code = code, message, box_code


def position_number(code):
    """规范后缀从-01开始；不设置99个的业务上限，不接受-001等别名。"""
    if not isinstance(code, str) or len(code) > 200 or not re.fullmatch(r'-[0-9]{2,}', code):
        raise ValueError('INVALID_POSITION_CODE')
    number = int(code[1:])
    if number < 1 or code != '-' + str(number).zfill(2):
        raise ValueError('INVALID_POSITION_CODE')
    return number


def position_code(number):
    if type(number) is not int or number < 1:
        raise ValueError('INVALID_POSITION_NUMBER')
    return '-' + str(number).zfill(2)


@dataclass(frozen=True)
class PositionDraft:
    action: str
    warehouse: str
    boxes: tuple[BoxRecord, ...]
    candidates: tuple[LocationRecord, ...]
    occupied: tuple[tuple[str, int], ...]
    quarantined_rows: frozenset[str]
    sources: tuple[dict, ...]


def plan_positions(action, codes, warehouse, boxes, locations, expected_source=None):
    """先核实整批，再给数据库分配器提供完整占用快照；这里不执行库存变更。"""
    if action not in ('IN', 'MOVE') or warehouse not in WAREHOUSES:
        raise ValueError('INVALID_POSITION_ACTION_OR_WAREHOUSE')
    if not codes or len(codes) > 36 or len(codes) != len(set(codes)):
        raise ValueError('UNIQUE_BOX_CODES_REQUIRED')
    if len({row.record_id for row in locations}) != len(locations):
        raise PositionRejected('ROW_RECORD_NOT_UNIQUE', '行表档案不唯一，暂不能分配')
    by_row = {row.record_id: row for row in locations}
    row_counts = Counter(row.location_code for row in locations)
    candidates = tuple(row for row in locations if row.warehouse == warehouse)
    if not candidates:
        raise PositionRejected('NO_WAREHOUSE_REGION', '所选仓库没有已配置的行码区域')
    if any(not row.location_code or row_counts[row.location_code] != 1 for row in candidates):
        raise PositionRejected('TARGET_ROW_NOT_UNIQUE', '目标仓库有缺失或重复行码，请先核实行表')

    by_box, usage, quarantined, membership = {}, set(), set(), {}
    for box in boxes:
        by_box.setdefault(box.box_code, []).append(box)
        links = box.location_record_ids
        if box.position_code and len(links) != 1:
            raise PositionRejected('POSITION_WITHOUT_UNIQUE_ROW', '箱子的位置码没有唯一行码关联', box.box_code)
        if not links:
            continue
        if len(links) != 1 or links[0] not in by_row:
            raise PositionRejected('ROW_REFERENCE_UNCONFIRMED', '箱子行关联无法核实', box.box_code)
        row_id = links[0]
        if not box.position_code:
            # 旧区域箱不虚构组合位置；新货可继续使用同一区域。
            continue
        try:
            number = position_number(box.position_code)
        except ValueError:
            # 有关联却无规范位置的旧箱子：整个区域先隔离，不能猜一个空位置绕过它。
            quarantined.add(row_id)
            continue
        usage.add((row_id, number))
        membership.setdefault((row_id, number), set()).add(box.record_id)

    requested, sources = [], []
    for code in codes:
        matches = by_box.get(code, [])
        if len(matches) != 1:
            raise PositionRejected('BOX_NOT_UNIQUE', '箱号不存在或档案不唯一，本批暂停', code)
        box = matches[0]
        if action == 'IN' and box.status not in ('在库', '在托'):
            # 自动入口只开放已确认的待入库路径；返库及其他状态没有因此自动获准。
            if box.status != '待入库':
                raise PositionRejected('INBOUND_STATUS_NOT_READY', '自动入库仅接收待入库箱；其他状态需先核实业务路径', code)
            if box.location_record_ids or box.position_code:
                raise PositionRejected('INBOUND_POSITION_CONFLICT', '待入库箱已有位置，本批暂停', code)
        else:
            if box.status not in ('在库', '在托'):
                raise PositionRejected('TRANSFER_STATUS_NOT_READY', '仅在库、在托箱允许正常转仓', code)
            if len(box.location_record_ids) != 1:
                raise PositionRejected('SOURCE_ROW_REQUIRED', '来源行码无法唯一核实', code)
            row = by_row[box.location_record_ids[0]]
            if row_counts[row.location_code] != 1 or not row.location_code:
                raise PositionRejected('SOURCE_ROW_NOT_UNIQUE', '来源行码缺失或重复', code)
            try:
                if box.position_code:
                    position_number(box.position_code)
            except ValueError:
                raise PositionRejected('SOURCE_POSITION_REQUIRED', '历史箱尚未确认位置码，不能自动转仓', code) from None
            if row.record_id in quarantined:
                raise PositionRejected('SOURCE_REGION_QUARANTINED', '来源区域有未核实的历史位置，需先交接', code)
            if expected_source is not None and expected_source != row.location_code:
                raise PositionRejected('SOURCE_ROW_MISMATCH', '填写的来源区域与箱表当前位置不一致', code)
            sources.append({'box_record_id': box.record_id, 'box_code': code,
                            'row_record_id': row.record_id, 'row_code': row.location_code,
                            'position_code': box.position_code, 'status': box.status,
                            'observed_member_ids': sorted(membership.get((row.record_id, position_number(box.position_code)), set())) if box.position_code else []})
        requested.append(box)

    if len({box.record_id for box in requested}) != len(requested):
        raise PositionRejected('BOX_RECORD_AMBIGUOUS', '多个箱号指向同一档案，本批暂停')
    if sources:
        # 入库自动转行沿用整批来源核验，不把不同来源或新旧箱混为一批。
        if len(sources) != len(requested):
            raise PositionRejected('MIXED_INBOUND_PATHS', '待入库箱与在库转行箱须分开提交')
    if action == 'IN' and sources:
        source_rows = {source['row_record_id'] for source in sources}
        candidates = tuple(row for row in candidates if row.record_id not in source_rows)
        if not candidates:
            raise PositionRejected('INBOUND_DIFFERENT_ROW_REQUIRED', '原行重复入库口径未定，目标仓没有其他可用行码')
    return PositionDraft(action, warehouse, tuple(requested), candidates,
                         tuple(sorted(usage)), frozenset(quarantined), tuple(sources))
