"""已确认的四条入库规则；只判断业务数据，不执行入账或回写飞书。

调用方应提供箱表、行表的完整查询结果。查询失败、权限不足、分页未完成
或字段不可见时必须标记查询未完成，不能用空列表冒充“箱号不存在”。
先输出逐箱问题，再按“任一异常，整条流水暂停”生成批次判定。
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class BoxRecord:
    record_id: str
    box_code: str
    status: str
    location_record_ids: tuple[str, ...] = ()
    position_code: str = ''


@dataclass(frozen=True)
class LocationRecord:
    record_id: str
    location_code: str
    warehouse: str


@dataclass(frozen=True)
class InboundIssue:
    code: str
    message: str
    box_code: str | None = None
    location_code: str | None = None


@dataclass(frozen=True)
class InboundCheck:
    issues: tuple[InboundIssue, ...]
    checked_boxes: tuple[str, ...]
    lookups_complete: bool

    @property
    def valid(self):
        """仅代表这四条规则未发现问题，不代表已入账或通过所有未来规则。"""
        return self.lookups_complete and not self.issues


@dataclass(frozen=True)
class InboundBatchDecision:
    """纯判定结果；feedback_fields 是未来回写建议，不在这里执行写入。"""
    state: str  # READY：校验通过；BLOCKED：业务异常；UNVERIFIED：查询未完成。
    boxes_to_process: tuple[str, ...]
    explanation: str

    @property
    def feedback_fields(self):
        # 查询问题不当作业务异常；成功校验也不能直接标记“已入账”。
        if self.state == 'BLOCKED':
            return {'处理状态': '异常', '处理说明': self.explanation}
        return {}


def decide_inbound_batch(check: InboundCheck):
    """任一异常均不给出可处理箱号，避免正常箱先入库形成部分成功。

    READY 只是可以进入后续执行阶段，不代表跨表事务保障或入账成功。
    """
    details = []
    for issue in check.issues:
        subject = (f'箱号 {issue.box_code}' if issue.box_code else
                   f'行码 {issue.location_code}' if issue.location_code else '')
        details.append(f'{subject}：{issue.message}' if subject else issue.message)
    if not check.lookups_complete:
        reason = '；'.join(details) or '相关业务表尚未完成核实'
        return InboundBatchDecision('UNVERIFIED', (), f'校验未完成：{reason}。本批暂停，待重新核实。')
    if check.issues:
        return InboundBatchDecision('BLOCKED', (), '；'.join(details) + '。本批暂停入库。')
    if not check.checked_boxes:
        raise ValueError('CHECKED_BOXES_REQUIRED')
    return InboundBatchDecision('READY', check.checked_boxes, '本批已通过当前入库规则校验，尚未执行入账。')


def _text(value):
    if not isinstance(value, str):
        raise ValueError('INVALID_INBOUND_RULE_INPUT')
    return value.strip()


def validate_inbound(box_codes, location_code, boxes, locations, *,
                     box_lookup_complete, location_lookup_complete, expected_warehouse=None):
    """检查档案唯一性、有效行码、重复入库及作废/空号状态。

    box_codes 为本次提交的箱号；boxes/locations 是按值匹配后仍保留各条源
    记录的查询结果，不能提前转成会吞掉重复档案的字典。
    行表的“仓”为目标仓的依据，不从箱表的“仓”公式推断位置是否合法。
    """
    if type(box_lookup_complete) is not bool or type(location_lookup_complete) is not bool:
        raise ValueError('LOOKUP_COMPLETION_FLAGS_REQUIRED')
    if isinstance(box_codes, (str, bytes)):
        raise ValueError('BOX_CODE_SEQUENCE_REQUIRED')
    codes = tuple(_text(code) for code in box_codes)
    if not codes or any(not code for code in codes):
        raise ValueError('BOX_REQUIRED')
    # 同一次输入重复扫描不重复判断、计数；不是“箱表中重复档案”的唯一性判断。
    codes = tuple(dict.fromkeys(codes))
    location = _text(location_code)
    if not location:
        raise ValueError('LOCATION_REQUIRED')
    issues = []
    if not box_lookup_complete:
        issues.append(InboundIssue('BOX_LOOKUP_UNCONFIRMED', '箱表查询未完成，不能判断箱号是否存在'))
    if not location_lookup_complete:
        issues.append(InboundIssue('LOCATION_LOOKUP_UNCONFIRMED', '行表查询未完成，不能判断行码是否有效', location_code=location))
    if issues:
        return InboundCheck(tuple(issues), (), False)

    matched_locations = [record for record in locations if _text(record.location_code) == location]
    if not matched_locations:
        issues.append(InboundIssue('LOCATION_NOT_FOUND', '行码不在行表中', location_code=location))
    elif len(matched_locations) != 1:
        issues.append(InboundIssue('LOCATION_NOT_UNIQUE', '行码匹配多个位置档案', location_code=location))
    elif not _text(matched_locations[0].warehouse):
        issues.append(InboundIssue('LOCATION_WAREHOUSE_REQUIRED', '行码未配置所属仓库', location_code=location))
    elif expected_warehouse is not None and _text(matched_locations[0].warehouse)!=_text(expected_warehouse):
        issues.append(InboundIssue('LOCATION_WAREHOUSE_MISMATCH','行码不属于所选仓库',location_code=location))

    # 不使用“箱表.箱号 → 单条记录”的字典，保留重复档案用于检测。
    by_box = {}
    for record in boxes:
        by_box.setdefault(_text(record.box_code), []).append(record)
    for code in codes:
        matched = by_box.get(code, [])
        if not matched:
            issues.append(InboundIssue('BOX_NOT_FOUND', '箱号不在箱表中', box_code=code))
        elif len(matched) != 1:
            issues.append(InboundIssue('BOX_NOT_UNIQUE', '箱号匹配多个箱子档案', box_code=code))
        else:
            status = _text(matched[0].status)
            transfer_target = (len(matched_locations) == 1 and len(matched[0].location_record_ids) == 1
                and matched_locations[0].record_id != matched[0].location_record_ids[0])
            # 此处只是基础预览；来源位置码、全批成员及SQL占用由自动分配/执行层核实。
            if status in ('在库', '在托') and not transfer_target:
                issues.append(InboundIssue('BOX_ALREADY_IN_STOCK', '箱子已在库，不能重复入库', box_code=code))
            elif status in {'作废', '空号'}:
                issues.append(InboundIssue('BOX_STATUS_NOT_ALLOWED', '作废或空号不能直接入库', box_code=code))
            elif not status:
                issues.append(InboundIssue('BOX_STATUS_UNCONFIRMED', '箱子状态为空，无法完成重复入库校验', box_code=code))
            if status=='待入库' and matched[0].location_record_ids:
                issues.append(InboundIssue('BOX_STATE_LOCATION_CONFLICT',
                    '待入库箱已有位置关联：'+','.join(matched[0].location_record_ids),box_code=code))
            elif status=='在库' and not matched[0].location_record_ids:
                issues.append(InboundIssue('BOX_LOCATION_REQUIRED','在库箱缺少位置关联',box_code=code))
            # 已出库、待清点等状态尚无已确认的拦截规则，不擅自追加。
    return InboundCheck(tuple(issues), codes, True)
