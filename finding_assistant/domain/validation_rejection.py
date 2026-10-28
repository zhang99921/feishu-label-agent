"""已确认的前置业务拒绝反馈；待定口径和技术故障不自动归为业务异常。"""
REASONS = {
    'BOX_ARCHIVE_NOT_UNIQUE': '箱档案不存在或同一箱号对应多个档案',
    'INBOUND_STATE_REVIEW_REQUIRED': '箱状态或已有位置不满足当前入库准入，需要复核',
    'INBOUND_TRANSFER_SOURCE_CHANGED': '入库转行的来源状态、位置或目标行与预占依据不一致',
    'TRANSFER_SOURCE_CHANGED': '箱子当前状态或来源位置与本次转仓依据不一致',
    'OUTBOUND_STATE_REVIEW_REQUIRED': '箱状态不满足当前出库准入，需要复核',
    'OUTBOUND_POSITION_CONFLICT': '箱状态与当前行码、位置码存在冲突',
    'BOX_ROW_UNCONFIRMED': '箱子的行关联不唯一或找不到对应区域档案',
    'TARGET_ROW_CHANGED': '目标区域的行码或仓库归属发生变化',
    'BOX_EXECUTION_ALREADY_PENDING': '同一箱已有其他尚未完成的库存操作',
}


def rejection_note(code, box_code=None):
    reason = REASONS[code]
    box = ('箱号：' + box_code[:200] + '；') if box_code else ''
    return f'本次整批暂停，尚未执行库存；{box}原因：{reason}（{code}）。请核对后重新提交。'
