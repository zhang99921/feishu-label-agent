"""日常扫码入口：四档授权 → 表单字段校验 → 用户身份写入扫码流水表。"""
import uuid

from finding_assistant.domain.scan_submission import normalize_record
from finding_assistant.security.errors import AccessDenied


class ScanService:
    def __init__(self, gate, access, journal=None, business_reader=None, transfer_reservations=None,
                 position_reservations=None, inventory_execution=None):
        self.gate, self.access = gate, access
        self.journal = journal
        self.business_reader = business_reader
        self.transfer_reservations = transfer_reservations
        self.position_reservations = position_reservations
        self.inventory_execution = inventory_execution

    def prepare_inbound(self, session_id, request_key, warehouse, fields):
        return self._prepare_position(session_id, request_key, 'IN', warehouse, fields)

    def _prepare_position(self, session_id, request_key, action, warehouse, fields):
        from finding_assistant.application.position_preparation import PositionPreparation
        return PositionPreparation(self.gate, self.access, self.business_reader, self.position_reservations,
                                   self.journal, self.transfer_reservations).submit(
                                       session_id, request_key, action, warehouse, fields)

    def prepare_transfer(self, session_id, request_key, warehouse, fields):
        if self.position_reservations is not None:
            return self._prepare_position(session_id, request_key, 'MOVE', warehouse, fields)
        from finding_assistant.application.transfer_preparation import TransferPreparation
        return TransferPreparation(self.gate, self.access, self.business_reader,
                                   self.transfer_reservations, self.journal).submit(
                                       session_id, request_key, warehouse, fields)

    def query(self, session_id, page_token=None):
        return self.access.records(self.gate.authorize(session_id, 'QUERY'), page_token)

    def submit(self, session_id, request_key, action, fields):
        identity = self.gate.authorize(session_id, action)
        events = {'IN':'入库', 'OUT':'出库', 'MOVE':'转仓'}
        if action not in events or not isinstance(fields, dict):
            raise ValueError('INVALID_SCAN_INPUT')
        allowed = {'行码', '来源区域', '目标区域', '目标托盘号', '原因', '事件类型'} | {f'箱号{i}' for i in range(1,37)}
        if set(fields) - allowed:
            raise AccessDenied('identity, quantity and processing result fields cannot be supplied')
        if any(not isinstance(v, str) or not v.strip() or len(v) > 200 for v in fields.values()):
            raise ValueError('INVALID_SCAN_FIELD')
        if fields.get('事件类型', events[action]) != events[action]:
            raise ValueError('EVENT_ROUTE_MISMATCH')
        operation = uuid.UUID(request_key)
        if operation.version != 4 or operation.variant != uuid.RFC_4122 or str(operation) != request_key:
            raise ValueError('UUID4_REQUEST_KEY_REQUIRED')
        payload = {**fields, '事件类型':events[action]}
        checked = normalize_record(self.access.config.app_token, self.access.config.scan_table_id,
            {'record_id':'validation', 'fields':payload}, include_blank_status=True)
        if checked is None or checked.errors:
            raise ValueError('INVALID_SCAN_SUBMISSION')
        send = lambda:self.access.create(identity, request_key, payload)
        if self.position_reservations is not None and action in ('IN', 'MOVE'):
            # 新模型下手填目标的旧入口只重放已有成功请求，不能绕过自动预占新建流水。
            if self.journal is None:
                raise AccessDenied('persistent journal required')
            record = self.journal.replay(identity, self.access.config.app_token, self.access.config.scan_table_id,
                                         request_key, action, payload)
        else:
            record = (self.journal.execute(identity,self.access.config.app_token,self.access.config.scan_table_id,
                  request_key,action,payload,send) if self.journal is not None else send())
        # 创建流水成功，不代表库存已入账；后续仍由既有流程处理。
        return {'record':record, 'inventory_posted':False}
