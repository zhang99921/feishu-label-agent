"""选择仓库→核实原行码→原子预占新行码→记录转仓流水；不提前标记已转仓。"""
import hashlib
import json
import uuid

from finding_assistant.adapters.feishu.business_tables import BusinessDataUnavailable
from finding_assistant.domain.transfer import WAREHOUSES, plan_transfer
from finding_assistant.security.errors import AccessDenied, AuthorizationUnavailable


class TransferPreparation:
    def __init__(self, gate, access, reader, reservations, journal):
        self.gate, self.access, self.reader = gate, access, reader
        self.reservations, self.journal = reservations, journal

    def submit(self, session_id, key, warehouse, fields):
        identity = self.gate.authorize(session_id, 'MOVE')
        operation = uuid.UUID(key)
        if operation.version != 4 or operation.variant != uuid.RFC_4122 or str(operation) != key:
            raise ValueError('UUID4_REQUEST_KEY_REQUIRED')
        if warehouse not in WAREHOUSES or not isinstance(fields, dict):
            raise ValueError('INVALID_TRANSFER_INPUT')
        allowed = {'事件类型', '来源区域', '原因'} | {f'箱号{i}' for i in range(1, 37)}
        if set(fields) - allowed:
            raise AccessDenied('target location, actor and processing results are server controlled')
        if any(not isinstance(value, str) or not value.strip() or len(value) > 200 for value in fields.values()):
            raise ValueError('INVALID_TRANSFER_FIELD')
        fields = {name: value.strip() for name, value in fields.items()}
        if fields.get('事件类型', '转仓') != '转仓':
            raise ValueError('EVENT_ROUTE_MISMATCH')
        codes = tuple(fields[f'箱号{i}'] for i in range(1, 37) if f'箱号{i}' in fields)
        if not codes:
            raise ValueError('BOX_REQUIRED')
        if len(codes) != len(set(codes)):
            raise ValueError('DUPLICATE_BOX_IN_SUBMISSION')
        if self.reader is None or self.reservations is None or self.journal is None:
            raise BusinessDataUnavailable('TRANSFER_ALLOCATION_NOT_CONFIGURED')
        fingerprint = hashlib.sha256(json.dumps({'warehouse': warehouse, 'fields': fields},
                                                sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        reservation = self.reservations.existing(identity, key, fingerprint)
        if reservation is None:
            boxes, locations = self.reader.transfer_snapshot(identity)
            draft = plan_transfer(codes, warehouse, boxes, locations, fields.get('来源区域'))
            reservation = self.reservations.reserve(identity, key, fingerprint, fields, draft)
        payload = reservation['payload']
        try:
            record = self.journal.execute(identity, self.access.config.app_token, self.access.config.scan_table_id,
                key, 'MOVE', payload, lambda: self.access.create(identity, key, payload))
        except Exception as error:
            definitive = isinstance(error, AccessDenied) and not isinstance(error, AuthorizationUnavailable)
            self.reservations.mark(identity, key, fingerprint, 'RELEASED' if definitive else 'UNKNOWN')
            raise
        self.reservations.mark(identity, key, fingerprint, 'RECORDED', record['record_id'])
        return {'record': record, 'source_location_code': reservation['source_location_code'],
                'target_location_code': reservation['target_location_code'], 'target_warehouse': warehouse,
                'location_reserved': True, 'inventory_posted': False}
