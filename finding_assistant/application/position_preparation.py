"""选仓、整批核实、组合位置预占、写流水；流水成功仍不等于库存入账。"""
import hashlib
import json
import uuid

from finding_assistant.adapters.feishu.business_tables import BusinessDataUnavailable
from finding_assistant.domain.positions import plan_positions
from finding_assistant.domain.transfer import WAREHOUSES
from finding_assistant.security.errors import AccessDenied, AuthorizationUnavailable
from finding_assistant.infrastructure.performance import timed


class PositionPreparation:
    def __init__(self, gate, access, reader, reservations, journal, legacy=None):
        self.gate, self.access, self.reader = gate, access, reader
        self.reservations, self.journal, self.legacy = reservations, journal, legacy

    @timed('position_allocation')
    def submit(self, session_id, key, action, warehouse, fields):
        identity = self.gate.authorize(session_id, action)
        operation = uuid.UUID(key)
        if operation.version != 4 or operation.variant != uuid.RFC_4122 or str(operation) != key:
            raise ValueError('UUID4_REQUEST_KEY_REQUIRED')
        if action not in ('IN', 'MOVE') or warehouse not in WAREHOUSES or not isinstance(fields, dict):
            raise ValueError('INVALID_POSITION_INPUT')
        allowed = {'原因', '事件类型'} | {f'箱号{i}' for i in range(1, 37)}
        if action == 'MOVE':
            allowed.add('来源区域')
        if set(fields) - allowed:
            raise AccessDenied('target row, position, identity and processing result are server controlled')
        if any(not isinstance(value, str) or not value.strip() or len(value) > 200 for value in fields.values()):
            raise ValueError('INVALID_POSITION_FIELD')
        fields = {name: value.strip() for name, value in fields.items()}
        event = '入库' if action == 'IN' else '转仓'
        if fields.get('事件类型', event) != event:
            raise ValueError('EVENT_ROUTE_MISMATCH')
        codes = tuple(fields[f'箱号{i}'] for i in range(1, 37) if f'箱号{i}' in fields)
        if not codes or len(codes) != len(set(codes)):
            raise ValueError('UNIQUE_BOX_CODES_REQUIRED')
        if self.reader is None or self.reservations is None or self.journal is None:
            raise BusinessDataUnavailable('POSITION_ALLOCATION_NOT_CONFIGURED')

        # 老转仓键继续返回老目标及原流水，不能用新版分配器改写其输入摘要。
        if action == 'MOVE' and self.legacy is not None:
            legacy_fingerprint = hashlib.sha256(json.dumps({'warehouse': warehouse, 'fields': fields},
                                                           sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            if self.legacy.existing(identity, key, legacy_fingerprint) is not None:
                from .transfer_preparation import TransferPreparation
                return TransferPreparation(self.gate, self.access, self.reader, self.legacy, self.journal).submit(
                    session_id, key, warehouse, fields)

        fingerprint = hashlib.sha256(json.dumps({'version': 2, 'action': action, 'warehouse': warehouse,
            'fields': fields}, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        reservation = self.reservations.existing(identity, key, fingerprint)
        if reservation is None:
            boxes, rows = self.reader.position_snapshot(identity)
            draft = plan_positions(action, codes, warehouse, boxes, rows, fields.get('来源区域'))
            reservation = self.reservations.reserve(identity, key, fingerprint, fields, draft)
        payload = reservation['payload']
        try:
            record = self.journal.execute(identity, self.access.config.app_token, self.access.config.scan_table_id,
                key, action, payload, lambda: self.access.create(identity, key, payload))
        except Exception as error:
            definitive = isinstance(error, AccessDenied) and not isinstance(error, AuthorizationUnavailable)
            self.reservations.mark(identity, key, fingerprint, 'RELEASED' if definitive else 'UNKNOWN')
            raise
        self.reservations.mark(identity, key, fingerprint, 'RECORDED', record['record_id'])
        source_locations = []
        for item in reservation['sources']:
            point = {'row_code':item['row_code'], 'position_code':item['position_code'],
                     'legacy_row_only': not item['position_code']}
            if point not in source_locations:source_locations.append(point)
        source = source_locations[0] if len(source_locations)==1 else {}
        return {'record': record, 'batch_id': str(reservation['batch_id']),
                'reservation_id': str(reservation['reservation_id']),
                'target_location_code': reservation['target_row_code'],
                'target_position_code': reservation['position_code'], 'target_warehouse': reservation['target_warehouse'],
                'source_location_code': source.get('row_code'), 'source_position_code': source.get('position_code'),
                'locations':{'target':{'row_code':reservation['target_row_code'],
                    'position_code':reservation['position_code'],'warehouse':reservation['target_warehouse']},
                    'sources':source_locations},
                'location_reserved': True, 'inventory_posted': False}
