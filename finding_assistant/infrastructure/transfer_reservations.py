"""持久预占目标行码；同键复用原分配，未知结果不自动释放。"""
import hashlib

from psycopg.types.json import Jsonb

from finding_assistant.application.workflow import Conflict
from finding_assistant.domain.transfer import TransferRejected
from finding_assistant.security.errors import AccessDenied


class TransferReservations:
    def __init__(self, store, base, table, row_table):
        self.store, self.base, self.table, self.row_table = store, base, table, row_table

    def _scope(self, key):
        return self.store.app_id, self.base, self.table, key

    @staticmethod
    def _check(row, identity, fingerprint):
        if row['open_id'] != identity.open_id or row['tenant_key'] != identity.tenant_key:
            raise AccessDenied('request key belongs to another identity')
        if row['input_fingerprint'] != fingerprint:
            raise Conflict('request key cannot be reused with different transfer input')
        if row['state'] in {'RELEASED', 'COOLING'}:
            raise Conflict('transfer reservation is no longer active')
        return row

    def existing(self, identity, key, fingerprint):
        with self.store.connection() as connection:
            row = connection.execute('''SELECT * FROM finding_assistant.location_reservations
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s''', self._scope(key)).fetchone()
        return self._check(row, identity, fingerprint) if row else None

    def reserve(self, identity, key, fingerprint, fields, draft):
        lock = int.from_bytes(hashlib.sha256((self.base + ':' + self.row_table).encode()).digest()[:8], 'big', signed=True)
        with self.store.connection() as connection:
            connection.execute("SET LOCAL lock_timeout = '5s'")
            connection.execute('SELECT pg_advisory_xact_lock(%s)', (lock,))
            existing = connection.execute('''SELECT * FROM finding_assistant.location_reservations
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s''', self._scope(key)).fetchone()
            if existing:
                return self._check(existing, identity, fingerprint)
            used = connection.execute('''SELECT 1 FROM finding_assistant.write_requests
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s''', self._scope(key)).fetchone()
            if used:
                raise Conflict('request key already belongs to another submission')
            # 仅释放已明确进入冷却且到期的历史预占；RESERVED/UNKNOWN从不按时间猜测释放。
            connection.execute('''UPDATE finding_assistant.location_reservations SET state='RELEASED',updated_at=now()
                WHERE base_token=%s AND row_table_id=%s AND state='COOLING' AND cooldown_until<=now()''',
                (self.base, self.row_table))
            occupied = connection.execute('''SELECT target_row_record_id,target_location_code,payload
                FROM finding_assistant.location_reservations WHERE base_token=%s AND row_table_id=%s
                AND state<>'RELEASED' ''', (self.base, self.row_table)).fetchall()
            # 不同请求不能同时转移同一箱，避免同箱生成两份目标预占和转仓流水。
            box_fields = {f'箱号{i}' for i in range(1, 37)}
            requested = {value for name, value in fields.items() if name in box_fields}
            for active in occupied:
                claimed = {value for name, value in active['payload'].items() if name in box_fields}
                if requested & claimed:
                    raise TransferRejected('BOX_TRANSFER_ALREADY_PENDING', '本批包含已有转仓预占的箱子，请先核实原流水')
            ids = {row['target_row_record_id'] for row in occupied}
            codes = {row['target_location_code'] for row in occupied}
            target = next((row for row in draft.candidates if row.record_id not in ids and row.location_code not in codes), None)
            if target is None:
                raise TransferRejected('NO_AVAILABLE_LOCATION', '目标仓库的空闲行码已被预占或仍在冷却')
            payload = {**fields, '事件类型': '转仓', '来源区域': draft.source_location_code, '目标区域': target.location_code}
            row = connection.execute('''INSERT INTO finding_assistant.location_reservations
                (app_id,base_token,table_id,request_key,row_table_id,tenant_key,open_id,input_fingerprint,
                 source_location_code,target_row_record_id,target_location_code,target_warehouse,payload,state)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'RESERVED') RETURNING *''',
                (*self._scope(key), self.row_table, identity.tenant_key, identity.open_id, fingerprint,
                 draft.source_location_code, target.record_id, target.location_code, draft.target_warehouse, Jsonb(payload))).fetchone()
        return row

    def mark(self, identity, key, fingerprint, state, record_id=None):
        if state not in {'RECORDED', 'UNKNOWN', 'RELEASED'}:
            raise ValueError('INVALID_RESERVATION_TRANSITION')
        with self.store.connection() as connection:
            row = connection.execute('''SELECT * FROM finding_assistant.location_reservations
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s FOR UPDATE''', self._scope(key)).fetchone()
            if row is None:
                raise Conflict('transfer reservation missing')
            self._check(row, identity, fingerprint)
            if row['state'] == 'RECORDED' and state != 'RECORDED':
                return  # 已有成功流水，不因重放后的局部故障释放或降级目标预占。
            connection.execute('''UPDATE finding_assistant.location_reservations
                SET state=%s,flow_record_id=COALESCE(%s,flow_record_id),updated_at=now()
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND request_key=%s''',
                (state, record_id, *self._scope(key)))
