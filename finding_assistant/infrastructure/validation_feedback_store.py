"""异常回写回执：先记录意图，未知结果只回读；未执行库存才允许释放本流水预占。"""
import uuid

from finding_assistant.application.workflow import Conflict
from finding_assistant.security.errors import AccessDenied


class ValidationFeedbackStore:
    def __init__(self, repository):
        self.repository = repository
        self.operations = repository.operations

    def get(self, source_key, identity):
        with self.operations.connection() as db:
            row = db.execute('SELECT * FROM finding_assistant.inventory_rejections WHERE source_key=%s', (source_key,)).fetchone()
        if row and (row['app_id'] != self.operations.app_id or row['tenant_key'] != identity.tenant_key or row['open_id'] != identity.open_id):
            raise AccessDenied('rejection identity mismatch')
        return row

    def _lock(self, db, source_key):
        db.execute("SET LOCAL lock_timeout='5s'")
        db.execute('SELECT pg_advisory_xact_lock(%s)', (self.repository.global_lock,))
        if db.execute('SELECT 1 FROM finding_assistant.inventory_executions WHERE source_key=%s FOR UPDATE', (source_key,)).fetchone():
            raise Conflict('prepared inventory cannot be treated as a validation rejection')

    def create(self, identity, submission, code, box_code, before_note, note):
        with self.operations.connection() as db:
            self._lock(db, submission.source_key)
            db.execute('''INSERT INTO finding_assistant.inventory_rejections
                (source_key,rejection_id,app_id,base_token,scan_table_id,source_record_id,tenant_key,open_id,
                 action,fingerprint,reason_code,box_code,before_note,note,state)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING') ON CONFLICT DO NOTHING''',
                (submission.source_key, uuid.uuid4(), self.operations.app_id, self.repository.base,
                 self.repository.scan_table, submission.source_record_id, identity.tenant_key, identity.open_id,
                 submission.action, submission.fingerprint, code, box_code, before_note, note))
        row = self.get(submission.source_key, identity)
        if row['fingerprint'] != submission.fingerprint:
            raise Conflict('rejected source input changed')
        return row

    def mark(self, identity, source_key, state):
        allowed = {'RUNNING': ('PENDING',), 'UNKNOWN': ('RUNNING',), 'REJECTED': ('RUNNING',)}
        if state not in allowed:raise ValueError('INVALID_FEEDBACK_STATE')
        self.get(source_key, identity)
        with self.operations.connection() as db:
            self._lock(db, source_key)
            row = db.execute('''UPDATE finding_assistant.inventory_rejections SET state=%s,updated_at=clock_timestamp()
                WHERE source_key=%s AND state=ANY(%s) RETURNING *''', (state, source_key, list(allowed[state]))).fetchone()
            if not row:raise Conflict('feedback attempt state changed')
            self.operations._audit(db, 'VALIDATION_FEEDBACK', state, identity, row['action'], key=row['rejection_id'])
        return row

    def confirmed(self, identity, source_key):
        row = self.get(source_key, identity)
        with self.operations.connection() as db:
            self._lock(db, source_key)
            current = db.execute('SELECT * FROM finding_assistant.inventory_rejections WHERE source_key=%s FOR UPDATE', (source_key,)).fetchone()
            if current['state'] == 'CONFIRMED':return current
            if current['state'] not in ('RUNNING', 'UNKNOWN'):
                raise Conflict('unowned feedback cannot be confirmed')
            reservations = db.execute('''SELECT * FROM finding_assistant.position_reservations
                WHERE app_id=%s AND base_token=%s AND table_id=%s AND flow_record_id=%s FOR UPDATE''',
                (self.operations.app_id, self.repository.base, self.repository.scan_table, row['source_record_id'])).fetchall()
            if len(reservations) > 1:raise Conflict('rejection reservation ambiguous')
            released = False
            for reservation in reservations:
                if (reservation['tenant_key'] != identity.tenant_key or reservation['open_id'] != identity.open_id
                        or reservation['box_table_id'] != self.repository.box_table
                        or reservation['row_table_id'] != self.repository.row_table
                        or reservation['state'] not in ('RECORDED', 'RELEASED')
                        or reservation['posting_evidence'] or reservation['departure_evidence']):
                    raise Conflict('rejection cannot release unconfirmed inventory')
                db.execute("UPDATE finding_assistant.position_reservations SET state='RELEASED',updated_at=clock_timestamp() WHERE reservation_id=%s", (reservation['reservation_id'],))
                db.execute('UPDATE finding_assistant.position_box_claims SET active=false WHERE reservation_id=%s', (reservation['reservation_id'],))
                released = True
            row = db.execute('''UPDATE finding_assistant.inventory_rejections SET state='CONFIRMED',remote_record_id=source_record_id,
                position_released=%s,updated_at=clock_timestamp() WHERE source_key=%s RETURNING *''', (released, source_key)).fetchone()
            self.operations._audit(db, 'VALIDATION_FEEDBACK', 'CONFIRMED', identity, row['action'], key=row['rejection_id'])
        return row

    @staticmethod
    def summary(row):
        return {'rejection_id': str(row['rejection_id']), 'state': row['state'], 'reason_code': row['reason_code'],
                'box_code': row['box_code'], 'position_released': row['position_released'], 'inventory_posted': False}
