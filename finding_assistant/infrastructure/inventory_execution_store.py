"""持久化不可变执行计划、逐箱事务与远端步骤；外部调用前先提交RUNNING意图。"""
from contextlib import contextmanager
import hashlib
from types import SimpleNamespace
import uuid

from psycopg.types.json import Jsonb

from finding_assistant.application.workflow import Conflict
from finding_assistant.domain.inventory_posting import PostingStopped
from finding_assistant.security.errors import AccessDenied


class InventoryExecutionStore:
    def __init__(self, operations, base, scan_table, box_table, row_table):
        self.operations, self.base, self.scan_table = operations, base, scan_table
        self.box_table, self.row_table = box_table, row_table
        self.global_lock = self._lock_id(base + ':' + row_table)

    @staticmethod
    def _lock_id(value):
        return int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], 'big', signed=True)

    def row(self, source_key):
        with self.operations.connection() as db:
            row = db.execute('SELECT * FROM finding_assistant.inventory_executions WHERE source_key=%s',
                             (source_key,)).fetchone()
        if row and row['app_id'] != self.operations.app_id:
            raise AccessDenied('execution belongs to another application')
        return row

    @contextmanager
    def validation_guard(self, source_key):
        """与执行lease共用来源锁，避免前置拒绝回写和该流水库存执行并行。"""
        with self.operations.tasks.connect() as db:
            db.autocommit = True
            acquired = db.execute('SELECT pg_try_advisory_lock(%s) acquired',
                (self._lock_id('inventory-execution:' + source_key),)).fetchone()['acquired']
            if not acquired:
                raise Conflict('inventory execution already in progress')
            yield lambda: db.execute('SELECT 1')

    def validation_rejected(self, identity, submission, code):
        import re
        safe = code if isinstance(code, str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,99}', code) else 'VALIDATION_REJECTED'
        with self.operations.connection() as db:
            self._event(db, submission.source_key, 'VALIDATION_REJECTED:' + safe)
            self.operations._audit(db, 'INVENTORY_VALIDATION', 'REJECTED', identity, submission.action)

    def prepare(self, identity, submission, plan):
        with self.operations.connection() as db:
            db.execute("SET LOCAL lock_timeout='5s'")
            db.execute('SELECT pg_advisory_xact_lock(%s)', (self.global_lock,))
            previous = db.execute('SELECT * FROM finding_assistant.inventory_executions WHERE source_key=%s FOR UPDATE',
                                  (submission.source_key,)).fetchone()
            if previous:
                if (previous['app_id'] != self.operations.app_id or previous['open_id'] != identity.open_id
                        or previous['tenant_key'] != identity.tenant_key):
                    raise AccessDenied('execution identity mismatch')
                if previous['fingerprint'] != submission.fingerprint:
                    raise Conflict('execution input is immutable')
                return previous
            job = db.execute('SELECT * FROM finding_assistant.scan_jobs WHERE source_key=%s FOR UPDATE',
                             (submission.source_key,)).fetchone()
            if not job or job['state'] != 'QUEUED' or job['fingerprint'] != submission.fingerprint:
                raise PostingStopped('INTAKE_NOT_EXECUTABLE')
            res_id = plan['position_reservation_id']
            if res_id:
                reservation = db.execute('''SELECT * FROM finding_assistant.position_reservations
                    WHERE reservation_id=%s FOR UPDATE''', (uuid.UUID(res_id),)).fetchone()
                members = {r['box_record_id'] for r in db.execute('''SELECT box_record_id
                    FROM finding_assistant.position_box_claims WHERE reservation_id=%s''', (uuid.UUID(res_id),)).fetchall()}
                if (not reservation or reservation['state'] != 'RECORDED'
                        or reservation['app_id'] != self.operations.app_id or reservation['base_token'] != self.base
                        or reservation['table_id'] != self.scan_table or reservation['box_table_id'] != self.box_table
                        or reservation['action'] != submission.action or reservation['open_id'] != identity.open_id
                        or reservation['flow_record_id'] != submission.source_record_id
                        or members != {t['box_record_id'] for t in plan['transactions']}):
                    raise PostingStopped('RESERVATION_NOT_EXECUTABLE')
            ids = [t['box_record_id'] for t in plan['transactions']] + [b['record_id'] for b in plan['skipped']]
            if ids:
                pending = db.execute('''SELECT 1 FROM finding_assistant.position_box_claims
                    WHERE base_token=%s AND box_table_id=%s AND box_record_id=ANY(%s) AND active
                    AND (%s::uuid IS NULL OR reservation_id<>%s::uuid) LIMIT 1''',
                    (self.base, self.box_table, ids, res_id, res_id)).fetchone()
                occupied = db.execute('''SELECT 1 FROM finding_assistant.inventory_transactions
                    WHERE base_token=%s AND box_table_id=%s AND box_record_id=ANY(%s) AND active LIMIT 1''',
                    (self.base, self.box_table, ids)).fetchone()
                if pending or occupied:
                    raise PostingStopped('BOX_EXECUTION_ALREADY_PENDING')
            for source in {s['reservation_id']: s for s in plan['outbound_sources'].values()}.values():
                current = db.execute('SELECT state FROM finding_assistant.position_reservations WHERE reservation_id=%s FOR UPDATE',
                                     (uuid.UUID(source['reservation_id']),)).fetchone()
                if not current or current['state'] != 'OCCUPIED':
                    raise PostingStopped('OUTBOUND_SOURCE_NOT_OCCUPIED')
            execution_id = uuid.uuid4()
            db.execute('''INSERT INTO finding_assistant.inventory_executions
                (source_key,execution_id,app_id,base_token,scan_table_id,source_record_id,tenant_key,open_id,action,fingerprint,plan,state)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PREPARED')''',
                (submission.source_key, execution_id, self.operations.app_id, self.base, self.scan_table, submission.source_record_id,
                 identity.tenant_key, identity.open_id, submission.action, submission.fingerprint, Jsonb(plan)))
            for step in plan['steps']:
                db.execute('''INSERT INTO finding_assistant.inventory_steps
                    (source_key,ordinal,step_id,kind,box_record_id,specification,state)
                    VALUES(%s,%s,%s,%s,%s,%s,'PENDING')''',
                    (submission.source_key, step['ordinal'], uuid.UUID(step['step_id']), step['kind'],
                     step['box_record_id'], Jsonb(step)))
            for transaction in plan['transactions']:
                db.execute('''INSERT INTO finding_assistant.inventory_transactions
                    (transaction_id,source_key,base_token,box_table_id,box_record_id,box_code,action,
                     document_reference,transaction_no,quantity,before_values,after_values,source_position_id,target_position_id,state)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PLANNED')''',
                    (uuid.UUID(transaction['transaction_id']), submission.source_key, self.base, self.box_table,
                     transaction['box_record_id'], transaction['box_code'], submission.action,
                     transaction['document_reference'], transaction['transaction_no'], transaction['quantity'],
                     Jsonb(transaction['before']), Jsonb(transaction['after']),
                     transaction['source_position_id'], transaction['target_position_id']))
            self._event(db, submission.source_key, 'POSTING_PREPARED')
            self.operations._audit(db, 'INVENTORY_EXECUTION', 'PREPARED', identity, submission.action, key=execution_id)
        return self.row(submission.source_key)

    @contextmanager
    def lease(self, source_key):
        """会话锁防同任务并行；owner_id阻止连接丢失的旧执行者继续提交后续步骤。"""
        lock_id = self._lock_id('inventory-execution:' + source_key)
        with self.operations.tasks.connect() as lock_db:
            acquired = lock_db.execute('SELECT pg_try_advisory_lock(%s) acquired', (lock_id,)).fetchone()['acquired']
            lock_db.commit()
            if not acquired:
                raise Conflict('inventory execution already in progress')
            try:
                owner = uuid.uuid4()
                with self.operations.connection() as db:
                    row = db.execute('SELECT * FROM finding_assistant.inventory_executions WHERE source_key=%s FOR UPDATE',
                                     (source_key,)).fetchone()
                    if not row or row['app_id'] != self.operations.app_id:
                        raise PostingStopped('EXECUTION_NOT_PREPARED')
                    if row['state'] == 'SUCCEEDED':
                        owner = None
                    else:
                        db.execute('''UPDATE finding_assistant.inventory_executions SET state='RUNNING',owner_id=%s,
                            failure_code=NULL,updated_at=clock_timestamp() WHERE source_key=%s''', (owner, source_key))
                        self.operations._audit(db, 'INVENTORY_EXECUTION', 'RUNNING',
                            SimpleNamespace(tenant_key=row['tenant_key'], open_id=row['open_id']), row['action'],
                            key=row['execution_id'])
                yield owner
            finally:
                lock_db.execute('SELECT pg_advisory_unlock(%s)', (lock_id,))
                lock_db.commit()

    def _owner(self, db, source_key, owner):
        row = db.execute('SELECT * FROM finding_assistant.inventory_executions WHERE source_key=%s FOR UPDATE',
                         (source_key,)).fetchone()
        if not row or row['owner_id'] != owner or owner is None or row['app_id'] != self.operations.app_id:
            raise Conflict('inventory execution ownership changed')
        return row

    def steps(self, source_key):
        with self.operations.connection() as db:
            return db.execute('SELECT * FROM finding_assistant.inventory_steps WHERE source_key=%s ORDER BY ordinal',
                              (source_key,)).fetchall()

    def begin_step(self, source_key, owner, ordinal):
        with self.operations.connection() as db:
            self._owner(db, source_key, owner)
            updated = db.execute('''UPDATE finding_assistant.inventory_steps SET state='RUNNING'
                WHERE source_key=%s AND ordinal=%s AND state='PENDING' RETURNING ordinal''',
                (source_key, ordinal)).fetchone()
            if not updated:
                raise Conflict('step already attempted; observe before continuing')

    def begin_steps(self, source_key, owner, ordinals):
        if not ordinals or len(set(ordinals))!=len(ordinals):raise PostingStopped('BATCH_INTENT_INVALID')
        with self.operations.connection() as db:
            self._owner(db, source_key, owner)
            rows=db.execute("""UPDATE finding_assistant.inventory_steps SET state='RUNNING'
                WHERE source_key=%s AND ordinal=ANY(%s) AND state='PENDING' RETURNING ordinal""",
                (source_key,ordinals)).fetchall()
            if len(rows)!=len(ordinals):raise Conflict('batch contains an already attempted step')

    def response(self, source_key, owner, ordinal, remote_id):
        with self.operations.connection() as db:
            self._owner(db, source_key, owner)
            db.execute('''UPDATE finding_assistant.inventory_steps SET remote_record_id=%s
                WHERE source_key=%s AND ordinal=%s AND state='RUNNING' ''', (remote_id, source_key, ordinal))

    def confirm(self, source_key, owner, ordinal, remote_id):
        with self.operations.connection() as db:
            self._owner(db, source_key, owner)
            step = db.execute('''UPDATE finding_assistant.inventory_steps SET state='CONFIRMED',remote_record_id=%s,
                failure_code=NULL,confirmed_at=clock_timestamp() WHERE source_key=%s AND ordinal=%s RETURNING *''',
                (remote_id, source_key, ordinal)).fetchone()
            if not step:
                raise PostingStopped('STEP_MISSING')
            if step['kind'] == 'LEDGER':
                db.execute('''UPDATE finding_assistant.inventory_transactions SET state='POSTED',remote_record_id=%s,
                    posted_at=clock_timestamp() WHERE transaction_id=%s''', (remote_id, step['step_id']))
            self._event(db, source_key, 'POSTING_STEP_CONFIRMED:' + str(ordinal))

    def uncertain(self, source_key, owner, ordinal, definitive=False):
        with self.operations.connection() as db:
            self._owner(db, source_key, owner)
            db.execute('''UPDATE finding_assistant.inventory_steps SET state=%s,failure_code=%s
                WHERE source_key=%s AND ordinal=%s AND state='RUNNING' ''',
                ('REJECTED' if definitive else 'UNKNOWN', 'REMOTE_DENIED' if definitive else 'REMOTE_UNCONFIRMED',
                 source_key, ordinal))

    def positions_confirmed(self, source_key, owner):
        with self.operations.connection() as db:
            self._owner(db, source_key, owner)
            db.execute('UPDATE finding_assistant.inventory_executions SET position_confirmed=true WHERE source_key=%s', (source_key,))

    def stop(self, source_key, owner, code):
        with self.operations.connection() as db:
            row = self._owner(db, source_key, owner)
            db.execute('''UPDATE finding_assistant.inventory_executions SET state='RECONCILE',failure_code=%s,
                updated_at=clock_timestamp() WHERE source_key=%s''', (code, source_key))
            self._event(db, source_key, 'POSTING_RECONCILE:' + code)
            self.operations._audit(db, 'INVENTORY_EXECUTION', 'RECONCILE',
                SimpleNamespace(tenant_key=row['tenant_key'], open_id=row['open_id']), row['action'], key=row['execution_id'])

    def finish(self, source_key, owner):
        with self.operations.connection() as db:
            row = self._owner(db, source_key, owner)
            remaining = db.execute("SELECT 1 FROM finding_assistant.inventory_steps WHERE source_key=%s AND state<>'CONFIRMED' LIMIT 1",
                                   (source_key,)).fetchone()
            if remaining or not row['position_confirmed']:
                raise PostingStopped('EXECUTION_NOT_FULLY_CONFIRMED')
            db.execute('UPDATE finding_assistant.inventory_transactions SET active=false WHERE source_key=%s', (source_key,))
            db.execute('''UPDATE finding_assistant.inventory_executions SET state='SUCCEEDED',owner_id=NULL,
                failure_code=NULL,updated_at=clock_timestamp() WHERE source_key=%s''', (source_key,))
            self._event(db, source_key, 'POSTING_SUCCEEDED')
            self.operations._audit(db, 'INVENTORY_EXECUTION', 'SUCCEEDED',
                SimpleNamespace(tenant_key=row['tenant_key'], open_id=row['open_id']), row['action'], key=row['execution_id'])

    @staticmethod
    def _event(db, source_key, event):
        db.execute('INSERT INTO finding_assistant.scan_job_events(source_key,event_code) VALUES(%s,%s)', (source_key, event))

    def summary(self, source_key):
        row = self.row(source_key)
        if not row:
            return {'found': False, 'inventory_posted': False}
        steps = self.steps(source_key)
        from finding_assistant.domain.public_locations import public_locations
        return {'locations': public_locations(row['plan']), 'found': True, 'execution_id': str(row['execution_id']),
                'source_record_id': row['source_record_id'], 'action': row['action'],
                'state': row['state'], 'failure_code': row['failure_code'],
                'box_count': len(row['plan']['transactions']),
                'confirmed_steps': sum(s['state'] == 'CONFIRMED' for s in steps), 'step_count': len(steps),
                'position_confirmed': row['position_confirmed'], 'inventory_posted': row['state'] == 'SUCCEEDED',
                'steps': [{'ordinal': s['ordinal'], 'kind': s['kind'], 'state': s['state'],
                           'remote_record_id': s['remote_record_id'], 'failure_code': s['failure_code']} for s in steps]}
